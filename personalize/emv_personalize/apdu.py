"""APDU protocol layer for the emv-card-sim applet.

Handles raw APDU construction and transport (pyscard or dry-run).
Implements the applet's custom personalization commands:

  INS 0x01  SET_EMV_TAG            — store an EMV tag value
  INS 0x02  SET_TAG_TEMPLATE       — configure a response template
  INS 0x03  SET_READ_RECORD_TEMPLATE — configure a READ RECORD response
  INS 0x04  SET_SETTINGS           — configure card settings
  INS 0x05  FACTORY_RESET          — wipe all personalization data
  INS 0x09  SET_EMV_TAG_CHUNKED    — chunked transfer for large tags (T=0)
  INS 0x0A  SET_SETTINGS_CHUNKED   — chunked transfer for large settings (T=0)
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field

from .tags import tag_to_p1p2, tag_name
from .tlv import build_tag_list_2byte

log = logging.getLogger(__name__)

# Applet CLA / INS constants
CLA_PROPRIETARY = 0x80
CLA_ISO = 0x00

INS_SET_EMV_TAG = 0x01
INS_SET_TAG_TEMPLATE = 0x02
INS_SET_READ_RECORD_TEMPLATE = 0x03
INS_SET_SETTINGS = 0x04
INS_FACTORY_RESET = 0x05
INS_SET_EMV_TAG_CHUNKED = 0x09
INS_SET_SETTINGS_CHUNKED = 0x0A

INS_SELECT = 0xA4
INS_STORE_DATA = 0xE2

# Maximum data bytes in a single short APDU
MAX_SHORT_DATA = 250
# Maximum DGI payload per STORE DATA command (leaves room for DGI+length header)
MAX_STORE_DATA_PAYLOAD = 240
# Chunk size for chunked transfers (leaves room for length header in first chunk)
CHUNK_SIZE = 200

# Well-known AIDs
PSE_AID = bytes.fromhex("315041592E5359532E4444463031")   # 1PAY.SYS.DDF01
PPSE_AID = bytes.fromhex("325041592E5359532E4444463031")  # 2PAY.SYS.DDF01


@dataclass
class ApduCommand:
    """A single APDU command."""
    cla: int
    ins: int
    p1: int
    p2: int
    data: bytes = b""
    le: int | None = None  # Expected response length (None=no Le, -1 omitted)
    description: str = ""

    def to_hex(self) -> str:
        """Encode as hex string (CLA INS P1 P2 [Lc Data] [Le])."""
        header = bytes([self.cla, self.ins, self.p1, self.p2])
        result = header
        if self.data:
            lc = len(self.data)
            if lc <= 255:
                result += bytes([lc]) + self.data
            else:
                # Extended length: 00 HH LL
                result += bytes([0x00, lc >> 8, lc & 0xFF]) + self.data
        if self.le is not None:
            result += bytes([self.le & 0xFF])
        return result.hex().upper()

    def __repr__(self) -> str:
        desc = f" # {self.description}" if self.description else ""
        return f"APDU({self.to_hex()}){desc}"


# ---- Transport Backends ----

class Transport(ABC):
    """Abstract APDU transport."""

    @abstractmethod
    def transmit(self, apdu: ApduCommand) -> tuple[bytes, int, int]:
        """Send an APDU and return (response_data, sw1, sw2)."""

    @abstractmethod
    def connect(self) -> None:
        """Establish connection."""

    @abstractmethod
    def disconnect(self) -> None:
        """Close connection."""


@dataclass
class DryRunTransport(Transport):
    """Collects APDUs without sending them. Prints to stdout."""
    apdus: list[ApduCommand] = field(default_factory=list)
    verbose: bool = True

    def connect(self) -> None:
        if self.verbose:
            print("[dry-run] Connected (simulated)")

    def disconnect(self) -> None:
        if self.verbose:
            print(f"[dry-run] Disconnected — {len(self.apdus)} APDUs collected")

    def transmit(self, apdu: ApduCommand) -> tuple[bytes, int, int]:
        self.apdus.append(apdu)
        desc = f"  # {apdu.description}" if apdu.description else ""
        if self.verbose:
            print(f"  → {apdu.to_hex()}{desc}")
        return b"", 0x90, 0x00  # Simulate success

    def to_gp_args(self) -> str:
        """Format collected APDUs as gp.jar -a arguments."""
        return " ".join(f"-a {a.to_hex()}" for a in self.apdus)


class PcscTransport(Transport):
    """PC/SC transport via pyscard."""

    def __init__(self, reader_name: str | None = None):
        self.reader_name = reader_name
        self._connection = None

    def connect(self) -> None:
        from smartcard.System import readers
        from smartcard.util import toHexString

        available = readers()
        if not available:
            raise RuntimeError("No smart card readers found")

        if self.reader_name:
            # Find matching reader
            matching = [r for r in available if self.reader_name.lower() in str(r).lower()]
            if not matching:
                names = ", ".join(str(r) for r in available)
                raise RuntimeError(
                    f"Reader '{self.reader_name}' not found. Available: {names}"
                )
            reader = matching[0]
        else:
            reader = available[0]

        log.info("Connecting to reader: %s", reader)
        self._connection = reader.createConnection()
        self._connection.connect()
        atr = toHexString(self._connection.getATR())
        log.info("Connected — ATR: %s", atr)

    def disconnect(self) -> None:
        if self._connection:
            self._connection.disconnect()
            self._connection = None

    def transmit(self, apdu: ApduCommand) -> tuple[bytes, int, int]:
        if not self._connection:
            raise RuntimeError("Not connected")

        apdu_bytes = list(bytes.fromhex(apdu.to_hex()))
        log.debug("TX: %s", apdu.to_hex())

        data, sw1, sw2 = self._connection.transmit(apdu_bytes)

        response_data = bytes(data)
        log.debug("RX: %s SW=%02X%02X", response_data.hex().upper(), sw1, sw2)

        if sw1 != 0x90 or sw2 != 0x00:
            sw = (sw1 << 8) | sw2
            desc = f" ({apdu.description})" if apdu.description else ""
            raise RuntimeError(
                f"Card returned SW={sw:04X}{desc} for APDU {apdu.to_hex()[:16]}..."
            )

        return response_data, sw1, sw2


# ---- APDU Builder ----

class ApduBuilder:
    """Builds and sends personalization APDUs via a transport."""

    def __init__(self, transport: Transport):
        self.transport = transport

    def send(self, apdu: ApduCommand) -> tuple[bytes, int, int]:
        return self.transport.transmit(apdu)

    def select(self, aid: bytes, description: str = "") -> tuple[bytes, int, int]:
        """SELECT an application by AID."""
        desc = description or f"SELECT {aid.hex().upper()}"
        apdu = ApduCommand(CLA_ISO, INS_SELECT, 0x04, 0x00, aid, description=desc)
        return self.send(apdu)

    def factory_reset(self, description: str = "FACTORY_RESET") -> None:
        """Send FACTORY_RESET command (INS=0x05).

        Shell script sends 8005000000 = CLA INS P1 P2 Le=00 (Case 2 APDU).
        """
        apdu = ApduCommand(CLA_PROPRIETARY, INS_FACTORY_RESET, 0x00, 0x00,
                           le=0x00, description=description)
        self.send(apdu)

    def set_emv_tag(self, tag: int, value: bytes, description: str = "") -> None:
        """Store an EMV tag value on the card.

        For data > MAX_SHORT_DATA bytes, automatically uses chunked transfer.
        """
        p1, p2 = tag_to_p1p2(tag)
        desc = description or f"SET_TAG {tag_name(tag)} ({tag:04X}), {len(value)} bytes"

        if len(value) <= MAX_SHORT_DATA:
            apdu = ApduCommand(CLA_PROPRIETARY, INS_SET_EMV_TAG, p1, p2, value, description=desc)
            self.send(apdu)
        else:
            self._chunked_tag(tag, value, desc)

    def _chunked_tag(self, tag: int, data: bytes, description: str) -> None:
        """Send large tag data using chunked transfer (INS=0x09)."""
        p1, p2 = tag_to_p1p2(tag)
        total_len = len(data)
        offset = 0
        is_first = True

        while offset < total_len:
            remaining = total_len - offset
            if is_first:
                # First chunk: 2-byte total length prefix + data
                chunk_data_size = min(CHUNK_SIZE - 2, remaining)
                chunk_payload = (
                    total_len.to_bytes(2, "big") +
                    data[offset:offset + chunk_data_size]
                )
                is_first = False
            else:
                chunk_data_size = min(CHUNK_SIZE, remaining)
                chunk_payload = data[offset:offset + chunk_data_size]

            chunk_desc = f"{description} [chunk @{offset}, {chunk_data_size}B]"
            apdu = ApduCommand(CLA_PROPRIETARY, INS_SET_EMV_TAG_CHUNKED,
                               p1, p2, chunk_payload, description=chunk_desc)
            self.send(apdu)
            offset += chunk_data_size

    def set_tag_template(self, template_id: int, tags: list[int],
                         description: str = "") -> None:
        """Configure a response template (INS=0x02).

        Template IDs:
          1 = GET_PROCESSING_OPTIONS response
          2 = DDA (INTERNAL AUTHENTICATE) response
          3 = GENERATE_AC response
          4 = SELECT Response (tag 6F content)
          5 = SELECT Response (tag A5 content)
          6 = SELECT Response (tag BF0C content)
        """
        data = build_tag_list_2byte(tags)
        desc = description or f"SET_TAG_TEMPLATE {template_id}"
        apdu = ApduCommand(CLA_PROPRIETARY, INS_SET_TAG_TEMPLATE,
                           (template_id >> 8) & 0xFF, template_id & 0xFF,
                           data, description=desc)
        self.send(apdu)

    def set_read_record_template(self, sfi: int, record: int,
                                 tags: list[int], description: str = "") -> None:
        """Configure a READ RECORD response template (INS=0x03).

        P1 = record number, P2 = (SFI << 3) | 0x04 (standard EMV SFI reference).
        The 0x04 low bits indicate "reference by SFI" per EMV spec.
        """
        data = build_tag_list_2byte(tags)
        desc = description or f"SET_READ_RECORD SFI{sfi}/REC{record}"
        apdu = ApduCommand(CLA_PROPRIETARY, INS_SET_READ_RECORD_TEMPLATE,
                           record, (sfi << 3) | 0x04, data, description=desc)
        self.send(apdu)

    def set_settings(self, setting_id: int, value: bytes,
                     description: str = "") -> None:
        """Configure a card setting (INS=0x04).

        For data > MAX_SHORT_DATA bytes, automatically uses chunked transfer.

        Setting IDs:
          0x0001 = PIN code (2 bytes)
          0x0002 = Response template tag (2 bytes: 0x0077 or 0x0080)
          0x0003 = Flags (2 bytes)
          0x0004 = RSA modulus
          0x0005 = RSA private exponent
          0x000B = EC P-256 private key scalar (32 bytes)
        """
        p1 = (setting_id >> 8) & 0xFF
        p2 = setting_id & 0xFF
        desc = description or f"SET_SETTINGS {setting_id:#06X}, {len(value)} bytes"

        if len(value) <= MAX_SHORT_DATA:
            apdu = ApduCommand(CLA_PROPRIETARY, INS_SET_SETTINGS,
                               p1, p2, value, description=desc)
            self.send(apdu)
        else:
            self._chunked_settings(setting_id, value, desc)

    def _chunked_settings(self, setting_id: int, data: bytes,
                          description: str) -> None:
        """Send large settings data using chunked transfer (INS=0x0A)."""
        p1 = (setting_id >> 8) & 0xFF
        p2 = setting_id & 0xFF
        total_len = len(data)
        offset = 0
        is_first = True

        while offset < total_len:
            remaining = total_len - offset
            if is_first:
                chunk_data_size = min(CHUNK_SIZE - 2, remaining)
                chunk_payload = (
                    total_len.to_bytes(2, "big") +
                    data[offset:offset + chunk_data_size]
                )
                is_first = False
            else:
                chunk_data_size = min(CHUNK_SIZE, remaining)
                chunk_payload = data[offset:offset + chunk_data_size]

            chunk_desc = f"{description} [chunk @{offset}, {chunk_data_size}B]"
            apdu = ApduCommand(CLA_PROPRIETARY, INS_SET_SETTINGS_CHUNKED,
                               p1, p2, chunk_payload, description=chunk_desc)
            self.send(apdu)
            offset += chunk_data_size

    # ---- CPS v2.0 STORE DATA (INS 0xE2) ----

    def store_data(self, dgi: int, data: bytes, *,
                   last: bool = False, description: str = "") -> None:
        """Send a CPS-compliant STORE DATA command.

        Per CPS v2.0 §4.3.4 Table 4-9, P1 bit 8 = 1 marks the last STORE DATA
        command, which the applet uses as the trigger to commit personalization
        (lifecycle PERSO_PENDING → PERSO_DONE). Once committed, further STORE
        DATAs return 6985.

        Default is ``last=False`` — callers sending a stream of STORE DATAs
        during personalization must not accidentally commit on the first one.
        Use :meth:`finalize_personalization` (on the high-level Card class) or
        pass ``last=True`` explicitly on the final STORE DATA of the session.

        Args:
            dgi: Data Grouping Identifier (2 bytes)
            data: DGI payload
            last: True if this is the last STORE DATA command of the session
            description: Human-readable description
        """
        desc = description or f"STORE_DATA DGI={dgi:04X}, {len(data)} bytes"

        # BER-TLV encode length
        if len(data) > 255:
            ber_len = bytes([0x82, len(data) >> 8, len(data) & 0xFF])
        elif len(data) > 127:
            ber_len = bytes([0x81, len(data)])
        else:
            ber_len = bytes([len(data)])

        payload = dgi.to_bytes(2, "big") + ber_len + data

        if len(payload) <= MAX_SHORT_DATA:
            # Single STORE DATA command
            p1 = 0x80 if last else 0x00  # bit 8: last block indicator
            apdu = ApduCommand(CLA_PROPRIETARY, INS_STORE_DATA, p1, 0x00,
                               payload, description=desc)
            self.send(apdu)
        else:
            # Chunk across multiple STORE DATA commands
            self._chunked_store_data(dgi, data, last, desc)

    def _chunked_store_data(self, dgi: int, data: bytes,
                            last: bool, description: str) -> None:
        """Send large DGI data across multiple STORE DATA commands."""
        # BER-TLV encode total length
        if len(data) > 255:
            ber_len = bytes([0x82, len(data) >> 8, len(data) & 0xFF])
        elif len(data) > 127:
            ber_len = bytes([0x81, len(data)])
        else:
            ber_len = bytes([len(data)])

        # First chunk: DGI + BER length + data
        header = dgi.to_bytes(2, "big") + ber_len
        first_chunk_size = min(MAX_STORE_DATA_PAYLOAD - len(header), len(data))
        first_payload = header + data[:first_chunk_size]

        apdu = ApduCommand(CLA_PROPRIETARY, INS_STORE_DATA, 0x00, 0x00,
                           first_payload,
                           description=f"{description} [chunk 1, {first_chunk_size}B]")
        self.send(apdu)

        # Subsequent chunks: raw data continuation
        offset = first_chunk_size
        while offset < len(data):
            remaining = len(data) - offset
            chunk_size = min(MAX_STORE_DATA_PAYLOAD, remaining)
            is_last = (offset + chunk_size >= len(data)) and last

            p1 = 0x80 if is_last else 0x00
            chunk = data[offset:offset + chunk_size]
            apdu = ApduCommand(CLA_PROPRIETARY, INS_STORE_DATA, p1, 0x00,
                               chunk,
                               description=f"{description} [chunk @{offset}, {chunk_size}B]")
            self.send(apdu)
            offset += chunk_size

    def store_data_multi(self, dgis: list[tuple[int, bytes]], *,
                         description: str = "") -> None:
        """Send multiple DGIs in a single STORE DATA command (CPS v2.0 Section 2.4).

        Args:
            dgis: List of (dgi, data) tuples to pack into one command
            description: Human-readable description
        """
        payload = b""
        for dgi, data in dgis:
            # BER-TLV encode each DGI's length
            if len(data) > 127:
                ber_len = bytes([0x81, len(data)])
            else:
                ber_len = bytes([len(data)])
            payload += dgi.to_bytes(2, "big") + ber_len + data

        desc = description or f"STORE_DATA_MULTI {len(dgis)} DGIs"

        if len(payload) <= MAX_SHORT_DATA:
            apdu = ApduCommand(CLA_PROPRIETARY, INS_STORE_DATA, 0x80, 0x00,
                               payload, description=desc)
            self.send(apdu)
        else:
            raise ValueError(
                f"Multi-DGI payload too large ({len(payload)} bytes). "
                "Send DGIs individually or reduce data."
            )
