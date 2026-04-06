"""TLV and DOL builder utilities for EMV personalization."""

from __future__ import annotations

from .tags import resolve_tag, tag_to_bytes


def encode_length(length: int) -> bytes:
    """Encode a BER-TLV length field.

    0-127     → 1 byte
    128-255   → 81 xx
    256-65535 → 82 xx xx
    """
    if length < 0x80:
        return bytes([length])
    elif length < 0x100:
        return bytes([0x81, length])
    elif length < 0x10000:
        return bytes([0x82, length >> 8, length & 0xFF])
    else:
        raise ValueError(f"Length {length} too large for BER-TLV encoding")


def build_tlv(tag: int, value: bytes) -> bytes:
    """Build a single TLV object: tag || length || value."""
    return tag_to_bytes(tag) + encode_length(len(value)) + value


def build_dol(entries: dict[str, int]) -> bytes:
    """Build a DOL (Data Object List) from a dict of {tag_name: byte_length}.

    A DOL is a concatenation of (tag || length) pairs, where length is a
    single byte indicating how many bytes the terminal should supply for
    that data element.

    Example:
        build_dol({
            "Amount Authorised": 6,
            "Unpredictable Number": 4,
            "Terminal Identification": 8,
            "Merchant Identifier": 15,
        })
        → bytes: 9F0206 9F3704 9F1C08 9F160F
    """
    result = bytearray()
    for name, length in entries.items():
        tag = resolve_tag(name)
        result.extend(tag_to_bytes(tag))
        result.append(length)
    return bytes(result)


def build_tag_list_2byte(tags: list[str | int]) -> bytes:
    """Build a tag list where each tag is padded to 2 bytes.

    Used for SET_TAG_TEMPLATE and SET_READ_RECORD_TEMPLATE commands.
    1-byte tags are left-padded with 0x00.

    Example:
        build_tag_list_2byte(["AIP", "CTQ", "AFL"])
        → bytes: 00 82 9F 6C 00 94
    """
    result = bytearray()
    for t in tags:
        tag_val = resolve_tag(str(t)) if isinstance(t, str) else t
        # Always encode as 2 bytes
        result.append((tag_val >> 8) & 0xFF)
        result.append(tag_val & 0xFF)
    return bytes(result)


def hex_to_bytes(hex_str: str) -> bytes:
    """Convert a hex string to bytes, stripping whitespace."""
    return bytes.fromhex(hex_str.replace(" ", "").replace(":", ""))


def bytes_to_hex(data: bytes) -> str:
    """Convert bytes to uppercase hex string."""
    return data.hex().upper()


def format_pan(pan: str) -> bytes:
    """Format a PAN string as BCD bytes (F-padded if odd length)."""
    if len(pan) % 2 == 1:
        pan += "F"
    return bytes.fromhex(pan)


def build_track2(pan: str, expiry_yymm: str, service_code: str = "2201") -> bytes:
    """Build Track 2 Equivalent Data.

    Format: PAN D YYMM ServiceCode 000000000000 F (truncated to 19 bytes)
    """
    pan_hex = pan if len(pan) % 2 == 0 else pan + "F"
    track2_hex = f"{pan_hex}D{expiry_yymm}{service_code}000000000000F"
    # Truncate to 38 hex chars (19 bytes)
    track2_hex = track2_hex[:38]
    return bytes.fromhex(track2_hex)


def build_afl(entries: list[tuple[int, int, int, int]]) -> bytes:
    """Build Application File Locator data.

    Each entry is (sfi, first_record, last_record, oda_record_count).
    SFI is encoded as (sfi << 3) in the AFL byte.

    Example:
        build_afl([
            (1, 2, 2, 0),  # SFI 1, records 2-2, 0 ODA
            (2, 1, 2, 2),  # SFI 2, records 1-2, 2 for ODA
            (3, 1, 5, 0),  # SFI 3, records 1-5, 0 ODA
        ])
    """
    result = bytearray()
    for sfi, first_rec, last_rec, oda_count in entries:
        result.append(sfi << 3)
        result.append(first_rec)
        result.append(last_rec)
        result.append(oda_count)
    return bytes(result)


def build_cvm_list(amount_x: int, amount_y: int, rules: list[tuple[int, int]]) -> bytes:
    """Build CVM List data.

    Args:
        amount_x: Amount field X (4 bytes, big-endian)
        amount_y: Amount field Y (4 bytes, big-endian)
        rules: List of (cvm_code, condition_code) pairs, 2 bytes each
    """
    result = bytearray()
    result.extend(amount_x.to_bytes(4, "big"))
    result.extend(amount_y.to_bytes(4, "big"))
    for cvm_code, condition_code in rules:
        result.append(cvm_code)
        result.append(condition_code)
    return bytes(result)
