"""High-level Card API for EMV personalization.

Provides a human-readable interface for personalizing the emv-card-sim applet.
Translates tag names, DOL descriptors, and certificate data into APDU sequences.
"""

from __future__ import annotations

import logging
from typing import Any

from .apdu import ApduBuilder, ApduCommand, Transport, PSE_AID, PPSE_AID
from .apdu import CLA_PROPRIETARY, INS_SET_READ_RECORD_TEMPLATE
from .tags import resolve_tag, tag_name
from .tlv import (
    build_dol, build_tlv, hex_to_bytes, format_pan,
    build_track2, build_afl, build_cvm_list,
)
from .crypto import CertificateHierarchy

log = logging.getLogger(__name__)

# Setting IDs
SETTING_PIN = 0x0001
SETTING_RESPONSE_TEMPLATE = 0x0002
SETTING_FLAGS = 0x0003
SETTING_RSA_MODULUS = 0x0004
SETTING_RSA_EXPONENT = 0x0005
SETTING_EC_PRIVATE = 0x000B

# Template IDs
TEMPLATE_GPO = 1
TEMPLATE_DDA = 2
TEMPLATE_GENAC = 3
TEMPLATE_SELECT_6F = 4
TEMPLATE_SELECT_A5 = 5


class Card:
    """High-level personalization API for a single applet instance.

    Args:
        transport: APDU transport backend
        use_store_data: If True (default), use CPS v2.0 STORE DATA (INS E2)
                       with standard DGI numbering. Required for production
                       handoff to card manufacturers. If False, use the
                       proprietary 80xx dev commands — only works on
                       non-production builds where they haven't been stripped.

    Tag-value cache:
        To build record bodies in CPS mode (DGI ``01XX..1EXX``), the Card
        maintains a local cache of the raw bytes set for each EMV tag. The
        cache is populated by every ``set_tag``/``set_pan``/``set_track2``/etc.
        call so that a later ``set_record_cps(sfi, rec, [tags...])`` can build
        the inner TLV without round-tripping to the card.
    """

    def __init__(self, transport: Transport, *, use_store_data: bool = True):
        self.builder = ApduBuilder(transport)
        self.transport = transport
        self.use_store_data = use_store_data
        # Cache of raw tag values, populated as set_* methods are called.
        # Used by set_record_cps to build record inner TLVs without round-tripping.
        self._tag_cache: dict[int, bytes] = {}

    # ---- Tag cache ----

    def _cache_tag(self, tag: int, data: bytes) -> None:
        """Remember what value we set for this tag so records can reference it."""
        self._tag_cache[tag] = data

    def set_emv_tag(self, tag: int, data: bytes, description: str = "") -> None:
        """Set a raw EMV tag value on the card, caching the value locally.

        Replaces direct ``card.builder.set_emv_tag(...)`` calls so the tag
        value is both sent to the card AND remembered for later record
        template expansion. Routes through STORE DATA or dev 80 01 depending
        on ``use_store_data``.
        """
        self._cache_tag(tag, data)
        desc = description or f"SET_TAG {tag_name(tag)}"
        if self.use_store_data:
            self.builder.store_data(tag, data,
                                    description=f"STORE_DATA {desc}")
        else:
            self.builder.set_emv_tag(tag, data, desc)

    # ---- Application Selection ----

    def select(self, aid: str | bytes) -> None:
        if isinstance(aid, str):
            aid = hex_to_bytes(aid)
        self.builder.select(aid)

    def select_pse(self) -> None:
        self.builder.select(PSE_AID, "SELECT PSE (1PAY.SYS.DDF01)")

    def select_ppse(self) -> None:
        self.builder.select(PPSE_AID, "SELECT PPSE (2PAY.SYS.DDF01)")

    # ---- Factory Reset ----

    def factory_reset(self) -> None:
        """Clear the applet and local tag cache.

        Sends the proprietary ``0x8005 FACTORY_RESET`` dev command which
        wipes the applet's persistent state (EmvTag list, record store,
        lifecycle). On production builds this command is stripped and
        the card will return 6D00 — in that case we skip the reset
        (a freshly installed applet is already in PERSO_PENDING).

        Also clears the local Python tag-value cache so stale values from
        a previous applet (e.g. PSE) don't leak into records personalized
        on the next one.
        """
        try:
            self.builder.factory_reset()
        except RuntimeError as exc:
            if "6D00" in str(exc):
                import logging
                logging.info("factory_reset rejected (production build) — "
                             "continuing with fresh applet state")
            else:
                raise
        self._tag_cache.clear()

    # ---- EMV Tag Setting ----

    def set_tag(
        self,
        tag_ref: str | int,
        *,
        value: str | bytes | None = None,
        dol: dict[str, int] | None = None,
    ) -> None:
        """Set an EMV tag on the card.

        Args:
            tag_ref: Tag name ("DDOL", "PAN") or hex string ("9F49", "5A")
            value:   Raw hex string or bytes for the tag value
            dol:     For DOL tags, a dict of {tag_name: byte_length}
        """
        tag = resolve_tag(str(tag_ref))
        if dol is not None:
            data = build_dol(dol)
        elif value is not None:
            data = hex_to_bytes(value) if isinstance(value, str) else value
        else:
            raise ValueError("Must provide either 'value' or 'dol'")

        self.set_emv_tag(tag, data, f"tag {tag_name(tag)}")

    def set_pan(self, pan: str) -> None:
        data = format_pan(pan)
        tag = resolve_tag("PAN")
        self.set_emv_tag(tag, data, f"PAN ({pan})")

    def set_track2(self, pan: str, expiry_yymm: str,
                   service_code: str = "2201") -> None:
        data = build_track2(pan, expiry_yymm, service_code)
        tag = resolve_tag("Track2")
        self.set_emv_tag(tag, data, f"Track2 ({len(data)} bytes)")

    def set_afl(self, entries: list[tuple[int, int, int, int]]) -> None:
        data = build_afl(entries)
        tag = resolve_tag("AFL")
        self.set_emv_tag(tag, data, f"AFL ({len(entries)} entries)")

    def set_cvm_list(self, amount_x: int, amount_y: int,
                     rules: list[tuple[int, int]]) -> None:
        data = build_cvm_list(amount_x, amount_y, rules)
        tag = resolve_tag("CVM List")
        self.set_emv_tag(tag, data, f"CVM List ({len(rules)} rules)")

    # ---- Template Configuration ----

    # DGI constants for templates (app-specific, used with STORE DATA)
    DGI_TEMPLATE_GPO = 0xB001
    DGI_TEMPLATE_DDA = 0xB002
    DGI_TEMPLATE_GENAC = 0xB003
    DGI_TEMPLATE_FCI_6F = 0xB004
    DGI_TEMPLATE_FCI_A5 = 0xB005

    def set_gpo_template(self, tags: list[str | int]) -> None:
        resolved = [resolve_tag(str(t)) for t in tags]
        if self.use_store_data:
            from .tlv import build_tag_list_2byte
            self.builder.store_data(self.DGI_TEMPLATE_GPO,
                                    build_tag_list_2byte(resolved),
                                    description="STORE_DATA GPO template")
        else:
            self.builder.set_tag_template(TEMPLATE_GPO, resolved, "GPO template")

    def set_dda_template(self, tags: list[str | int]) -> None:
        resolved = [resolve_tag(str(t)) for t in tags]
        if self.use_store_data:
            from .tlv import build_tag_list_2byte
            self.builder.store_data(self.DGI_TEMPLATE_DDA,
                                    build_tag_list_2byte(resolved),
                                    description="STORE_DATA DDA template")
        else:
            self.builder.set_tag_template(TEMPLATE_DDA, resolved, "DDA template")

    def set_genac_template(self, tags: list[str | int]) -> None:
        resolved = [resolve_tag(str(t)) for t in tags]
        if self.use_store_data:
            from .tlv import build_tag_list_2byte
            self.builder.store_data(self.DGI_TEMPLATE_GENAC,
                                    build_tag_list_2byte(resolved),
                                    description="STORE_DATA GenAC template")
        else:
            self.builder.set_tag_template(TEMPLATE_GENAC, resolved, "GenAC template")

    def set_fci_template(self, tags_6f: list[str | int] | None = None,
                         tags_a5: list[str | int] | None = None) -> None:
        if tags_6f is not None:
            resolved = [resolve_tag(str(t)) for t in tags_6f]
            if self.use_store_data:
                from .tlv import build_tag_list_2byte
                self.builder.store_data(self.DGI_TEMPLATE_FCI_6F,
                                        build_tag_list_2byte(resolved),
                                        description="STORE_DATA FCI (6F) template")
            else:
                self.builder.set_tag_template(TEMPLATE_SELECT_6F, resolved,
                                              "FCI (6F) template")
        if tags_a5 is not None:
            resolved = [resolve_tag(str(t)) for t in tags_a5]
            if self.use_store_data:
                from .tlv import build_tag_list_2byte
                self.builder.store_data(self.DGI_TEMPLATE_FCI_A5,
                                        build_tag_list_2byte(resolved),
                                        description="STORE_DATA FCI (A5) template")
            else:
                self.builder.set_tag_template(TEMPLATE_SELECT_A5, resolved,
                                              "FCI (A5) template")

    def set_read_record_template(self, sfi: int, record: int,
                                 tags: list[str | int]) -> None:
        """Set the contents of a linear-fixed EF record.

        In CPS mode (``use_store_data=True``, the default), builds the inner
        TLV by looking up each tag in the local cache and sends it via
        STORE DATA DGI ``(sfi << 8) | record``. Each tag referenced MUST
        already have been set on the card (via ``set_tag``, ``set_pan``,
        etc.) — otherwise a ``KeyError`` is raised with the missing tag.

        In legacy dev mode (``use_store_data=False``), sends a tag-list
        template via the proprietary ``INS=0x03 SET_READ_RECORD_TEMPLATE``
        command. The applet expands this at READ RECORD time by looking
        each tag up in its EmvTag store.
        """
        resolved = [resolve_tag(str(t)) for t in tags]
        if self.use_store_data:
            self.set_record_cps(sfi, record, resolved)
        else:
            self.builder.set_read_record_template(sfi, record, resolved)

    def set_record_cps(self, sfi: int, record: int, tags: list[int]) -> None:
        """Send a record via CPS STORE DATA DGI ``(sfi<<8) | record``.

        Builds the inner TLV (concatenated tag-length-value tuples) from the
        tag cache and sends it as the DGI payload. The applet's
        processOneDgi for DGI ``01XX..1EXX`` stores the raw bytes in its
        RecordStore, and READ RECORD wraps them in tag 70 when responding.

        Raises KeyError if any referenced tag hasn't been set yet.
        """
        if not (1 <= sfi <= 30):
            raise ValueError(f"SFI must be 1..30, got {sfi}")
        if not (1 <= record <= 255):
            raise ValueError(f"Record number must be 1..255, got {record}")

        body = bytearray()
        for tag_id in tags:
            if tag_id not in self._tag_cache:
                raise KeyError(
                    f"Tag {tag_id:#06X} ({tag_name(tag_id)}) not in cache; "
                    f"set it via set_tag/set_pan/etc. before building record "
                    f"SFI{sfi}/REC{record}"
                )
            body.extend(build_tlv(tag_id, self._tag_cache[tag_id]))

        dgi = (sfi << 8) | record
        self.builder.store_data(
            dgi, bytes(body),
            description=f"STORE_DATA record SFI{sfi}/REC{record} ({len(body)}B, {len(tags)} tags)",
        )

    def create_ef(self, sfi: int, num_records: int,
                  max_record_size: int) -> None:
        """Send DGI 0062 to pre-declare an EF's file structure.

        Builds a single 62-FCP TLV per CPS v2.0 Annex A.5 Table A-27:

          62 L
            80 02 <file_size>      (number of data bytes)
            82 05 0A 01 <max_rec> <num_recs>   (linear fixed, T=1, max rec size, num recs)
            88 01 <sfi>            (short EF identifier)

        The applet preallocates the SFI's record slots so subsequent record
        DGIs (XX YY) are validated against the declared bounds. Optional per
        spec but recommended for real perso bureau workflows.
        """
        if not (1 <= sfi <= 30):
            raise ValueError(f"SFI must be 1..30, got {sfi}")
        if not (1 <= num_records <= 16):
            raise ValueError(f"num_records must be 1..16, got {num_records}")
        if not (1 <= max_record_size <= 254):
            raise ValueError(f"max_record_size must be 1..254, got {max_record_size}")

        file_size = num_records * max_record_size
        inner = (
            b"\x80\x02" + file_size.to_bytes(2, "big") +
            b"\x82\x05\x0a\x01" + max_record_size.to_bytes(2, "big") + bytes([num_records]) +
            b"\x88\x01" + bytes([sfi])
        )
        fcp = b"\x62" + bytes([len(inner)]) + inner
        self.builder.store_data(
            0x0062, fcp,
            description=f"STORE_DATA DGI 0062 (create EF SFI{sfi}, {num_records}x{max_record_size}B)",
        )

    # ---- Settings ----

    # CPS DGIs for settings
    DGI_PIN = 0x8010         # CPS standard: offline PIN block
    DGI_RSA_KEY = 0x8000     # CPS standard: block cipher keys (symmetric)
    # App-specific DGIs for asymmetric keys and config (not in CPS standard)
    DGI_RSA_MODULUS = 0x8201
    DGI_RSA_EXPONENT = 0x8202
    DGI_EC_SCALAR = 0x8203
    DGI_RESPONSE_TEMPLATE = 0xA002
    DGI_FLAGS = 0xA003

    def set_pin(self, pin: str) -> None:
        data = bytes.fromhex(pin)
        if self.use_store_data:
            self.builder.store_data(self.DGI_PIN, data, description=f"STORE_DATA PIN={pin}")
        else:
            self.builder.set_settings(SETTING_PIN, data, f"PIN={pin}")

    def set_response_template_tag(self, tag: int) -> None:
        data = tag.to_bytes(2, "big")
        if self.use_store_data:
            self.builder.store_data(self.DGI_RESPONSE_TEMPLATE, data,
                                    description=f"STORE_DATA Response template={tag:#06X}")
        else:
            self.builder.set_settings(SETTING_RESPONSE_TEMPLATE, data,
                                      f"Response template={tag:#06X}")

    def set_flags(self, use_random: bool = True) -> None:
        flags = 0x0001 if use_random else 0x0000
        data = flags.to_bytes(2, "big")
        if self.use_store_data:
            self.builder.store_data(self.DGI_FLAGS, data,
                                    description=f"STORE_DATA Flags={'random' if use_random else 'predictable'}")
        else:
            self.builder.set_settings(SETTING_FLAGS, data,
                                      f"Flags={'random' if use_random else 'predictable'}")

    def set_rsa_key(self, modulus: bytes, private_exp: bytes) -> None:
        if self.use_store_data:
            # App-specific DGIs for RSA key components (not CPS 8000 which is symmetric)
            self.builder.store_data(self.DGI_RSA_MODULUS, modulus,
                                    description=f"STORE_DATA RSA modulus ({len(modulus)}B)")
            self.builder.store_data(self.DGI_RSA_EXPONENT, private_exp,
                                    description=f"STORE_DATA RSA exponent ({len(private_exp)}B)")
        else:
            self.builder.set_settings(SETTING_RSA_MODULUS, modulus,
                                      f"RSA modulus ({len(modulus)} bytes)")
            self.builder.set_settings(SETTING_RSA_EXPONENT, private_exp,
                                      f"RSA private exp ({len(private_exp)} bytes)")

    def set_ec_private_key(self, scalar: bytes) -> None:
        if len(scalar) != 32:
            raise ValueError(f"EC scalar must be 32 bytes, got {len(scalar)}")
        if self.use_store_data:
            self.builder.store_data(self.DGI_EC_SCALAR, scalar,
                                    description="STORE_DATA EC P-256 private key")
        else:
            self.builder.set_settings(SETTING_EC_PRIVATE, scalar, "EC P-256 private key")

    # ---- Personalization Lifecycle ----

    def finalize_personalization(self) -> None:
        """Commit the applet's personalization lifecycle.

        Sends a final STORE DATA command with bit 8 of P1 set (CPS v2.0
        §4.3.4 Table 4-9). On receipt, the applet transitions from
        PERSO_PENDING to PERSO_DONE (CPS §4.3.5.1). Once committed, any
        further STORE DATA on the same applet returns 6985.

        The payload is DGI 7FFF (personalization integrity MAC per CPS
        §4.3.5.2). We don't compute a real MAC here — the applet accepts
        DGI 7FFF as a no-op placeholder — but CPS recommends it be present
        in the last STORE DATA command.

        Should only be called in STORE DATA mode (use_store_data=True).
        In dev-command mode the lifecycle stays PERSO_PENDING.
        """
        if not self.use_store_data:
            log.debug("finalize_personalization() no-op in dev-command mode")
            return
        # DGI 7FFF placeholder payload (8 bytes of zeros). Real perso bureau
        # would put the computed CPS integrity MAC here.
        self.builder.store_data(0x7FFF, b"\x00" * 8,
                                last=True,
                                description="STORE_DATA DGI 7FFF (finalize perso)")


# ---- Personalization Functions ----


def personalize_pse(
    card: Card, *, contact_aid: str, label: str,
) -> None:
    """Personalize the PSE (1PAY.SYS.DDF01) directory applet."""
    pse_aid_hex = PSE_AID.hex()
    aid_bytes = hex_to_bytes(contact_aid)
    label_bytes = label.encode()

    card.select_pse()
    card.factory_reset()

    card.set_tag("8E", value=pse_aid_hex)
    card.set_tag("DF Name", value=pse_aid_hex)
    card.set_tag("88", value="01")
    card.set_tag("Language Preference", value="656E")

    card.set_fci_template(tags_a5=["88"], tags_6f=["DF Name", "A5"])

    # Build directory entry: 4F <aid> 50 <label> 87 01
    dir_entry = bytearray()
    dir_entry += b"\x4F" + bytes([len(aid_bytes)]) + aid_bytes
    dir_entry += b"\x50" + bytes([len(label_bytes)]) + label_bytes
    dir_entry += b"\x87\x01\x01"
    # Set tag 61 (caches the value) and bind it to SFI 1 REC 1 as the PSE's
    # directory record. set_read_record_template will build the inner TLV
    # `61 LL <dir_entry>` from the cached tag and send STORE DATA DGI 0101.
    card.set_emv_tag(0x61, bytes(dir_entry), "PSE directory entry (61)")
    card.set_read_record_template(1, 1, ["61"])


def personalize_ppse(
    card: Card, *, contactless_aid: str, label: str,
    preferred_name: str | None = None,
    kernel_identifier: str | None = None,
) -> None:
    """Personalize the PPSE (2PAY.SYS.DDF01) directory applet.

    The PPSE applet is specialised — it does NOT use the generic EmvTag store
    or RecordStore. It has its own proprietary STORE DATA handler that accepts
    only two DGIs:

      * ``D001`` — directory entry (inside-tag-61 content)
      * ``D002`` — complete FCI template (not used here)

    We therefore bypass ``card.set_emv_tag()`` and send the directory entry
    directly via STORE DATA DGI D001 regardless of ``use_store_data`` mode.
    """
    aid_bytes = hex_to_bytes(contactless_aid)
    label_bytes = label.encode()

    card.select_ppse()
    card.factory_reset()

    # Build directory entry: AID + label + priority + kernel ID
    dir_entry = bytearray()
    dir_entry += b"\x4F" + bytes([len(aid_bytes)]) + aid_bytes
    dir_entry += b"\x50" + bytes([len(label_bytes)]) + label_bytes
    dir_entry += b"\x87\x01\x01"  # Priority
    if kernel_identifier:
        kid = bytes.fromhex(kernel_identifier)
        dir_entry += b"\x9F\x2A" + bytes([len(kid)]) + kid

    # Send to PPSE's proprietary STORE DATA handler as DGI D001.
    card.builder.store_data(
        0xD001, bytes(dir_entry),
        description=f"STORE_DATA PPSE directory entry (DGI D001, {len(dir_entry)}B)",
    )


def personalize_payment_app(
    card: Card,
    *,
    aid: str,
    profile: dict,
    pan: str,
    expiry_yymmdd: str,
    certs: CertificateHierarchy,
    contactless: bool = False,
) -> None:
    """Personalize one payment application instance (contact or contactless).

    The same function handles both interfaces — the applet stores one set of
    tags and decides which to use at runtime based on the interface detected.
    This replaces the 4 near-identical sections in personalize.sh.

    Args:
        card: Card API instance
        aid: Full AID hex string (e.g., "A0000009510001")
        profile: Parsed YAML profile dict
        pan: Primary Account Number
        expiry_yymmdd: Expiry date in YYMMDD format
        certs: Certificate hierarchy (CAPK → Issuer → ICC)
        contactless: If True, apply contactless overrides (PDOL, FCI with 9F38)
    """
    label = profile.get("application_label", "COLOSSUS")
    expiry_yymm = expiry_yymmdd[:4]
    cardholder_name = f"{label}/CARDHOLDER "

    # Merge contactless overrides into profile if applicable
    cl_overrides = profile.get("contactless", {}) if contactless else {}

    # ── Select & Reset ──
    card.select(aid)
    card.factory_reset()

    # ── Settings ──
    settings = profile.get("settings", {})
    flags = settings.get("flags", {})
    card.set_flags(use_random=flags.get("use_random", True))
    card.set_pin(settings.get("pin", "1234"))
    resp_tmpl = settings.get("response_template", "0077")
    card.set_response_template_tag(
        int(resp_tmpl, 16) if isinstance(resp_tmpl, str) else resp_tmpl
    )

    # ── RSA + EC keys ──
    card.set_rsa_key(certs.icc.modulus, certs.icc.private_exp)
    if certs.ec_key:
        card.set_ec_private_key(certs.ec_key.private_scalar)

    # ── Certificates ──
    card.set_tag("CA Public Key Index", value=certs.capk_index)
    card.set_tag("Issuer PK Exponent", value="03")
    card.set_emv_tag(0x90, certs.issuer_cert.certificate,
                     "Issuer PK Certificate")
    card.set_emv_tag(0x92, certs.issuer_cert.remainder,
                     "Issuer PK Remainder")
    card.set_tag("ICC PK Exponent", value="03")
    card.set_emv_tag(0x9F46, certs.icc_cert.certificate,
                     "ICC PK Certificate")
    card.set_emv_tag(0x9F48, certs.icc_cert.remainder,
                     "ICC PK Remainder")

    # ── Response Templates (from profile) ──
    templates = profile.get("templates", {})
    card.set_gpo_template(templates.get("gpo", ["AIP", "CTQ", "AFL"]))
    card.set_dda_template(templates.get("dda", ["9F4C", "9F4B"]))
    card.set_genac_template(templates.get("genac", ["9F27", "9F36", "9F26", "9F4B", "9F10"]))
    # FCI template — contactless adds 9F12 (Preferred Name) and 9F38 (PDOL)
    cl_fci = cl_overrides.get("fci", {})
    fci = templates.get("fci", {})
    card.set_fci_template(
        tags_a5=cl_fci.get("a5", fci.get("a5", ["Application Label", "Application Priority Indicator"])),
        tags_6f=cl_fci.get("6f", fci.get("6f", ["DF Name", "A5"])),
    )

    # ── ATC ──
    card.set_tag("ATC", value="0001")

    # ── Core Identity Tags ──
    card.set_tag("DF Name", value=aid)
    card.set_pan(pan)
    card.set_tag("Application Expiration Date", value=expiry_yymmdd)
    card.set_tag("PAN Sequence Number", value="01")
    card.set_track2(pan, expiry_yymm)
    card.set_tag("Application Label", value=label.encode().hex())
    card.set_tag("Application Priority Indicator", value="01")
    if contactless:
        preferred_name = profile.get("preferred_name", label)
        card.set_tag("Application Preferred Name", value=preferred_name.encode().hex())
    card.set_tag("Cardholder Name", value=cardholder_name.encode().hex())

    # ── AFL (from profile) ──
    afl_entries = []
    for entry in profile.get("afl", []):
        afl_entries.append((
            entry["sfi"], entry["first_record"],
            entry["last_record"], entry.get("oda_count", 0),
        ))
    if afl_entries:
        card.set_afl(afl_entries)

    # ── CVM List (from profile) ──
    cvm = profile.get("cvm_list", {})
    if cvm:
        rules = [(r[0], r[1]) for r in cvm.get("rules", [(0x1F, 0x00)])]
        card.set_cvm_list(cvm.get("amount_x", 0), cvm.get("amount_y", 0), rules)

    # ── All Other Tags (from profile) ──
    # DOLs, IACs, AIP, currency codes, etc. — all driven by the YAML
    for tag_name_or_hex, spec in profile.get("tags", {}).items():
        if isinstance(spec, dict):
            tag_type = spec.get("type", "raw")
            if tag_type == "dol":
                card.set_tag(tag_name_or_hex, dol=spec["value"])
            else:
                card.set_tag(tag_name_or_hex, value=spec["value"])
        else:
            card.set_tag(tag_name_or_hex, value=str(spec))

    # ── Contactless-only tags (PDOL, etc.) ──
    for tag_name_or_hex, spec in cl_overrides.get("tags", {}).items():
        if isinstance(spec, dict):
            tag_type = spec.get("type", "raw")
            if tag_type == "dol":
                card.set_tag(tag_name_or_hex, dol=spec["value"])
            else:
                card.set_tag(tag_name_or_hex, value=spec["value"])
        else:
            card.set_tag(tag_name_or_hex, value=str(spec))

    # ── READ RECORD Templates (LAST — records reference tags set above) ──
    # In CPS mode, records are built as inner TLVs from the tag cache, so every
    # referenced tag must already have been set by the time we get here. Keep
    # this block at the bottom of the personalization sequence.
    for sfi_def in profile.get("records", []):
        sfi = sfi_def["sfi"]
        for rec_def in sfi_def["records"]:
            card.set_read_record_template(sfi, rec_def["record"], rec_def["tags"])
