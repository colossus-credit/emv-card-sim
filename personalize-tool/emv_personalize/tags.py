"""EMV Tag Registry — maps human-readable names to hex tag IDs."""

# Canonical registry: tag_hex (int) → list of known names
# First name in the list is the "canonical" display name.
_TAG_DB: dict[int, list[str]] = {
    # ---- Single-byte tags (00-9E) ----
    0x50: ["Application Label"],
    0x57: ["Track 2 Equivalent Data", "Track2"],
    0x61: ["Application Template"],
    0x6F: ["FCI Template"],
    0x70: ["EMV Proprietary Template", "Record Template"],
    0x77: ["Response Message Template Format 2"],
    0x80: ["Response Message Template Format 1"],
    0x82: ["Application Interchange Profile", "AIP"],
    0x84: ["DF Name", "Dedicated File Name"],
    0x87: ["Application Priority Indicator"],
    0x88: ["SFI of Directory Elementary File", "Short File Identifier"],
    0x8C: ["CDOL1", "Card Risk Management DOL 1"],
    0x8D: ["CDOL2", "Card Risk Management DOL 2"],
    0x8E: ["CVM List", "Cardholder Verification Method List"],
    0x8F: ["CA Public Key Index", "Certification Authority PK Index"],
    0x90: ["Issuer PK Certificate", "Issuer Public Key Certificate"],
    0x92: ["Issuer PK Remainder", "Issuer Public Key Remainder"],
    0x94: ["Application File Locator", "AFL"],
    0x9A: ["Transaction Date"],
    0x9C: ["Transaction Type"],

    # ---- Two-byte tags (5Fxx, 9Fxx, DFxx) ----
    0x5F20: ["Cardholder Name"],
    0x5F24: ["Application Expiration Date"],
    0x5F25: ["Application Effective Date"],
    0x5F28: ["Issuer Country Code"],
    0x5F2A: ["Transaction Currency Code"],
    0x5F2D: ["Language Preference"],
    0x5F30: ["Service Code"],
    0x5F34: ["PAN Sequence Number", "PSN"],

    0x9F01: ["Acquirer Identifier"],
    0x9F02: ["Amount Authorised", "Amount, Authorised"],
    0x9F03: ["Amount Other", "Amount, Other"],
    0x9F06: ["AID", "Application Identifier"],
    0x9F07: ["Application Usage Control", "AUC"],
    0x9F08: ["Application Version Number"],
    0x9F09: ["Application Version Number (Terminal)"],
    0x9F0D: ["IAC-Default", "Issuer Action Code - Default"],
    0x9F0E: ["IAC-Denial", "Issuer Action Code - Denial"],
    0x9F0F: ["IAC-Online", "Issuer Action Code - Online"],
    0x9F10: ["Issuer Application Data", "IAD"],
    0x9F11: ["Issuer Code Table Index"],
    0x9F12: ["Application Preferred Name"],
    0x9F16: ["Merchant Identifier"],
    0x9F1A: ["Terminal Country Code"],
    0x9F1C: ["Terminal Identification"],
    0x9F1F: ["Track 1 Discretionary Data"],
    0x9F26: ["Application Cryptogram", "AC"],
    0x9F27: ["Cryptogram Information Data", "CID"],
    0x9F32: ["Issuer PK Exponent", "Issuer Public Key Exponent"],
    0x9F33: ["Terminal Capabilities"],
    0x9F34: ["CVM Results"],
    0x9F35: ["Terminal Type"],
    0x9F36: ["Application Transaction Counter", "ATC"],
    0x9F37: ["Unpredictable Number"],
    0x9F38: ["PDOL", "Processing Options DOL"],
    0x9F40: ["Additional Terminal Capabilities"],
    0x9F42: ["Application Currency Code"],
    0x9F44: ["Application Currency Exponent"],
    0x9F46: ["ICC PK Certificate", "ICC Public Key Certificate"],
    0x9F47: ["ICC PK Exponent", "ICC Public Key Exponent"],
    0x9F48: ["ICC PK Remainder", "ICC Public Key Remainder"],
    0x9F49: ["DDOL", "Dynamic Data Authentication DOL"],
    0x9F4A: ["Static Data Authentication Tag List", "SDA Tag List"],
    0x9F4B: ["Signed Dynamic Application Data", "SDAD"],
    0x9F4C: ["ICC Dynamic Number"],
    0x9F66: ["Terminal Transaction Qualifiers", "TTQ"],
    0x9F6C: ["Card Transaction Qualifiers", "CTQ"],
    0x9F69: ["UDOL", "Card Authentication Related Data"],

    0x8A: ["Authorisation Response Code", "ARC"],

    # ---- Constructed tags ----
    0xA5: ["FCI Proprietary Template"],
    0xBF0C: ["FCI Issuer Discretionary Data"],

    # ---- Proprietary / less common ----
    0x5A: ["PAN", "Application Primary Account Number"],
    0x95: ["Terminal Verification Results", "TVR"],
    0x9B: ["Transaction Status Information", "TSI"],
    0xDF8101: ["Visa Contactless Limit"],
}

# ---- Build reverse lookups ----

# name_lower → tag_hex
_NAME_TO_TAG: dict[str, int] = {}
# tag_hex → canonical name
_TAG_TO_NAME: dict[int, str] = {}

for _tag, _names in _TAG_DB.items():
    _TAG_TO_NAME[_tag] = _names[0]
    for _n in _names:
        _NAME_TO_TAG[_n.lower()] = _tag


def resolve_tag(name_or_hex: str) -> int:
    """Resolve a tag name or hex string to an integer tag value.

    Examples:
        resolve_tag("DDOL")          → 0x9F49
        resolve_tag("9F49")          → 0x9F49
        resolve_tag("PAN")           → 0x5A
        resolve_tag("Application Interchange Profile") → 0x82
    """
    # Try name lookup first (case-insensitive)
    tag = _NAME_TO_TAG.get(name_or_hex.lower())
    if tag is not None:
        return tag

    # Try parsing as hex
    cleaned = name_or_hex.replace("0x", "").replace("0X", "").strip()
    try:
        return int(cleaned, 16)
    except ValueError:
        raise ValueError(f"Unknown tag: {name_or_hex!r}")


def tag_name(tag: int) -> str:
    """Return canonical name for a tag, or hex string if unknown."""
    return _TAG_TO_NAME.get(tag, f"{tag:04X}" if tag > 0xFF else f"{tag:02X}")


def tag_to_bytes(tag: int) -> bytes:
    """Encode a tag integer to its minimal byte representation.

    0x5A     → b'\\x5a'       (1 byte)
    0x9F49   → b'\\x9f\\x49'  (2 bytes)
    0xDF8101 → b'\\xdf\\x81\\x01' (3 bytes)
    """
    if tag <= 0xFF:
        return bytes([tag])
    elif tag <= 0xFFFF:
        return bytes([tag >> 8, tag & 0xFF])
    else:
        return bytes([(tag >> 16) & 0xFF, (tag >> 8) & 0xFF, tag & 0xFF])


def tag_to_p1p2(tag: int) -> tuple[int, int]:
    """Encode a tag as (P1, P2) for the applet's SET_EMV_TAG command.

    1-byte tags:  P1=0x00, P2=tag
    2-byte tags:  P1=high_byte, P2=low_byte
    """
    if tag <= 0xFF:
        return (0x00, tag)
    elif tag <= 0xFFFF:
        return (tag >> 8, tag & 0xFF)
    else:
        raise ValueError(f"Tag {tag:#X} is too large for P1P2 encoding (max 2 bytes)")
