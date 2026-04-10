"""Tests for the EMV tag registry."""

import pytest
from emv_personalize.tags import resolve_tag, tag_name, tag_to_bytes, tag_to_p1p2


class TestResolveTag:
    def test_by_canonical_name(self):
        assert resolve_tag("DDOL") == 0x9F49
        assert resolve_tag("PAN") == 0x5A
        assert resolve_tag("AIP") == 0x82

    def test_by_full_name(self):
        assert resolve_tag("Application Interchange Profile") == 0x82
        assert resolve_tag("Cardholder Name") == 0x5F20

    def test_case_insensitive(self):
        assert resolve_tag("ddol") == 0x9F49
        assert resolve_tag("pan") == 0x5A
        assert resolve_tag("application interchange profile") == 0x82

    def test_by_hex_string(self):
        assert resolve_tag("9F49") == 0x9F49
        assert resolve_tag("5A") == 0x5A
        assert resolve_tag("82") == 0x82

    def test_by_hex_with_prefix(self):
        assert resolve_tag("0x9F49") == 0x9F49
        assert resolve_tag("0X5A") == 0x5A

    def test_unknown_raises(self):
        with pytest.raises(ValueError, match="Unknown tag"):
            resolve_tag("not_a_real_tag")

    def test_alias_names(self):
        # Multiple names for the same tag
        assert resolve_tag("Track 2 Equivalent Data") == 0x57
        assert resolve_tag("Track2") == 0x57
        assert resolve_tag("AC") == 0x9F26
        assert resolve_tag("Application Cryptogram") == 0x9F26


class TestTagName:
    def test_known_tag(self):
        assert tag_name(0x9F49) == "DDOL"
        assert tag_name(0x5A) == "PAN"
        assert tag_name(0x82) == "Application Interchange Profile"

    def test_unknown_1byte(self):
        assert tag_name(0xFF) == "FF"

    def test_unknown_2byte(self):
        assert tag_name(0x9F99) == "9F99"


class TestTagToBytes:
    def test_1byte_tag(self):
        assert tag_to_bytes(0x5A) == b"\x5A"
        assert tag_to_bytes(0x82) == b"\x82"

    def test_2byte_tag(self):
        assert tag_to_bytes(0x9F49) == b"\x9F\x49"
        assert tag_to_bytes(0x5F20) == b"\x5F\x20"

    def test_3byte_tag(self):
        assert tag_to_bytes(0xDF8101) == b"\xDF\x81\x01"


class TestTagToP1P2:
    def test_1byte_tag(self):
        assert tag_to_p1p2(0x5A) == (0x00, 0x5A)
        assert tag_to_p1p2(0x82) == (0x00, 0x82)

    def test_2byte_tag(self):
        assert tag_to_p1p2(0x9F49) == (0x9F, 0x49)
        assert tag_to_p1p2(0x5F20) == (0x5F, 0x20)

    def test_3byte_tag_raises(self):
        with pytest.raises(ValueError, match="too large"):
            tag_to_p1p2(0xDF8101)
