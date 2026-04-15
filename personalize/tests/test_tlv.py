"""Tests for TLV and DOL builder utilities."""

import pytest
from emv_personalize.tlv import (
    encode_length, build_tlv, build_dol, build_tag_list_2byte,
    hex_to_bytes, bytes_to_hex, format_pan, build_track2, build_afl,
    build_cvm_list,
)


class TestEncodeLength:
    def test_short(self):
        assert encode_length(0) == b"\x00"
        assert encode_length(1) == b"\x01"
        assert encode_length(0x7F) == b"\x7F"

    def test_medium(self):
        assert encode_length(0x80) == b"\x81\x80"
        assert encode_length(0xFF) == b"\x81\xFF"

    def test_long(self):
        assert encode_length(0x100) == b"\x82\x01\x00"
        assert encode_length(0xFFFF) == b"\x82\xFF\xFF"

    def test_too_long(self):
        with pytest.raises(ValueError):
            encode_length(0x10000)


class TestBuildTlv:
    def test_simple(self):
        result = build_tlv(0x5A, b"\x12\x34")
        assert result == b"\x5A\x02\x12\x34"

    def test_2byte_tag(self):
        result = build_tlv(0x9F26, b"\xAB\xCD")
        assert result == b"\x9F\x26\x02\xAB\xCD"

    def test_empty_value(self):
        result = build_tlv(0x82, b"")
        assert result == b"\x82\x00"


class TestBuildDol:
    def test_ddol_from_shell_script(self):
        """DDOL should match shell script: 9F0206 9F3704 9F1C08 9F160F."""
        result = build_dol({
            "Amount Authorised": 6,
            "Unpredictable Number": 4,
            "Terminal Identification": 8,
            "Merchant Identifier": 15,
        })
        assert result == bytes.fromhex("9F02069F37049F1C089F160F")

    def test_cdol2_from_shell_script(self):
        """CDOL2 should match shell script: 8A02 + DDOL."""
        result = build_dol({
            "Authorisation Response Code": 2,
            "Amount Authorised": 6,
            "Unpredictable Number": 4,
            "Terminal Identification": 8,
            "Merchant Identifier": 15,
        })
        assert result == bytes.fromhex("8A029F02069F37049F1C089F160F")


class TestBuildTagList2Byte:
    def test_gpo_template(self):
        """GPO template: AIP(82), CTQ(9F6C), AFL(94) → 0082 9F6C 0094."""
        result = build_tag_list_2byte(["AIP", "CTQ", "AFL"])
        assert result == bytes.fromhex("00829F6C0094")

    def test_dda_template(self):
        """DDA template: 9F4C, 9F4B → 9F4C 9F4B."""
        result = build_tag_list_2byte(["9F4C", "9F4B"])
        assert result == bytes.fromhex("9F4C9F4B")

    def test_genac_template(self):
        result = build_tag_list_2byte(["9F27", "9F36", "9F26", "9F4B", "9F10"])
        assert result == bytes.fromhex("9F279F369F269F4B9F10")

    def test_mixed_1byte_and_2byte_tags(self):
        result = build_tag_list_2byte(["8F", "92", "9F32", "9F47"])
        assert result == bytes.fromhex("008F00929F329F47")

    def test_integer_tags(self):
        result = build_tag_list_2byte([0x82, 0x9F6C, 0x94])
        assert result == bytes.fromhex("00829F6C0094")


class TestHexConversions:
    def test_hex_to_bytes(self):
        assert hex_to_bytes("ABCD") == b"\xAB\xCD"
        assert hex_to_bytes("AB CD") == b"\xAB\xCD"
        assert hex_to_bytes("ab:cd") == b"\xAB\xCD"

    def test_bytes_to_hex(self):
        assert bytes_to_hex(b"\xAB\xCD") == "ABCD"


class TestFormatPan:
    def test_even_length(self):
        assert format_pan("6690750012345678") == bytes.fromhex("6690750012345678")

    def test_odd_length_pads_f(self):
        assert format_pan("123456789012345") == bytes.fromhex("123456789012345F")


class TestBuildTrack2:
    def test_standard(self):
        result = build_track2("6690750012345678", "2712")
        expected = bytes.fromhex("6690750012345678D27122201000000000000F"[:38])
        assert result == expected
        assert len(result) == 19

    def test_odd_pan(self):
        result = build_track2("123456789012345", "2712")
        # Odd PAN gets F-padded
        assert len(result) == 19


class TestBuildAfl:
    def test_matches_shell_script(self):
        """AFL from shell: 080202001001020218010500."""
        result = build_afl([
            (1, 2, 2, 0),
            (2, 1, 2, 2),
            (3, 1, 5, 0),
        ])
        assert result == bytes.fromhex("080202001001020218010500")

    def test_single_entry(self):
        result = build_afl([(1, 1, 1, 1)])
        assert result == bytes.fromhex("08010101")


class TestBuildCvmList:
    def test_visa_no_cvm(self):
        """CVM list from shell: 00000000 00000000 1F00."""
        result = build_cvm_list(0, 0, [(0x1F, 0x00)])
        assert result == bytes.fromhex("00000000000000001F00")

    def test_multiple_rules(self):
        result = build_cvm_list(0, 0, [(0x42, 0x03), (0x1F, 0x00)])
        assert result == bytes.fromhex("000000000000000042031F00")
