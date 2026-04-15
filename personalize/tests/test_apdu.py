"""Tests for APDU protocol layer."""

import pytest
from emv_personalize.apdu import (
    ApduCommand, ApduBuilder, DryRunTransport,
    CLA_PROPRIETARY, CLA_ISO, INS_SET_EMV_TAG, INS_FACTORY_RESET,
    INS_SELECT, PSE_AID, PPSE_AID,
)


class TestApduCommand:
    def test_case1_no_data_no_le(self):
        """Case 1: CLA INS P1 P2 only."""
        apdu = ApduCommand(0x80, 0x05, 0x00, 0x00)
        assert apdu.to_hex() == "80050000"

    def test_case2_le_only(self):
        """Case 2: CLA INS P1 P2 Le — factory reset."""
        apdu = ApduCommand(0x80, 0x05, 0x00, 0x00, le=0x00)
        assert apdu.to_hex() == "8005000000"

    def test_case3_data_only(self):
        """Case 3: CLA INS P1 P2 Lc Data."""
        apdu = ApduCommand(0x80, 0x01, 0x00, 0x82, b"\x3C\x01")
        assert apdu.to_hex() == "80010082023C01"

    def test_select_pse(self):
        """SELECT PSE: 00 A4 04 00 0E <PSE AID>."""
        apdu = ApduCommand(CLA_ISO, INS_SELECT, 0x04, 0x00, PSE_AID)
        assert apdu.to_hex() == "00A404000E315041592E5359532E4444463031"

    def test_extended_length(self):
        """Data > 255 bytes uses extended length encoding."""
        data = bytes(256)
        apdu = ApduCommand(0x80, 0x01, 0x9F, 0x46, data)
        hex_str = apdu.to_hex()
        # 80 01 9F 46 00 01 00 <256 zeros>
        assert hex_str.startswith("80019F46000100")
        assert len(hex_str) == (4 + 3 + 256) * 2  # header + ext_lc + data


class TestDryRunTransport:
    def test_collects_apdus(self):
        transport = DryRunTransport(verbose=False)
        transport.connect()
        apdu = ApduCommand(0x80, 0x05, 0x00, 0x00, le=0x00)
        data, sw1, sw2 = transport.transmit(apdu)
        assert data == b""
        assert sw1 == 0x90
        assert sw2 == 0x00
        assert len(transport.apdus) == 1
        transport.disconnect()

    def test_to_gp_args(self):
        transport = DryRunTransport(verbose=False)
        transport.transmit(ApduCommand(0x80, 0x05, 0x00, 0x00, le=0x00))
        transport.transmit(ApduCommand(0x80, 0x01, 0x00, 0x82, b"\x3C\x01"))
        result = transport.to_gp_args()
        assert result == "-a 8005000000 -a 80010082023C01"


class TestApduBuilder:
    def setup_method(self):
        self.transport = DryRunTransport(verbose=False)
        self.builder = ApduBuilder(self.transport)

    def test_factory_reset(self):
        self.builder.factory_reset()
        assert len(self.transport.apdus) == 1
        assert self.transport.apdus[0].to_hex() == "8005000000"

    def test_select(self):
        self.builder.select(PSE_AID)
        assert self.transport.apdus[0].to_hex() == "00A404000E315041592E5359532E4444463031"

    def test_set_emv_tag_small(self):
        """AIP: 80 01 00 82 02 3C01."""
        self.builder.set_emv_tag(0x82, b"\x3C\x01")
        assert self.transport.apdus[0].to_hex() == "80010082023C01"

    def test_set_emv_tag_2byte_tag(self):
        """DDOL: 80 01 9F 49 0C ..."""
        data = bytes.fromhex("9F02069F37049F1C089F160F")
        self.builder.set_emv_tag(0x9F49, data)
        assert self.transport.apdus[0].to_hex() == "80019F490C9F02069F37049F1C089F160F"

    def test_set_emv_tag_chunked(self):
        """Data > 250 bytes should auto-chunk."""
        big_data = bytes(300)
        self.builder.set_emv_tag(0x90, big_data)
        # Should produce multiple APDUs with INS=0x09
        assert len(self.transport.apdus) >= 2
        # First chunk has INS=0x09 and starts with 2-byte total length
        first = self.transport.apdus[0]
        assert first.ins == 0x09
        assert first.data[:2] == (300).to_bytes(2, "big")

    def test_set_tag_template_gpo(self):
        """GPO template: 80 02 00 01 06 0082 9F6C 0094."""
        self.builder.set_tag_template(1, [0x82, 0x9F6C, 0x94])
        assert self.transport.apdus[0].to_hex() == "800200010600829F6C0094"

    def test_set_tag_template_dda(self):
        """DDA template: 80 02 00 02 04 9F4C 9F4B."""
        self.builder.set_tag_template(2, [0x9F4C, 0x9F4B])
        assert self.transport.apdus[0].to_hex() == "80020002049F4C9F4B"

    def test_set_read_record_template_sfi1_rec2(self):
        """SFI1/REC2: 80 03 02 0C 06 0057 5F20 9F1F."""
        self.builder.set_read_record_template(1, 2, [0x57, 0x5F20, 0x9F1F])
        assert self.transport.apdus[0].to_hex() == "8003020C0600575F209F1F"

    def test_set_read_record_template_sfi2_rec1(self):
        """SFI2/REC1: 80 03 01 14 08 008F 0092 9F32 9F47."""
        self.builder.set_read_record_template(2, 1, [0x8F, 0x92, 0x9F32, 0x9F47])
        assert self.transport.apdus[0].to_hex() == "8003011408008F00929F329F47"

    def test_set_read_record_template_sfi3_rec1(self):
        """SFI3/REC1: 80 03 01 1C 18 005A 5F24 ... 008C 008D."""
        tags = [0x5A, 0x5F24, 0x5F25, 0x5F28, 0x5F34,
                0x9F07, 0x9F0D, 0x9F0E, 0x9F0F, 0x9F4A, 0x8C, 0x8D]
        self.builder.set_read_record_template(3, 1, tags)
        assert self.transport.apdus[0].to_hex() == \
            "8003011C18005A5F245F255F285F349F079F0D9F0E9F0F9F4A008C008D"

    def test_set_settings_flags(self):
        """Flags: 80 04 00 03 02 0001."""
        self.builder.set_settings(0x0003, b"\x00\x01")
        assert self.transport.apdus[0].to_hex() == "80040003020001"

    def test_set_settings_pin(self):
        """PIN: 80 04 00 01 02 1234."""
        self.builder.set_settings(0x0001, bytes.fromhex("1234"))
        assert self.transport.apdus[0].to_hex() == "80040001021234"

    def test_set_settings_chunked(self):
        """Large settings data (>250 bytes) uses INS=0x0A."""
        big_data = bytes(260)
        self.builder.set_settings(0x0004, big_data)
        assert len(self.transport.apdus) >= 2
        assert self.transport.apdus[0].ins == 0x0A

    def test_set_settings_ec_key(self):
        """EC private key: 80 04 00 0B 20 <32 bytes>."""
        scalar = bytes(32)
        self.builder.set_settings(0x000B, scalar)
        hex_str = self.transport.apdus[0].to_hex()
        assert hex_str.startswith("8004000B20")
        assert len(hex_str) == (4 + 1 + 32) * 2
