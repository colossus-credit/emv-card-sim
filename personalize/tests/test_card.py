"""Tests for the high-level Card API and personalization functions."""

import pytest
import yaml
from emv_personalize.apdu import DryRunTransport, PSE_AID, PPSE_AID
from emv_personalize.card import (
    Card, personalize_pse, personalize_ppse, personalize_payment_app,
)
from emv_personalize.crypto import CertificateHierarchy


@pytest.fixture
def card():
    """Card fixture pinned to legacy dev-command mode.

    These tests assert specific 80xx APDU byte sequences (SET_TAG, SET_SETTINGS,
    SET_READ_RECORD_TEMPLATE, etc.). They were written before the default
    flipped to CPS mode, so they explicitly request ``use_store_data=False``
    to keep asserting dev-mode output. CPS-mode test coverage lives in the
    dry-run integration path in ``personalize.py``.
    """
    transport = DryRunTransport(verbose=False)
    return Card(transport, use_store_data=False), transport


@pytest.fixture
def certs():
    return CertificateHierarchy.generate(
        pan="6690750012345678", key_size=1024, capk_index="92",
    )


@pytest.fixture
def profile():
    """Minimal profile dict matching default.yaml structure."""
    return {
        "application_label": "TEST",
        "rid": "A000000951",
        "contact_aid_suffix": "0001",
        "contactless_aid_suffix": "1010",
        "bin": "66907500",
        "expiry": "271231",
        "keys": {"capk_index": "92", "key_size": 1024},
        "templates": {
            "gpo": ["AIP", "CTQ", "AFL"],
            "dda": ["9F4C", "9F4B"],
            "genac": ["9F27", "9F36", "9F26", "9F4B", "9F10"],
            "fci": {
                "6f": ["DF Name", "A5"],
                "a5": ["Application Label", "Application Priority Indicator"],
            },
        },
        "records": [
            {"sfi": 1, "records": [{"record": 2, "tags": ["57", "5F20", "9F1F"]}]},
            {"sfi": 2, "records": [
                {"record": 1, "tags": ["8F", "92", "9F32", "9F47"]},
                {"record": 2, "tags": ["90"]},
            ]},
            {"sfi": 3, "records": [
                {"record": 1, "tags": ["5A", "5F24", "5F25", "5F28", "5F34",
                                        "9F07", "9F0D", "9F0E", "9F0F", "9F4A",
                                        "8C", "8D"]},
                {"record": 2, "tags": ["8E"]},
                {"record": 3, "tags": ["5F30", "9F08", "9F42", "9F44", "9F49"]},
                {"record": 4, "tags": ["9F46"]},
                {"record": 5, "tags": ["9F48"]},
            ]},
        ],
        "afl": [
            {"sfi": 1, "first_record": 2, "last_record": 2, "oda_count": 0},
            {"sfi": 2, "first_record": 1, "last_record": 2, "oda_count": 2},
            {"sfi": 3, "first_record": 1, "last_record": 5, "oda_count": 0},
        ],
        "settings": {"pin": "1234", "flags": {"use_random": True},
                      "response_template": "0077"},
        "cvm_list": {"amount_x": 0, "amount_y": 0, "rules": [[0x1F, 0x00]]},
        "tags": {
            "DDOL": {"type": "dol", "value": {
                "Amount Authorised": 6, "Unpredictable Number": 4,
                "Terminal Identification": 8, "Merchant Identifier": 15,
            }},
            "CDOL1": {"type": "dol", "value": {
                "Amount Authorised": 6, "Unpredictable Number": 4,
                "Terminal Identification": 8, "Merchant Identifier": 15,
            }},
            "CDOL2": {"type": "dol", "value": {
                "Authorisation Response Code": 2, "Amount Authorised": 6,
                "Unpredictable Number": 4, "Terminal Identification": 8,
                "Merchant Identifier": 15,
            }},
            "Application Interchange Profile": "3C01",
            "Application Version Number": "0001",
            "Application Effective Date": "240101",
            "Issuer Country Code": "0840",
            "Application Usage Control": "FF0000",
            "SDA Tag List": "82",
            "Service Code": "0201",
            "Application Currency Code": "0840",
            "Application Currency Exponent": "02",
            "IAC-Default": "FC688C9800",
            "IAC-Denial": "0000000000",
            "IAC-Online": "FC68FC9800",
            "Issuer Application Data": "06010A03A4A002",
            "CTQ": "8000",
        },
    }


class TestCardSetTag:
    def test_set_tag_by_name(self, card):
        c, transport = card
        c.set_tag("AIP", value="3C01")
        assert transport.apdus[-1].to_hex() == "80010082023C01"

    def test_set_tag_by_hex(self, card):
        c, transport = card
        c.set_tag("9F6C", value="8000")
        assert transport.apdus[-1].to_hex() == "80019F6C028000"

    def test_set_tag_dol(self, card):
        c, transport = card
        c.set_tag("DDOL", dol={
            "Amount Authorised": 6,
            "Unpredictable Number": 4,
            "Terminal Identification": 8,
            "Merchant Identifier": 15,
        })
        assert transport.apdus[-1].to_hex() == "80019F490C9F02069F37049F1C089F160F"

    def test_set_tag_requires_value_or_dol(self, card):
        c, _ = card
        with pytest.raises(ValueError, match="Must provide"):
            c.set_tag("AIP")


class TestCardTemplates:
    def test_gpo_template(self, card):
        c, transport = card
        c.set_gpo_template(["AIP", "CTQ", "AFL"])
        assert transport.apdus[-1].to_hex() == "800200010600829F6C0094"

    def test_read_record_template(self, card):
        c, transport = card
        c.set_read_record_template(2, 1, ["8F", "92", "9F32", "9F47"])
        assert transport.apdus[-1].to_hex() == "8003011408008F00929F329F47"


class TestCardSettings:
    def test_set_pin(self, card):
        c, transport = card
        c.set_pin("1234")
        assert transport.apdus[-1].to_hex() == "80040001021234"

    def test_set_flags(self, card):
        c, transport = card
        c.set_flags(use_random=True)
        assert transport.apdus[-1].to_hex() == "80040003020001"

    def test_set_ec_key(self, card):
        c, transport = card
        scalar = b"\x01" * 32
        c.set_ec_private_key(scalar)
        hex_str = transport.apdus[-1].to_hex()
        assert hex_str.startswith("8004000B20")

    def test_set_ec_key_wrong_size(self, card):
        c, _ = card
        with pytest.raises(ValueError, match="32 bytes"):
            c.set_ec_private_key(b"\x01" * 31)


class TestPersonalizePse:
    def test_pse_apdu_sequence(self, card):
        c, transport = card
        personalize_pse(c, contact_aid="A0000009510001", label="COLOSSUS")

        hexes = [a.to_hex() for a in transport.apdus]

        # SELECT PSE
        assert hexes[0] == "00A404000E315041592E5359532E4444463031"
        # FACTORY_RESET
        assert hexes[1] == "8005000000"
        # Should contain directory entry with the contact AID
        dir_apdus = [h for h in hexes if "A0000009510001" in h and h.startswith("8001006116")]
        assert len(dir_apdus) == 1


class TestPersonalizePpse:
    def test_ppse_apdu_sequence(self, card):
        c, transport = card
        personalize_ppse(c, contactless_aid="A0000009511010", label="COLOSSUS")

        hexes = [a.to_hex() for a in transport.apdus]

        # SELECT PPSE
        assert hexes[0] == "00A404000E325041592E5359532E4444463031"
        # FACTORY_RESET
        assert hexes[1] == "8005000000"
        # PPSE perso was migrated to the proprietary CPS STORE DATA path
        # (DGI D001) in commit 243d516 — PPSE's own STORE DATA handler only
        # accepts D001 and D002. The directory entry now rides in a STORE
        # DATA body (80 E2 00 00 LC D0 01 <len> <contactless-AID-bytes ...>).
        dir_apdus = [
            h for h in hexes
            if "A0000009511010" in h and h.startswith("80E20000") and "D001" in h
        ]
        assert len(dir_apdus) == 1


class TestPersonalizePaymentApp:
    def test_produces_correct_apdu_count(self, card, profile, certs):
        c, transport = card
        personalize_payment_app(
            c, aid="A0000009510001", profile=profile,
            pan="6690750012345678", expiry_yymmdd="271231", certs=certs,
        )
        # Should have: SELECT + RESET + settings(3) + keys(2-3) + certs(7)
        #   + templates(5) + records(8) + ATC + identity(9) + AFL + CVM
        #   + profile tags(~17) = ~56 APDUs
        assert len(transport.apdus) > 50

    def test_starts_with_select_and_reset(self, card, profile, certs):
        c, transport = card
        personalize_payment_app(
            c, aid="A0000009510001", profile=profile,
            pan="6690750012345678", expiry_yymmdd="271231", certs=certs,
        )
        hexes = [a.to_hex() for a in transport.apdus]
        assert hexes[0] == "00A4040007A0000009510001"
        assert hexes[1] == "8005000000"

    def test_key_apdus_match_shell_script(self, card, profile, certs):
        """Verify specific APDUs match the shell script format."""
        c, transport = card
        personalize_payment_app(
            c, aid="A0000009510001", profile=profile,
            pan="6690750012345678", expiry_yymmdd="271231", certs=certs,
        )
        hexes = [a.to_hex() for a in transport.apdus]

        # Flags
        assert "80040003020001" in hexes
        # PIN
        assert "80040001021234" in hexes
        # GPO template
        assert "800200010600829F6C0094" in hexes
        # DDA template (corrected LC=04)
        assert "80020002049F4C9F4B" in hexes
        # GenAC template
        assert "800200030A9F279F369F269F4B9F10" in hexes
        # AIP
        assert "80010082023C01" in hexes
        # AFL
        assert "800100940C080202001001020218010500" in hexes
        # DDOL
        assert "80019F490C9F02069F37049F1C089F160F" in hexes
        # CDOL1
        assert "8001008C0C9F02069F37049F1C089F160F" in hexes
        # CDOL2
        assert "8001008D0E8A029F02069F37049F1C089F160F" in hexes
        # CVM List
        assert "8001008E0A00000000000000001F00" in hexes
        # IAC-Default
        assert "80019F0D05FC688C9800" in hexes
        # IAC-Online
        assert "80019F0F05FC68FC9800" in hexes
        # CTQ
        assert "80019F6C028000" in hexes

    def test_contact_and_contactless_same_structure(self, card, profile, certs):
        """Both AIDs should produce the same APDU structure (different AID only)."""
        t1 = DryRunTransport(verbose=False)
        c1 = Card(t1, use_store_data=False)
        personalize_payment_app(
            c1, aid="A0000009510001", profile=profile,
            pan="6690750012345678", expiry_yymmdd="271231", certs=certs,
        )

        t2 = DryRunTransport(verbose=False)
        c2 = Card(t2, use_store_data=False)
        personalize_payment_app(
            c2, aid="A0000009511010", profile=profile,
            pan="6690750012345678", expiry_yymmdd="271231", certs=certs,
        )

        # Same number of APDUs
        assert len(t1.apdus) == len(t2.apdus)

        # Only SELECT and DF Name APDUs should differ
        for a1, a2 in zip(t1.apdus, t2.apdus):
            h1, h2 = a1.to_hex(), a2.to_hex()
            if "A0000009510001" in h1 or "A0000009511010" in h1:
                continue  # AID-specific, expected to differ
            assert h1 == h2, f"APDU mismatch:\n  {h1}\n  {h2}"
