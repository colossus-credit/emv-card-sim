"""Tests for Luhn algorithm utilities."""

from emv_personalize.luhn import luhn_validate, luhn_checkdigit, generate_pan


class TestLuhnValidate:
    def test_valid_pans(self):
        assert luhn_validate("4111111111111111")
        assert luhn_validate("5500000000000004")

    def test_invalid_pans(self):
        assert not luhn_validate("1234567890123456")
        assert not luhn_validate("6690750012345678")

    def test_single_digit(self):
        assert luhn_validate("0")


class TestLuhnCheckdigit:
    def test_known_values(self):
        assert luhn_checkdigit("411111111111111") == 1
        assert luhn_checkdigit("550000000000000") == 4


class TestGeneratePan:
    def test_default_length(self):
        pan = generate_pan("66907500")
        assert len(pan) == 16
        assert pan.startswith("66907500")
        assert luhn_validate(pan)

    def test_custom_length(self):
        pan = generate_pan("4111", 19)
        assert len(pan) == 19
        assert pan.startswith("4111")
        assert luhn_validate(pan)

    def test_generates_different_pans(self):
        pans = {generate_pan("66907500") for _ in range(10)}
        assert len(pans) > 1  # Extremely unlikely to generate all identical
