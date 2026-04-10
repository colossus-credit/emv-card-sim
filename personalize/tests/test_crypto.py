"""Tests for EMV certificate hierarchy generation."""

import os
import tempfile
import pytest
from emv_personalize.crypto import (
    RsaKeyMaterial, EcKeyMaterial, EmvCertificate,
    build_issuer_certificate, build_icc_certificate,
    build_static_data_auth, CertificateHierarchy,
    _raw_rsa_private, _sha1,
)


class TestRsaKeyMaterial:
    def test_generate_default_size(self):
        key = RsaKeyMaterial.generate(1984)
        assert key.key_size == 1984
        assert len(key.modulus) == 248  # 1984 / 8
        assert key.exponent == b"\x03"
        assert len(key.private_exp) == 248

    def test_generate_1024(self):
        key = RsaKeyMaterial.generate(1024)
        assert key.key_size == 1024
        assert len(key.modulus) == 128

    def test_save_and_load_pem(self):
        key = RsaKeyMaterial.generate(1024)
        with tempfile.NamedTemporaryFile(suffix=".pem", delete=False) as f:
            path = f.name
        try:
            key.save_pem(path)
            loaded = RsaKeyMaterial.from_pem(path)
            assert loaded.modulus == key.modulus
            assert loaded.private_exp == key.private_exp
        finally:
            os.unlink(path)

    def test_save_modulus_bin(self):
        key = RsaKeyMaterial.generate(1024)
        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
            path = f.name
        try:
            key.save_modulus_bin(path)
            with open(path, "rb") as f:
                data = f.read()
            assert data == key.modulus
        finally:
            os.unlink(path)


class TestEcKeyMaterial:
    def test_generate(self):
        key = EcKeyMaterial.generate()
        assert len(key.private_scalar) == 32

    def test_save_and_load_pem(self):
        key = EcKeyMaterial.generate()
        with tempfile.NamedTemporaryFile(suffix=".pem", delete=False) as f:
            path = f.name
        try:
            key.save_pem(path)
            loaded = EcKeyMaterial.from_pem(path)
            assert loaded.private_scalar == key.private_scalar
        finally:
            os.unlink(path)

    def test_save_and_load_bin(self):
        key = EcKeyMaterial.generate()
        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
            path = f.name
        try:
            key.save_scalar_bin(path)
            loaded = EcKeyMaterial.from_bin(path)
            assert loaded.private_scalar == key.private_scalar
        finally:
            os.unlink(path)


class TestRawRsa:
    def test_sign_and_recover(self):
        """Raw RSA: encrypt with private key, decrypt with public key."""
        key = RsaKeyMaterial.generate(1024)
        mod_size = len(key.modulus)
        # Create a valid message (< modulus)
        message = b"\x6A" + b"\x00" * (mod_size - 2) + b"\xBC"
        signed = _raw_rsa_private(key.private_key, message)
        assert len(signed) == mod_size

        # Verify by recovering with public key (m^e mod n)
        n = key.private_key.public_key().public_numbers().n
        e = key.private_key.public_key().public_numbers().e
        recovered = pow(int.from_bytes(signed, "big"), e, n)
        recovered_bytes = recovered.to_bytes(mod_size, "big")
        assert recovered_bytes == message


class TestBuildIssuerCertificate:
    def test_certificate_size_matches_capk_modulus(self):
        capk = RsaKeyMaterial.generate(1984)
        issuer = RsaKeyMaterial.generate(1984)
        cert = build_issuer_certificate(capk, issuer)
        assert len(cert.certificate) == len(capk.modulus)  # 248

    def test_remainder_size_1984(self):
        """For 1984-bit keys: remainder = 248 - (248 - 36) = 36 bytes."""
        capk = RsaKeyMaterial.generate(1984)
        issuer = RsaKeyMaterial.generate(1984)
        cert = build_issuer_certificate(capk, issuer)
        assert len(cert.remainder) == 36

    def test_certificate_recoverable(self):
        """The certificate should be recoverable with CAPK public key."""
        capk = RsaKeyMaterial.generate(1024)
        issuer = RsaKeyMaterial.generate(1024)
        cert = build_issuer_certificate(capk, issuer)

        # Recover: cert^e mod n
        n = capk.private_key.public_key().public_numbers().n
        e = capk.private_key.public_key().public_numbers().e
        recovered = pow(int.from_bytes(cert.certificate, "big"), e, n)
        recovered_bytes = recovered.to_bytes(len(capk.modulus), "big")

        # Should start with 6A and end with BC
        assert recovered_bytes[0] == 0x6A
        assert recovered_bytes[-1] == 0xBC
        # Second byte should be 02 (Issuer PK Cert format)
        assert recovered_bytes[1] == 0x02


class TestBuildIccCertificate:
    def test_certificate_size_matches_issuer_modulus(self):
        issuer = RsaKeyMaterial.generate(1984)
        icc = RsaKeyMaterial.generate(1984)
        cert = build_icc_certificate(issuer, icc, "6690750012345678")
        assert len(cert.certificate) == len(issuer.modulus)

    def test_remainder_size_1984(self):
        """For 1984-bit keys: remainder = 248 - (248 - 42) = 42 bytes."""
        issuer = RsaKeyMaterial.generate(1984)
        icc = RsaKeyMaterial.generate(1984)
        cert = build_icc_certificate(issuer, icc, "6690750012345678")
        assert len(cert.remainder) == 42

    def test_certificate_recoverable(self):
        """ICC cert recoverable with Issuer public key, format = 0x04."""
        issuer = RsaKeyMaterial.generate(1024)
        icc = RsaKeyMaterial.generate(1024)
        cert = build_icc_certificate(issuer, icc, "6690750012345678")

        n = issuer.private_key.public_key().public_numbers().n
        e = issuer.private_key.public_key().public_numbers().e
        recovered = pow(int.from_bytes(cert.certificate, "big"), e, n)
        recovered_bytes = recovered.to_bytes(len(issuer.modulus), "big")

        assert recovered_bytes[0] == 0x6A
        assert recovered_bytes[-1] == 0xBC
        assert recovered_bytes[1] == 0x04  # ICC PK Cert format

    def test_pan_embedded_in_cert(self):
        """PAN should be BCD-encoded in the certificate."""
        issuer = RsaKeyMaterial.generate(1024)
        icc = RsaKeyMaterial.generate(1024)
        pan = "6690750012345678"
        cert = build_icc_certificate(issuer, icc, pan)

        n = issuer.private_key.public_key().public_numbers().n
        e = issuer.private_key.public_key().public_numbers().e
        recovered = pow(int.from_bytes(cert.certificate, "big"), e, n)
        recovered_bytes = recovered.to_bytes(len(issuer.modulus), "big")

        # PAN at bytes 2-11 (10 bytes), F-padded
        pan_in_cert = recovered_bytes[2:12]
        assert pan_in_cert == bytes.fromhex("6690750012345678FFFF")


class TestCertificateHierarchy:
    def test_generate_full_chain(self):
        hierarchy = CertificateHierarchy.generate(
            pan="6690750012345678", key_size=1024, capk_index="92",
        )
        assert hierarchy.capk.key_size == 1024
        assert hierarchy.issuer.key_size == 1024
        assert hierarchy.icc.key_size == 1024
        assert hierarchy.ec_key is not None
        assert len(hierarchy.ec_key.private_scalar) == 32
        assert hierarchy.capk_index == "92"

    def test_save_and_reload(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            keys_dir = os.path.join(tmpdir, "keys")
            hierarchy = CertificateHierarchy.generate(
                pan="6690750012345678", key_size=1024, capk_index="92",
            )
            hierarchy.save_to_dir(keys_dir)

            # Reload (regenerates ICC cert for same PAN)
            loaded = CertificateHierarchy.from_keys_dir(
                keys_dir, pan="6690750012345678", capk_index="92",
            )
            assert loaded.capk.modulus == hierarchy.capk.modulus
            assert loaded.issuer.modulus == hierarchy.issuer.modulus
            assert loaded.icc.modulus == hierarchy.icc.modulus
            # ICC cert is regenerated, so certificates may differ
            # but the key material should match

    def test_certificate_chain_verifiable(self):
        """Full chain: CAPK signs Issuer cert, Issuer signs ICC cert."""
        h = CertificateHierarchy.generate(key_size=1024)

        # Verify Issuer cert with CAPK
        n = h.capk.private_key.public_key().public_numbers().n
        e = h.capk.private_key.public_key().public_numbers().e
        recovered = pow(int.from_bytes(h.issuer_cert.certificate, "big"), e, n)
        recovered_bytes = recovered.to_bytes(len(h.capk.modulus), "big")
        assert recovered_bytes[0] == 0x6A
        assert recovered_bytes[-1] == 0xBC

        # Verify ICC cert with Issuer
        n = h.issuer.private_key.public_key().public_numbers().n
        e = h.issuer.private_key.public_key().public_numbers().e
        recovered = pow(int.from_bytes(h.icc_cert.certificate, "big"), e, n)
        recovered_bytes = recovered.to_bytes(len(h.issuer.modulus), "big")
        assert recovered_bytes[0] == 0x6A
        assert recovered_bytes[-1] == 0xBC
