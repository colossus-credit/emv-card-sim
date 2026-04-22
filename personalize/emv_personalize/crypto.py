"""EMV certificate hierarchy generation.

Implements the RSA-based CA → Issuer → ICC certificate chain used in
EMV contact transactions, plus ECDSA P-256 key generation.

Certificate format is EMV-specific (6A header, BC trailer, SHA-1 hash)
— NOT x.509.
"""

from __future__ import annotations

import hashlib
import logging
import os
from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric import rsa, ec, utils, padding
from cryptography.hazmat.primitives import serialization

log = logging.getLogger(__name__)

# Default key sizes (bits)
DEFAULT_KEY_SIZE = 1984  # 248 bytes — fits in single APDU, matches terminal CAPK storage

# EMV certificate overhead
ISSUER_CERT_OVERHEAD = 36  # Header(1)+Format(1)+IssuerID(4)+Expiry(2)+Serial(3)+HashAlgo(1)+PKAlgo(1)+PKLen(1)+PKExpLen(1)+Hash(20)+Trailer(1)
ICC_CERT_OVERHEAD = 42     # Header(1)+Format(1)+PAN(10)+Expiry(2)+Serial(3)+HashAlgo(1)+PKAlgo(1)+PKLen(1)+PKExpLen(1)+Hash(20)+Trailer(1)


def _generate_rsa_key(key_size: int = DEFAULT_KEY_SIZE, exponent: int = 3) -> rsa.RSAPrivateKey:
    """Generate an RSA private key with the given size and public exponent."""
    return rsa.generate_private_key(public_exponent=exponent, key_size=key_size)


def _get_modulus_bytes(key: rsa.RSAPrivateKey) -> bytes:
    """Extract the RSA modulus as big-endian bytes."""
    numbers = key.public_key().public_numbers()
    mod_size = key.key_size // 8
    return numbers.n.to_bytes(mod_size, "big")


def _get_private_exponent_bytes(key: rsa.RSAPrivateKey) -> bytes:
    """Extract the RSA private exponent as big-endian bytes, padded to modulus size."""
    numbers = key.private_numbers()
    mod_size = key.key_size // 8
    return numbers.d.to_bytes(mod_size, "big")


def _raw_rsa_sign(key: rsa.RSAPrivateKey, data: bytes) -> bytes:
    """Raw RSA signature (no padding scheme) — textbook RSA for EMV certs.

    EMV certificates use raw modular exponentiation: signature = data^d mod n
    """
    # Use RSA with no padding (raw)
    return key.sign(data, padding.PKCS1v15())
    # NOTE: EMV uses raw RSA (no padding), but the `cryptography` library doesn't
    # expose raw RSA directly. We work around this by doing the math ourselves.


def _raw_rsa_private(key: rsa.RSAPrivateKey, plaintext: bytes) -> bytes:
    """Perform raw RSA private key operation: result = plaintext^d mod n.

    This is the EMV "signing" operation — no PKCS#1 padding.
    """
    numbers = key.private_numbers()
    n = key.public_key().public_numbers().n
    d = numbers.d
    mod_size = key.key_size // 8

    # Convert plaintext to integer
    m = int.from_bytes(plaintext, "big")
    if m >= n:
        raise ValueError(f"Plaintext ({m}) must be less than modulus ({n})")

    # Raw RSA: result = m^d mod n
    result = pow(m, d, n)
    return result.to_bytes(mod_size, "big")


def _sha1(data: bytes) -> bytes:
    """Compute SHA-1 hash (20 bytes). Used in EMV certificate construction."""
    return hashlib.sha1(data).digest()


@dataclass
class RsaKeyMaterial:
    """Container for RSA key components needed for personalization."""
    private_key: rsa.RSAPrivateKey
    modulus: bytes       # Public modulus (big-endian)
    exponent: bytes      # Public exponent (typically 0x03)
    private_exp: bytes   # Private exponent (big-endian, padded to modulus size)
    key_size: int        # Key size in bits

    @classmethod
    def generate(cls, key_size: int = DEFAULT_KEY_SIZE) -> RsaKeyMaterial:
        key = _generate_rsa_key(key_size)
        return cls(
            private_key=key,
            modulus=_get_modulus_bytes(key),
            exponent=b"\x03",
            private_exp=_get_private_exponent_bytes(key),
            key_size=key_size,
        )

    @classmethod
    def from_pem(cls, pem_path: str) -> RsaKeyMaterial:
        """Load from a PEM private key file."""
        with open(pem_path, "rb") as f:
            key = serialization.load_pem_private_key(f.read(), password=None)
        if not isinstance(key, rsa.RSAPrivateKey):
            raise ValueError(f"Expected RSA key, got {type(key).__name__}")
        return cls(
            private_key=key,
            modulus=_get_modulus_bytes(key),
            exponent=key.public_key().public_numbers().e.to_bytes(
                (key.public_key().public_numbers().e.bit_length() + 7) // 8, "big"
            ),
            private_exp=_get_private_exponent_bytes(key),
            key_size=key.key_size,
        )

    def save_pem(self, path: str) -> None:
        pem = self.private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
        with open(path, "wb") as f:
            f.write(pem)

    def save_modulus_bin(self, path: str) -> None:
        with open(path, "wb") as f:
            f.write(self.modulus)

    def save_exponent_bin(self, path: str) -> None:
        with open(path, "wb") as f:
            f.write(self.exponent)


@dataclass
class EcKeyMaterial:
    """Container for EC P-256 key components."""
    private_key: ec.EllipticCurvePrivateKey
    private_scalar: bytes  # 32-byte raw private key scalar

    @classmethod
    def generate(cls) -> EcKeyMaterial:
        key = ec.generate_private_key(ec.SECP256R1())
        scalar = key.private_numbers().private_value.to_bytes(32, "big")
        return cls(private_key=key, private_scalar=scalar)

    @classmethod
    def from_pem(cls, pem_path: str) -> EcKeyMaterial:
        with open(pem_path, "rb") as f:
            key = serialization.load_pem_private_key(f.read(), password=None)
        if not isinstance(key, ec.EllipticCurvePrivateKey):
            raise ValueError(f"Expected EC key, got {type(key).__name__}")
        scalar = key.private_numbers().private_value.to_bytes(32, "big")
        return cls(private_key=key, private_scalar=scalar)

    @classmethod
    def from_bin(cls, bin_path: str) -> EcKeyMaterial:
        """Load from a raw 32-byte private scalar binary file."""
        with open(bin_path, "rb") as f:
            scalar = f.read()
        if len(scalar) != 32:
            raise ValueError(f"EC private scalar must be 32 bytes, got {len(scalar)}")
        private_value = int.from_bytes(scalar, "big")
        private_key = ec.derive_private_key(private_value, ec.SECP256R1())
        return cls(private_key=private_key, private_scalar=scalar)

    def save_pem(self, path: str) -> None:
        pem = self.private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
        with open(path, "wb") as f:
            f.write(pem)

    def save_scalar_bin(self, path: str) -> None:
        with open(path, "wb") as f:
            f.write(self.private_scalar)


@dataclass
class EmvCertificate:
    """An EMV certificate (signed data block)."""
    certificate: bytes   # Raw signed certificate (modulus-sized)
    remainder: bytes     # Public key remainder (if key > cert space)


def build_issuer_certificate(
    capk: RsaKeyMaterial,
    issuer: RsaKeyMaterial,
    issuer_id: str = "66907500",
    expiry_mmyy: str = "1227",
    serial: str = "000001",
) -> EmvCertificate:
    """Build and sign an Issuer Public Key Certificate.

    EMV Book 2, Table 5: Issuer PK Certificate format.
    Signed by the CA (CAPK) private key.
    """
    capk_mod_len = len(capk.modulus)  # = certificate size
    pk_in_cert_space = capk_mod_len - ISSUER_CERT_OVERHEAD

    issuer_mod = issuer.modulus
    issuer_mod_len = len(issuer_mod)

    # Build certificate content
    fmt = b"\x02"  # Format: Issuer PK Certificate
    issuer_id_bytes = bytes.fromhex(issuer_id)
    expiry_bytes = bytes.fromhex(expiry_mmyy)
    serial_bytes = bytes.fromhex(serial)
    hash_algo = b"\x01"  # SHA-1
    pk_algo = b"\x01"    # RSA
    pk_len = bytes([issuer_mod_len])
    pk_exp_len = b"\x01"

    # Split issuer modulus into cert portion and remainder
    if issuer_mod_len > pk_in_cert_space:
        pk_in_cert = issuer_mod[:pk_in_cert_space]
        remainder = issuer_mod[pk_in_cert_space:]
        padding_bytes = b""
    else:
        pk_in_cert = issuer_mod
        remainder = b""
        padding_bytes = b"\xBB" * (pk_in_cert_space - issuer_mod_len)

    # Data that goes inside the certificate (between header and hash)
    data_in_cert = (
        fmt + issuer_id_bytes + expiry_bytes + serial_bytes +
        hash_algo + pk_algo + pk_len + pk_exp_len +
        pk_in_cert + padding_bytes
    )

    # Data to hash: cert_data + remainder + exponent
    data_to_hash = data_in_cert + remainder + issuer.exponent
    cert_hash = _sha1(data_to_hash)

    # Build sign block: 6A || data_in_cert || hash || BC
    sign_block = b"\x6A" + data_in_cert + cert_hash + b"\xBC"

    assert len(sign_block) == capk_mod_len, \
        f"Sign block size {len(sign_block)} != CAPK modulus {capk_mod_len}"

    # Sign with CAPK private key (raw RSA)
    certificate = _raw_rsa_private(capk.private_key, sign_block)

    log.info("Issuer cert: %d bytes in cert, %d bytes remainder",
             min(issuer_mod_len, pk_in_cert_space), len(remainder))

    return EmvCertificate(certificate=certificate, remainder=remainder)


def build_icc_certificate(
    issuer: RsaKeyMaterial,
    icc: RsaKeyMaterial,
    pan: str,
    expiry_yymmdd: str = "271231",
    serial: str = "000001",
    static_data_auth: bytes = b"",
) -> EmvCertificate:
    """Build and sign an ICC Public Key Certificate.

    EMV Book 2, Table 8: ICC PK Certificate format.
    Signed by the Issuer private key.
    """
    issuer_mod_len = len(issuer.modulus)  # = certificate size
    pk_in_cert_space = issuer_mod_len - ICC_CERT_OVERHEAD

    icc_mod = icc.modulus
    icc_mod_len = len(icc_mod)

    # Build certificate content
    fmt = b"\x04"  # Format: ICC PK Certificate

    # PAN in certificate: BCD-encoded, F-padded to 10 bytes
    pan_bcd = pan
    while len(pan_bcd) < 20:
        pan_bcd += "F"
    pan_bytes = bytes.fromhex(pan_bcd[:20])

    # Expiry: convert YYMMDD → MMYY
    cert_expiry = expiry_yymmdd[2:4] + expiry_yymmdd[0:2]
    expiry_bytes = bytes.fromhex(cert_expiry)

    serial_bytes = bytes.fromhex(serial)
    hash_algo = b"\x01"  # SHA-1
    pk_algo = b"\x01"    # RSA
    pk_len = bytes([icc_mod_len % 256])
    pk_exp_len = b"\x01"

    # Split ICC modulus
    if icc_mod_len > pk_in_cert_space:
        pk_in_cert = icc_mod[:pk_in_cert_space]
        remainder = icc_mod[pk_in_cert_space:]
        padding_bytes = b""
    else:
        pk_in_cert = icc_mod
        remainder = b""
        padding_bytes = b"\xBB" * (pk_in_cert_space - icc_mod_len)

    # Data inside certificate
    data_in_cert = (
        fmt + pan_bytes + expiry_bytes + serial_bytes +
        hash_algo + pk_algo + pk_len + pk_exp_len +
        pk_in_cert + padding_bytes
    )

    # Data to hash: cert_data + remainder + exponent + static_data_auth
    data_to_hash = data_in_cert + remainder + icc.exponent + static_data_auth
    cert_hash = _sha1(data_to_hash)

    # Build sign block: 6A || data_in_cert || hash || BC
    sign_block = b"\x6A" + data_in_cert + cert_hash + b"\xBC"

    assert len(sign_block) == issuer_mod_len, \
        f"Sign block size {len(sign_block)} != Issuer modulus {issuer_mod_len}"

    # Sign with Issuer private key (raw RSA)
    certificate = _raw_rsa_private(issuer.private_key, sign_block)

    log.info("ICC cert: %d bytes in cert, %d bytes remainder",
             min(icc_mod_len, pk_in_cert_space), len(remainder))

    return EmvCertificate(certificate=certificate, remainder=remainder)


def build_static_data_auth(
    oda_record_tags: list[list[tuple[int, bytes]]],
    aip: bytes = b"\x39\x80",
) -> bytes:
    """Build the Static Data to be Authenticated for ICC certificate hash.

    Per EMV Book 3 Section 10.3:
    - Concatenation of record content (inside tag 70, excluding tag 70 wrapper)
      from records marked as ODA in the AFL
    - Followed by the VALUE of tags listed in SDA Tag List (9F4A), typically AIP

    Per Book 3: "For files with SFI in the range 1 to 10, the record tag ('70')
    and the record length are excluded. All other data in the data field of the
    response to the READ RECORD command is included."

    Args:
        oda_record_tags: List of records, each record is a list of (tag_id, value) tuples.
                         These must be in the same order as the record template.
        aip: AIP value bytes (from SDA Tag List tag 9F4A which specifies tag 82)
    """
    result = bytearray()

    for record in oda_record_tags:
        for tag_id, value in record:
            # Serialize as TLV (same as EmvTag.copyToArray)
            if tag_id <= 0xFF:
                # Single-byte tag
                result.append(tag_id & 0xFF)
            else:
                # Two-byte tag
                result.append((tag_id >> 8) & 0xFF)
                result.append(tag_id & 0xFF)
            # Length encoding
            val_len = len(value)
            if val_len >= 128:
                result.append(0x81)
                result.append(val_len & 0xFF)
            else:
                result.append(val_len)
            result += value

    # Append AIP value (from SDA Tag List 9F4A which says tag 82)
    result += aip

    return bytes(result)


@dataclass
class CertificateHierarchy:
    """Complete CAPK → Issuer → ICC certificate chain."""
    capk: RsaKeyMaterial
    issuer: RsaKeyMaterial
    issuer_cert: EmvCertificate
    icc: RsaKeyMaterial
    icc_cert: EmvCertificate
    ec_key: EcKeyMaterial | None = None
    capk_index: str = "92"

    @classmethod
    def generate(
        cls,
        pan: str = "6690750012345678",
        expiry: str = "271231",
        key_size: int = DEFAULT_KEY_SIZE,
        capk_index: str = "92",
    ) -> CertificateHierarchy:
        """Generate a complete certificate hierarchy from scratch."""
        log.info("Generating CAPK RSA-%d...", key_size)
        capk = RsaKeyMaterial.generate(key_size)

        log.info("Generating Issuer RSA-%d...", key_size)
        issuer = RsaKeyMaterial.generate(key_size)

        log.info("Building Issuer certificate...")
        issuer_cert = build_issuer_certificate(capk, issuer)

        log.info("Generating ICC RSA-%d...", key_size)
        icc = RsaKeyMaterial.generate(key_size)

        log.info("Generating ICC EC P-256...")
        ec_key = EcKeyMaterial.generate()

        # Build static data auth for ICC cert hash
        # ODA count = 1: only SFI2/R1 is in the SDA (matches real Mastercard)
        oda_records = [
            [  # SFI2/R1: must match record template order: 8F, 92, 9F32, 9F47
                (0x8F, bytes.fromhex(capk_index)),
                (0x92, issuer_cert.remainder),
                (0x9F32, b"\x03"),
                (0x9F47, b"\x03"),
            ],
        ]
        sda = build_static_data_auth(oda_records, aip=b"\x19\x80")

        log.info("Building ICC certificate...")
        icc_cert = build_icc_certificate(issuer, icc, pan, expiry,
                                         static_data_auth=sda)

        return cls(
            capk=capk, issuer=issuer, issuer_cert=issuer_cert,
            icc=icc, icc_cert=icc_cert, ec_key=ec_key,
            capk_index=capk_index,
        )

    @classmethod
    def from_keys_dir(
        cls,
        keys_dir: str,
        pan: str = "6690750012345678",
        expiry: str = "271231",
        capk_index: str = "92",
    ) -> CertificateHierarchy:
        """Load existing keys from a keys/ directory structure and regenerate ICC cert.

        Expected layout:
          keys/capk/capk_private.pem, capk_modulus.bin
          keys/issuer/issuer_private.pem, issuer_certificate.bin, issuer_remainder.bin
          keys/icc/icc_private.pem, icc_modulus.bin, icc_ec_private.bin (optional)
        """
        import os

        capk = RsaKeyMaterial.from_pem(os.path.join(keys_dir, "capk", "capk_private.pem"))
        issuer = RsaKeyMaterial.from_pem(os.path.join(keys_dir, "issuer", "issuer_private.pem"))

        # Load existing issuer certificate
        with open(os.path.join(keys_dir, "issuer", "issuer_certificate.bin"), "rb") as f:
            issuer_cert_data = f.read()
        with open(os.path.join(keys_dir, "issuer", "issuer_remainder.bin"), "rb") as f:
            issuer_rem_data = f.read()
        issuer_cert = EmvCertificate(certificate=issuer_cert_data, remainder=issuer_rem_data)

        icc = RsaKeyMaterial.from_pem(os.path.join(keys_dir, "icc", "icc_private.pem"))

        # Load EC key if available
        ec_key = None
        ec_bin_path = os.path.join(keys_dir, "icc", "icc_ec_private.bin")
        ec_pem_path = os.path.join(keys_dir, "icc", "icc_ec_private.pem")
        if os.path.exists(ec_bin_path):
            ec_key = EcKeyMaterial.from_bin(ec_bin_path)
        elif os.path.exists(ec_pem_path):
            ec_key = EcKeyMaterial.from_pem(ec_pem_path)

        # Regenerate ICC certificate (it contains PAN and must match)
        # ODA records must match what the card returns for SFI2/R1 and R2
        oda_records = [
            [  # SFI2/R1: must match record template order: 8F, 92, 9F32, 9F47
                (0x8F, bytes.fromhex(capk_index)),
                (0x92, issuer_cert.remainder),
                (0x9F32, issuer.exponent),
                (0x9F47, icc.exponent),
            ],
        ]
        sda = build_static_data_auth(oda_records, aip=b"\x19\x80")
        icc_cert = build_icc_certificate(issuer, icc, pan, expiry,
                                         static_data_auth=sda)

        return cls(
            capk=capk, issuer=issuer, issuer_cert=issuer_cert,
            icc=icc, icc_cert=icc_cert, ec_key=ec_key,
            capk_index=capk_index,
        )

    def save_to_dir(self, keys_dir: str) -> None:
        """Save all keys and certificates to a directory structure."""
        for subdir in ("capk", "issuer", "icc"):
            os.makedirs(os.path.join(keys_dir, subdir), exist_ok=True)

        # CAPK
        self.capk.save_pem(os.path.join(keys_dir, "capk", "capk_private.pem"))
        self.capk.save_modulus_bin(os.path.join(keys_dir, "capk", "capk_modulus.bin"))
        self.capk.save_exponent_bin(os.path.join(keys_dir, "capk", "capk_exponent.bin"))

        # Issuer
        self.issuer.save_pem(os.path.join(keys_dir, "issuer", "issuer_private.pem"))
        self.issuer.save_modulus_bin(os.path.join(keys_dir, "issuer", "issuer_modulus.bin"))
        self.issuer.save_exponent_bin(os.path.join(keys_dir, "issuer", "issuer_exponent.bin"))
        with open(os.path.join(keys_dir, "issuer", "issuer_certificate.bin"), "wb") as f:
            f.write(self.issuer_cert.certificate)
        with open(os.path.join(keys_dir, "issuer", "issuer_remainder.bin"), "wb") as f:
            f.write(self.issuer_cert.remainder)

        # ICC
        self.icc.save_pem(os.path.join(keys_dir, "icc", "icc_private.pem"))
        self.icc.save_modulus_bin(os.path.join(keys_dir, "icc", "icc_modulus.bin"))
        self.icc.save_exponent_bin(os.path.join(keys_dir, "icc", "icc_exponent.bin"))
        with open(os.path.join(keys_dir, "icc", "icc_certificate.bin"), "wb") as f:
            f.write(self.icc_cert.certificate)
        with open(os.path.join(keys_dir, "icc", "icc_remainder.bin"), "wb") as f:
            f.write(self.icc_cert.remainder)

        # EC key
        if self.ec_key:
            self.ec_key.save_pem(os.path.join(keys_dir, "icc", "icc_ec_private.pem"))
            self.ec_key.save_scalar_bin(os.path.join(keys_dir, "icc", "icc_ec_private.bin"))
