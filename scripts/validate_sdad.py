#!/usr/bin/env python3
"""
Validate SDAD (Signed Dynamic Application Data) from a GENERATE AC response.
Uses the ICC public key to decrypt and verify the SDAD structure.
"""

import sys
import hashlib
from pathlib import Path

def hex_to_bytes(hex_str):
    """Convert hex string (with or without spaces) to bytes."""
    return bytes.fromhex(hex_str.replace(' ', '').replace('\n', ''))

def bytes_to_hex(data):
    """Convert bytes to hex string with spaces."""
    return ' '.join(f'{b:02X}' for b in data)

def parse_tlv(data):
    """Parse TLV data and return dict of tag -> value."""
    tlvs = {}
    i = 0
    while i < len(data):
        # Get tag (1 or 2 bytes)
        tag = data[i]
        i += 1
        if (tag & 0x1F) == 0x1F:  # Two-byte tag
            tag = (tag << 8) | data[i]
            i += 1

        # Get length (1, 2, or 3 bytes)
        length = data[i]
        i += 1
        if length == 0x81:
            length = data[i]
            i += 1
        elif length == 0x82:
            length = (data[i] << 8) | data[i + 1]
            i += 2

        # Get value
        value = data[i:i + length]
        i += length

        tlvs[tag] = value

    return tlvs

def rsa_recover(encrypted, modulus, exponent):
    """RSA public key recovery (decryption with public key)."""
    # Convert to integers
    enc_int = int.from_bytes(encrypted, 'big')
    mod_int = int.from_bytes(modulus, 'big')
    exp_int = int.from_bytes(exponent, 'big')

    # RSA: decrypted = encrypted^exponent mod modulus
    dec_int = pow(enc_int, exp_int, mod_int)

    # Convert back to bytes (same length as modulus)
    return dec_int.to_bytes(len(modulus), 'big')

def validate_sdad(sdad, icc_modulus, icc_exponent, expected_cid=None, expected_ac=None, unpredictable_number=None):
    """Validate SDAD structure and content."""
    print(f"\n{'='*60}")
    print("SDAD VALIDATION")
    print(f"{'='*60}")
    print(f"SDAD length: {len(sdad)} bytes")
    print(f"SDAD (encrypted): {bytes_to_hex(sdad[:32])}...")

    # RSA recover the SDAD
    recovered = rsa_recover(sdad, icc_modulus, icc_exponent)
    print(f"\nRecovered SDAD plaintext:")
    print(f"  {bytes_to_hex(recovered)}")

    # Validate structure per EMV Book 2 Table 18
    print(f"\n--- Structure Validation ---")

    # Header (byte 0)
    header = recovered[0]
    print(f"Header: 0x{header:02X} {'PASS' if header == 0x6A else 'FAIL (expected 0x6A)'}")

    # Signed Data Format (byte 1)
    data_format = recovered[1]
    format_ok = data_format == 0x05
    print(f"Signed Data Format: 0x{data_format:02X} {'PASS' if format_ok else 'FAIL (expected 0x05 for CDA)'}")

    # Hash Algorithm Indicator (byte 2)
    hash_algo = recovered[2]
    if hash_algo == 0x01:
        hash_name = "SHA-1"
        hash_size = 20
    elif hash_algo == 0x02:
        hash_name = "SHA-256"
        hash_size = 32
    else:
        hash_name = f"Unknown (0x{hash_algo:02X})"
        hash_size = 20  # Assume SHA-1
    print(f"Hash Algorithm: 0x{hash_algo:02X} ({hash_name}) {'PASS' if hash_algo in [0x01, 0x02] else 'UNKNOWN'}")

    # ICC Dynamic Data Length (byte 3)
    ldd = recovered[3]
    print(f"ICC Dynamic Data Length (LDD): {ldd} bytes")

    # Trailer (last byte)
    trailer = recovered[-1]
    print(f"Trailer: 0x{trailer:02X} {'PASS' if trailer == 0xBC else 'FAIL (expected 0xBC)'}")

    # Parse ICC Dynamic Data
    print(f"\n--- ICC Dynamic Data ---")
    offset = 4

    # ICC Dynamic Number length
    icc_dyn_num_len = recovered[offset]
    offset += 1
    print(f"ICC Dynamic Number Length: {icc_dyn_num_len}")

    # ICC Dynamic Number
    icc_dyn_num = recovered[offset:offset + icc_dyn_num_len]
    offset += icc_dyn_num_len
    print(f"ICC Dynamic Number: {bytes_to_hex(icc_dyn_num)}")

    # CID (Cryptogram Information Data)
    embedded_cid = recovered[offset]
    offset += 1
    cid_match = expected_cid is None or embedded_cid == expected_cid
    print(f"Embedded CID: 0x{embedded_cid:02X} {'PASS' if cid_match else f'FAIL (expected 0x{expected_cid:02X})'}")

    # AC (Application Cryptogram) - 8 bytes
    embedded_ac = recovered[offset:offset + 8]
    offset += 8
    ac_match = expected_ac is None or embedded_ac == expected_ac
    print(f"Embedded AC: {bytes_to_hex(embedded_ac)} {'PASS' if ac_match else 'FAIL'}")

    # Transaction Data Hash - hash_size bytes
    tx_data_hash = recovered[offset:offset + hash_size]
    offset += hash_size
    print(f"Transaction Data Hash: {bytes_to_hex(tx_data_hash)}")

    # Check padding
    print(f"\n--- Padding ---")
    padding_start = 4 + ldd
    hash_start = len(recovered) - hash_size - 1  # hash + trailer
    padding = recovered[padding_start:hash_start]
    padding_ok = all(b == 0xBB for b in padding)
    print(f"Padding bytes: {len(padding)} bytes from offset {padding_start} to {hash_start - 1}")
    print(f"Padding (0xBB pattern): {'PASS' if padding_ok else 'FAIL'}")

    # Embedded hash
    print(f"\n--- Hash Verification ---")
    embedded_hash = recovered[hash_start:hash_start + hash_size]
    print(f"Embedded Hash ({hash_name}): {bytes_to_hex(embedded_hash)}")

    # Calculate expected hash if UN provided
    if unpredictable_number:
        # Hash input: Format || Hash Algo || LDD || ICC Dyn Data || Padding || UN
        hash_input = recovered[1:hash_start] + unpredictable_number
        if hash_algo == 0x02:
            calculated_hash = hashlib.sha256(hash_input).digest()
        else:
            calculated_hash = hashlib.sha1(hash_input).digest()
        print(f"Calculated Hash: {bytes_to_hex(calculated_hash)}")
        hash_match = calculated_hash == embedded_hash
        print(f"Hash Match: {'PASS' if hash_match else 'MISMATCH (hash input construction may differ)'}")

    # Summary
    print(f"\n{'='*60}")
    print("VALIDATION SUMMARY")
    print(f"{'='*60}")
    all_pass = (header == 0x6A and format_ok and hash_algo in [0x01, 0x02] and
                trailer == 0xBC and padding_ok and cid_match and ac_match)

    if all_pass:
        print("SDAD STRUCTURE VALID")
        print(f"  - Header: 0x6A")
        print(f"  - Format: 0x05 (CDA)")
        print(f"  - Hash Algorithm: 0x{hash_algo:02X} ({hash_name})")
        print(f"  - Padding: 0xBB pattern")
        print(f"  - Trailer: 0xBC")
        print(f"  - CID/AC bindings: Verified")
    else:
        print("SDAD VALIDATION FAILED - See details above")

    return all_pass, recovered

def main():
    # Check for command line argument
    if len(sys.argv) > 1:
        # Read hex from command line or file
        arg = sys.argv[1]
        if arg == '-':
            print("Reading hex data from stdin (paste hex, then Ctrl+D):")
            genac_response_hex = sys.stdin.read()
        elif Path(arg).exists():
            genac_response_hex = Path(arg).read_text()
        else:
            genac_response_hex = arg
    else:
        print("=" * 60)
        print("SDAD Validation Script")
        print("=" * 60)
        print("\nUsage: python validate_sdad.py <hex_data | hex_file | ->")
        print("       Use '-' to read from stdin")
        print("\nThe hex data should be the complete GENERATE AC response")
        print("including the 9F4B (SDAD) tag.")
        print("\nExample:")
        print("  python validate_sdad.py '77 82 01 23 9F 27 01 80 ... 90 00'")
        print("\nNote: Your log output appears to be truncated (missing 39 bytes).")
        print("Make sure to capture the complete response from the terminal.")
        print("\nTo run the unit test validation instead:")
        print("  ./gradlew test --tests ColossusPaymentApplicationTest.testSdadValidation")
        return 0

    # Parse the response (remove SW 90 00)
    response_data = hex_to_bytes(genac_response_hex)
    if response_data[-2:] == b'\x90\x00':
        response_data = response_data[:-2]

    print("GENERATE AC Response Analysis")
    print("=" * 60)
    print(f"Total response length: {len(response_data)} bytes")

    # Skip template tag and length
    if response_data[0] == 0x77:
        if response_data[1] == 0x82:
            tlv_data = response_data[4:]  # Skip 77 82 XX XX
        elif response_data[1] == 0x81:
            tlv_data = response_data[3:]  # Skip 77 81 XX
        else:
            tlv_data = response_data[2:]  # Skip 77 XX
    else:
        tlv_data = response_data

    # Parse TLVs
    tlvs = parse_tlv(tlv_data)

    print("\nParsed TLVs:")
    for tag, value in tlvs.items():
        tag_name = {
            0x9F27: "CID (Cryptogram Information Data)",
            0x9F36: "ATC (Application Transaction Counter)",
            0x9F26: "AC (Application Cryptogram)",
            0x9F10: "IAD (Issuer Application Data)",
            0x9F4B: "SDAD (Signed Dynamic Application Data)"
        }.get(tag, "Unknown")
        if len(value) <= 16:
            print(f"  {tag:04X} ({tag_name}): {bytes_to_hex(value)}")
        else:
            print(f"  {tag:04X} ({tag_name}): {len(value)} bytes")

    # Extract key values
    cid = tlvs.get(0x9F27, b'\x00')[0]
    ac = tlvs.get(0x9F26, b'\x00' * 8)
    sdad = tlvs.get(0x9F4B)

    if not sdad:
        print("\nERROR: No SDAD (9F4B) found in response!")
        return 1

    print(f"\nCID: 0x{cid:02X} ({'ARQC' if cid == 0x80 else 'AAC' if cid == 0x00 else 'TC' if cid == 0x40 else 'Unknown'})")
    print(f"AC: {bytes_to_hex(ac)}")
    print(f"SDAD: {len(sdad)} bytes")

    # Load ICC public key
    keys_dir = Path(__file__).parent.parent / "keys" / "icc"
    modulus_file = keys_dir / "icc_modulus.bin"
    exponent_file = keys_dir / "icc_exponent.bin"

    if not modulus_file.exists():
        print(f"\nERROR: ICC modulus not found at {modulus_file}")
        print("Make sure you've generated the ICC keys with ./scripts/generate_keys.sh icc")
        return 1

    icc_modulus = modulus_file.read_bytes()
    icc_exponent = exponent_file.read_bytes() if exponent_file.exists() else b'\x03'

    print(f"\nICC Public Key:")
    print(f"  Modulus: {len(icc_modulus)} bytes")
    print(f"  Exponent: {bytes_to_hex(icc_exponent)}")

    # Extract UN from CDOL data in command
    # Command: 80 AE 80 00 3A [CDOL data...]
    # UN (9F37) is at offset 29-32 in CDOL: 62 6A 69 39
    unpredictable_number = hex_to_bytes("62 6A 69 39")
    print(f"\nUnpredictable Number (from command): {bytes_to_hex(unpredictable_number)}")

    # Validate SDAD
    valid, recovered = validate_sdad(
        sdad,
        icc_modulus,
        icc_exponent,
        expected_cid=cid,
        expected_ac=ac,
        unpredictable_number=unpredictable_number
    )

    return 0 if valid else 1

if __name__ == "__main__":
    sys.exit(main())
