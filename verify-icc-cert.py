#!/usr/bin/env python3
"""
Verify ICC Certificate Chain for Colossus EMV Card

This script verifies:
1. Issuer certificate is signed correctly by CAPK
2. ICC certificate is signed correctly by Issuer
3. Hash values in certificates match computed hashes
"""

import hashlib
import sys
import os

def read_binary_file(path):
    with open(path, 'rb') as f:
        return f.read()

def bytes_to_int(b):
    return int.from_bytes(b, 'big')

def int_to_bytes(n, length):
    return n.to_bytes(length, 'big')

def rsa_recover(ciphertext, exponent, modulus):
    """RSA recovery: plaintext = ciphertext^e mod n"""
    c = bytes_to_int(ciphertext)
    n = bytes_to_int(modulus)
    m = pow(c, exponent, n)
    return int_to_bytes(m, len(modulus))

def verify_issuer_certificate():
    """Verify Issuer certificate signed by CAPK"""
    print("\n" + "="*60)
    print("VERIFYING ISSUER CERTIFICATE")
    print("="*60)

    base_dir = '/Users/dangerousfood/Dev/emv-card-simulator/keys'

    # Read CAPK public key
    capk_modulus = read_binary_file(f'{base_dir}/capk/capk_modulus.bin')
    capk_exponent = read_binary_file(f'{base_dir}/capk/capk_exponent.bin')
    capk_exp = bytes_to_int(capk_exponent)

    print(f"\nCAPK Modulus size: {len(capk_modulus)} bytes ({len(capk_modulus)*8} bits)")
    print(f"CAPK Exponent: {capk_exp}")

    # Read Issuer certificate
    issuer_cert = read_binary_file(f'{base_dir}/issuer/issuer_certificate.bin')
    issuer_remainder = read_binary_file(f'{base_dir}/issuer/issuer_remainder.bin')
    issuer_exponent = read_binary_file(f'{base_dir}/issuer/issuer_exponent.bin')

    print(f"\nIssuer Certificate size: {len(issuer_cert)} bytes")
    print(f"Issuer Remainder size: {len(issuer_remainder)} bytes")
    print(f"Issuer Exponent: {bytes_to_int(issuer_exponent)}")

    # Recover Issuer certificate plaintext
    recovered = rsa_recover(issuer_cert, capk_exp, capk_modulus)

    print(f"\nRecovered Issuer Certificate:")
    print(f"  First byte (header): 0x{recovered[0]:02X} (expect 0x6A)")
    print(f"  Last byte (trailer): 0x{recovered[-1]:02X} (expect 0xBC)")
    print(f"  Format byte: 0x{recovered[1]:02X} (expect 0x02 for Issuer)")

    if recovered[0] != 0x6A or recovered[-1] != 0xBC:
        print("\n*** ISSUER CERTIFICATE FORMAT INVALID ***")
        return None

    print("\n  Certificate structure:")
    # Parse issuer certificate structure:
    # [0]: Header 0x6A
    # [1]: Format 0x02
    # [2-5]: Issuer Identifier (BIN) - 4 bytes
    # [6-7]: Expiry Date MMYY - 2 bytes
    # [8-10]: Serial Number - 3 bytes
    # [11]: Hash Algorithm Indicator
    # [12]: PK Algorithm Indicator
    # [13]: PK Length
    # [14]: PK Exponent Length
    # [15:15+key_space]: Leftmost PK digits
    # [-21:-1]: Hash (20 bytes)
    # [-1]: Trailer 0xBC

    issuer_id = recovered[2:6].hex()
    expiry_mmyy = recovered[6:8].hex()
    serial = recovered[8:11].hex()
    hash_algo = recovered[11]
    pk_algo = recovered[12]
    pk_len = recovered[13] if recovered[13] != 0 else 256
    exp_len = recovered[14]

    print(f"    Issuer ID (BIN): {issuer_id}")
    print(f"    Expiry (MMYY): {expiry_mmyy}")
    print(f"    Serial: {serial}")
    print(f"    Hash Algorithm: {hash_algo} (1=SHA-1)")
    print(f"    PK Algorithm: {pk_algo} (1=RSA)")
    print(f"    PK Length: {pk_len} bytes")
    print(f"    Exponent Length: {exp_len} bytes")

    # Calculate key space
    metadata_size = 15  # bytes 0-14
    hash_and_trailer = 21  # 20 bytes hash + 1 byte trailer
    key_space = len(recovered) - metadata_size - hash_and_trailer

    print(f"    Key space: {key_space} bytes")

    # Extract leftmost PK digits and hash from certificate
    leftmost_pk = recovered[15:15+key_space]
    cert_hash = recovered[-21:-1]

    print(f"\n  Leftmost PK: {len(leftmost_pk)} bytes")
    print(f"    First 16 bytes: {leftmost_pk[:16].hex()}")
    print(f"  Certificate Hash: {cert_hash.hex()}")

    # Reconstruct full Issuer public key
    # Leftmost from cert + Remainder = Full modulus
    full_issuer_pk = leftmost_pk + issuer_remainder
    print(f"\n  Reconstructed Issuer PK size: {len(full_issuer_pk)} bytes")

    # Compare with actual issuer modulus file
    actual_issuer_modulus = read_binary_file(f'{base_dir}/issuer/issuer_modulus.bin')
    if full_issuer_pk == actual_issuer_modulus:
        print("  *** Issuer PK matches modulus file ***")
    else:
        print(f"  *** MISMATCH: Reconstructed={len(full_issuer_pk)}, Actual={len(actual_issuer_modulus)} ***")
        print(f"      Reconstructed first 16: {full_issuer_pk[:16].hex()}")
        print(f"      Actual first 16: {actual_issuer_modulus[:16].hex()}")

    # Verify hash
    # Hash is computed over: Format || Issuer ID || Expiry || Serial || Hash Algo ||
    #                        PK Algo || PK Len || Exp Len || Leftmost PK || Remainder || Exponent
    hash_input = (
        recovered[1:15] +  # Format through Exp Len
        leftmost_pk +
        issuer_remainder +
        issuer_exponent
    )

    computed_hash = hashlib.sha1(hash_input).digest()
    print(f"\n  Hash verification:")
    print(f"    Hash input size: {len(hash_input)} bytes")
    print(f"    Computed hash: {computed_hash.hex()}")
    print(f"    Cert hash:     {cert_hash.hex()}")

    if computed_hash == cert_hash:
        print("  *** HASH MATCHES - ISSUER CERTIFICATE VALID ***")
        return actual_issuer_modulus, issuer_exponent
    else:
        print("  *** HASH MISMATCH - ISSUER CERTIFICATE INVALID ***")
        return None

def verify_icc_certificate(issuer_modulus, issuer_exponent):
    """Verify ICC certificate signed by Issuer"""
    print("\n" + "="*60)
    print("VERIFYING ICC CERTIFICATE")
    print("="*60)

    base_dir = '/Users/dangerousfood/Dev/emv-card-simulator/keys'

    issuer_exp = bytes_to_int(issuer_exponent)
    print(f"\nIssuer Modulus size: {len(issuer_modulus)} bytes ({len(issuer_modulus)*8} bits)")
    print(f"Issuer Exponent: {issuer_exp}")

    # Read ICC certificate
    icc_cert = read_binary_file(f'{base_dir}/icc/icc_certificate.bin')
    icc_remainder = read_binary_file(f'{base_dir}/icc/icc_remainder.bin')
    icc_exponent = read_binary_file(f'{base_dir}/icc/icc_exponent.bin')

    print(f"\nICC Certificate size: {len(icc_cert)} bytes")
    print(f"ICC Remainder size: {len(icc_remainder)} bytes")
    print(f"ICC Exponent: {bytes_to_int(icc_exponent)}")

    # Recover ICC certificate plaintext
    recovered = rsa_recover(icc_cert, issuer_exp, issuer_modulus)

    print(f"\nRecovered ICC Certificate:")
    print(f"  First byte (header): 0x{recovered[0]:02X} (expect 0x6A)")
    print(f"  Last byte (trailer): 0x{recovered[-1]:02X} (expect 0xBC)")
    print(f"  Format byte: 0x{recovered[1]:02X} (expect 0x04 for ICC)")

    if recovered[0] != 0x6A or recovered[-1] != 0xBC:
        print("\n*** ICC CERTIFICATE FORMAT INVALID ***")
        return False

    print("\n  Certificate structure:")
    # Parse ICC certificate structure:
    # [0]: Header 0x6A
    # [1]: Format 0x04
    # [2-11]: Application PAN (10 bytes BCD)
    # [12-13]: Expiry Date MMYY - 2 bytes
    # [14-16]: Serial Number - 3 bytes
    # [17]: Hash Algorithm Indicator
    # [18]: PK Algorithm Indicator
    # [19]: PK Length
    # [20]: PK Exponent Length
    # [21:21+key_space]: Leftmost PK digits
    # [-21:-1]: Hash (20 bytes)
    # [-1]: Trailer 0xBC

    pan_bcd = recovered[2:12].hex().upper()
    # Remove trailing F padding
    pan = pan_bcd.rstrip('F')
    expiry_mmyy = recovered[12:14].hex()
    serial = recovered[14:17].hex()
    hash_algo = recovered[17]
    pk_algo = recovered[18]
    pk_len = recovered[19] if recovered[19] != 0 else 256
    exp_len = recovered[20]

    print(f"    Application PAN (BCD): {pan_bcd}")
    print(f"    Application PAN: {pan}")
    print(f"    Expiry (MMYY): {expiry_mmyy}")
    print(f"    Serial: {serial}")
    print(f"    Hash Algorithm: {hash_algo} (1=SHA-1)")
    print(f"    PK Algorithm: {pk_algo} (1=RSA)")
    print(f"    PK Length: {pk_len} bytes")
    print(f"    Exponent Length: {exp_len} bytes")

    # Calculate key space
    metadata_size = 21  # bytes 0-20
    hash_and_trailer = 21  # 20 bytes hash + 1 byte trailer
    key_space = len(recovered) - metadata_size - hash_and_trailer

    print(f"    Key space: {key_space} bytes")

    # Extract leftmost PK digits and hash from certificate
    leftmost_pk = recovered[21:21+key_space]
    cert_hash = recovered[-21:-1]

    print(f"\n  Leftmost ICC PK: {len(leftmost_pk)} bytes")
    print(f"    First 16 bytes: {leftmost_pk[:16].hex()}")
    print(f"  Certificate Hash: {cert_hash.hex()}")

    # Reconstruct full ICC public key
    full_icc_pk = leftmost_pk + icc_remainder
    print(f"\n  Reconstructed ICC PK size: {len(full_icc_pk)} bytes")

    # Compare with actual ICC modulus file
    actual_icc_modulus = read_binary_file(f'{base_dir}/icc/icc_modulus.bin')
    if full_icc_pk == actual_icc_modulus:
        print("  *** ICC PK matches modulus file ***")
    else:
        print(f"  *** MISMATCH: Reconstructed={len(full_icc_pk)}, Actual={len(actual_icc_modulus)} ***")
        print(f"      Reconstructed first 16: {full_icc_pk[:16].hex()}")
        print(f"      Actual first 16: {actual_icc_modulus[:16].hex()}")

    # Verify hash
    # Hash is computed over: Format || PAN || Expiry || Serial || Hash Algo ||
    #                        PK Algo || PK Len || Exp Len || Leftmost PK || Remainder || Exponent
    hash_input = (
        recovered[1:21] +  # Format through Exp Len (20 bytes)
        leftmost_pk +
        icc_remainder +
        icc_exponent
    )

    computed_hash = hashlib.sha1(hash_input).digest()
    print(f"\n  Hash verification:")
    print(f"    Hash input size: {len(hash_input)} bytes")
    print(f"    Computed hash: {computed_hash.hex()}")
    print(f"    Cert hash:     {cert_hash.hex()}")

    if computed_hash == cert_hash:
        print("  *** HASH MATCHES - ICC CERTIFICATE VALID ***")
        return True
    else:
        print("  *** HASH MISMATCH - ICC CERTIFICATE INVALID ***")
        # Debug: show the differences
        print("\n  Debug: Hash input breakdown:")
        print(f"    [1:21] Format through Exp Len: {recovered[1:21].hex()}")
        print(f"    Leftmost PK first 16: {leftmost_pk[:16].hex()}")
        print(f"    Leftmost PK last 16: {leftmost_pk[-16:].hex()}")
        print(f"    Remainder: {icc_remainder.hex()}")
        print(f"    Exponent: {icc_exponent.hex()}")
        return False

def main():
    print("EMV Certificate Chain Verification")
    print("="*60)

    # Step 1: Verify Issuer certificate
    result = verify_issuer_certificate()
    if result is None:
        print("\n*** FAILED: Issuer certificate verification failed ***")
        return False

    issuer_modulus, issuer_exponent = result

    # Step 2: Verify ICC certificate
    if not verify_icc_certificate(issuer_modulus, issuer_exponent):
        print("\n*** FAILED: ICC certificate verification failed ***")
        return False

    print("\n" + "="*60)
    print("CERTIFICATE CHAIN VERIFICATION COMPLETE")
    print("="*60)
    print("\nAll certificates are valid!")
    return True

if __name__ == '__main__':
    success = main()
    sys.exit(0 if success else 1)
