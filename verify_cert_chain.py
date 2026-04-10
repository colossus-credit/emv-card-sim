#!/usr/bin/env python3
"""
EMV Certificate Chain Verification
Verifies: CAPK -> Issuer Certificate -> ICC Certificate
"""

import hashlib

def bytes_to_int(b):
    return int.from_bytes(b, 'big')

def int_to_bytes(n, length):
    return n.to_bytes(length, 'big')

def rsa_recover(data, exponent, modulus):
    """RSA public key recovery: data^exponent mod modulus"""
    d = bytes_to_int(data)
    e = exponent
    n = bytes_to_int(modulus)
    result = pow(d, e, n)
    return int_to_bytes(result, len(modulus))

# CAPK for RID A000000951, Index 92
CAPK_MODULUS = bytes.fromhex(
    "A3191F60C3EB54BEA99E2E7B7846E1C88ECB027C2679AD519CB713A3CD02FFB3"
    "CE7E5915407A1FAE724FBEAABA4E37326AC2FBB87583B3E4FC10E593E6F1A1B2"
    "2B873A11009F16326E24B0A2F0E02D4707B92F2208863BC88DDE18DA3DFEFF39"
    "66079D38E6889B8A94AAF556CB149A11A178CE3010994FDD88D5BF0AABE283E6"
    "DA0353F2D1E6EC3AF8EDA2AE993F5C56524842D8018E76185DFB3A122460874B"
    "0E6F6F0ED13CEAA35A8085F168E911075E277907A49CE2E93A39FFE622CB55C0"
    "230790CDA1781D1B6DF82237107753DDEF1D9B582CFECE3D35752D32FCCBE023"
    "F96048DFBA6D4F9B37940FD2EE8038505F8B2D644CCB6F0D"
)
CAPK_EXPONENT = 3

# Issuer Certificate (tag 90) from card
ISSUER_CERT = bytes.fromhex(
    "210BA800A3627D444D03C9F6CDD236FAC4A3A2551868A12FD686988C8FAA7E0F"
    "96D51E449B0C7E31F39A0F35C5C9AB57DD1D8EF314C8DBF6F47A3AE331263059"
    "190C546DB48FD4852A9AA8CB5C666D96D7DE707894D456AEE04C2AD0FD5BDB24"
    "A1E777A3B6E11F3014109339CF3A030CE83B60C72D73307A0526CFB7A80C3165"
    "96A691E4EB3D52CA05D7A01ADE467B25103175025DC405B1995CDF08C71D24FC"
    "C456241FEE394989B6154D90B4CACE9A1E15E4C404DF9C7E013DA78B4A3F52BF"
    "CF6F38C89F536FAEF3E43958C8312C10AF1282E7B2F75A49FA48A51225A3FB55"
    "88421D731561EFA5E44FF2EE028817061AE2D959E128C75A"
)

# Issuer PK Remainder (tag 92) from card
ISSUER_REMAINDER = bytes.fromhex(
    "6F807F4F021F67D013425BE300FB4A00B29CEF34B0AC9272BD74B97AC207738498DAE579"
)

# ICC Certificate (tag 9F46) from card
ICC_CERT = bytes.fromhex(
    "87F65ED2638B741D4467E78600A45B39774881105B4C147A27FFAEAAE5B99EB9"
    "ADCF5B419862CBA96A10450C33C5D9B1756EAF3A19E191795FA8B813F909433D"
    "CECB8879614A9130DC8F441B4F60F53E0703A11750CAB7EA780D69B0DA285086"
    "CAD33319BE71FFAA7C57BE1CD7966AF0E68EFAEB254E528490E05F571B609211"
    "3F9000660013AD33598C79631FF452128C7B05CE8E05037A28627B6069AAEE6D"
    "9C3AB046E74420F4A63D297A72E0D7CDE2498AFA77EF691143F4EA27889F7841"
    "5F3A9AF7B16E558596C69FFEA329C57C4684956FE4D028D1C0C837352ADBEAC0"
    "619A4767A47D4A2CD9132D761BE78BA64D7D263D509445A8"
)

# ICC PK Remainder (tag 9F48) from card
ICC_REMAINDER = bytes.fromhex(
    "F27D9CD883A0FE8FB52A72F954BDA1E5B0E7853A93375A144E96F7CFC322CE0A24C4B876B54064CE7599"
)

# Issuer PK Exponent (tag 9F32)
ISSUER_PK_EXPONENT = 3

# ICC PK Exponent (tag 9F47)
ICC_PK_EXPONENT = 3

print("=" * 60)
print("EMV Certificate Chain Verification")
print("=" * 60)

# Step 1: Recover Issuer Certificate with CAPK
print("\n[Step 1] Recovering Issuer Certificate with CAPK...")
print(f"  CAPK Modulus length: {len(CAPK_MODULUS)} bytes ({len(CAPK_MODULUS)*8} bits)")
print(f"  Issuer Cert length: {len(ISSUER_CERT)} bytes")

recovered_issuer = rsa_recover(ISSUER_CERT, CAPK_EXPONENT, CAPK_MODULUS)
print(f"  Recovered data: {recovered_issuer.hex()[:64]}...")

# Parse recovered issuer certificate (EMV Book 2, Table 4)
print("\n[Step 2] Parsing Issuer Certificate...")
header = recovered_issuer[0]
format_byte = recovered_issuer[1]
issuer_id = recovered_issuer[2:6]
cert_exp = recovered_issuer[6:8]
cert_serial = recovered_issuer[8:11]
hash_algo = recovered_issuer[11]
issuer_pk_algo = recovered_issuer[12]
issuer_pk_len = recovered_issuer[13]
issuer_pk_exp_len = recovered_issuer[14]
# Issuer PK (leftmost digits) starts at offset 15
# Length is NCA - 36 where NCA is CAPK modulus length
issuer_pk_in_cert = recovered_issuer[15:-21]  # Up to hash (last 20) + trailer (1)
hash_result = recovered_issuer[-21:-1]
trailer = recovered_issuer[-1]

print(f"  Header: 0x{header:02X} (expected 0x6A)")
print(f"  Format: 0x{format_byte:02X} (expected 0x02 for Issuer Cert)")
print(f"  Issuer ID: {issuer_id.hex()}")
print(f"  Cert Expiry: {cert_exp.hex()}")
print(f"  Cert Serial: {cert_serial.hex()}")
print(f"  Hash Algorithm: 0x{hash_algo:02X} (01=SHA-1)")
print(f"  Issuer PK Algorithm: 0x{issuer_pk_algo:02X} (01=RSA)")
print(f"  Issuer PK Length: {issuer_pk_len} bytes ({issuer_pk_len*8} bits)")
print(f"  Issuer PK Exponent Length: {issuer_pk_exp_len} bytes")
print(f"  Hash in cert: {hash_result.hex()}")
print(f"  Trailer: 0x{trailer:02X} (expected 0xBC)")

# Validate header and trailer
if header != 0x6A:
    print(f"\n  *** ERROR: Invalid header 0x{header:02X}, expected 0x6A ***")
if trailer != 0xBC:
    print(f"\n  *** ERROR: Invalid trailer 0x{trailer:02X}, expected 0xBC ***")
if format_byte != 0x02:
    print(f"\n  *** ERROR: Invalid format 0x{format_byte:02X}, expected 0x02 ***")

# Reconstruct Issuer Public Key
print("\n[Step 3] Reconstructing Issuer Public Key...")
# Issuer PK = leftmost part from cert + remainder
issuer_pk_leftmost = issuer_pk_in_cert[:issuer_pk_len - len(ISSUER_REMAINDER)]
issuer_public_key = issuer_pk_leftmost + ISSUER_REMAINDER
print(f"  Issuer PK leftmost from cert: {len(issuer_pk_leftmost)} bytes")
print(f"  Issuer PK remainder: {len(ISSUER_REMAINDER)} bytes")
print(f"  Total Issuer PK: {len(issuer_public_key)} bytes")
print(f"  Issuer PK: {issuer_public_key.hex()[:64]}...")

# Verify hash
print("\n[Step 4] Verifying Issuer Certificate Hash...")
# Hash input: Format || Issuer ID || Cert Exp || Cert Serial || Hash Algo ||
#             Issuer PK Algo || Issuer PK Len || Issuer PK Exp Len ||
#             Issuer PK || Issuer PK Remainder || Issuer PK Exponent
hash_input = (
    bytes([format_byte]) +
    issuer_id +
    cert_exp +
    cert_serial +
    bytes([hash_algo, issuer_pk_algo, issuer_pk_len, issuer_pk_exp_len]) +
    issuer_public_key +
    bytes([ISSUER_PK_EXPONENT])  # Exponent as single byte since exp_len=1
)
computed_hash = hashlib.sha1(hash_input).digest()
print(f"  Computed hash: {computed_hash.hex()}")
print(f"  Hash in cert:  {hash_result.hex()}")
if computed_hash == hash_result:
    print("  *** ISSUER CERTIFICATE HASH VALID ***")
else:
    print("  *** ERROR: ISSUER CERTIFICATE HASH MISMATCH ***")

# Step 5: Recover ICC Certificate with Issuer PK
print("\n" + "=" * 60)
print("[Step 5] Recovering ICC Certificate with Issuer PK...")
print(f"  Issuer PK length: {len(issuer_public_key)} bytes")
print(f"  ICC Cert length: {len(ICC_CERT)} bytes")

recovered_icc = rsa_recover(ICC_CERT, ISSUER_PK_EXPONENT, issuer_public_key)
print(f"  Recovered data: {recovered_icc.hex()[:64]}...")

# Parse recovered ICC certificate (EMV Book 2, Table 14)
print("\n[Step 6] Parsing ICC Certificate...")
icc_header = recovered_icc[0]
icc_format = recovered_icc[1]
icc_pan = recovered_icc[2:12]  # 10 bytes
icc_cert_exp = recovered_icc[12:14]
icc_cert_serial = recovered_icc[14:17]
icc_hash_algo = recovered_icc[17]
icc_pk_algo = recovered_icc[18]
icc_pk_len = recovered_icc[19]
icc_pk_exp_len = recovered_icc[20]
icc_pk_in_cert = recovered_icc[21:-21]  # Up to hash
icc_hash_result = recovered_icc[-21:-1]
icc_trailer = recovered_icc[-1]

print(f"  Header: 0x{icc_header:02X} (expected 0x6A)")
print(f"  Format: 0x{icc_format:02X} (expected 0x04 for ICC Cert)")
print(f"  PAN: {icc_pan.hex()}")
print(f"  Cert Expiry: {icc_cert_exp.hex()}")
print(f"  Cert Serial: {icc_cert_serial.hex()}")
print(f"  Hash Algorithm: 0x{icc_hash_algo:02X} (01=SHA-1)")
print(f"  ICC PK Algorithm: 0x{icc_pk_algo:02X} (01=RSA)")
print(f"  ICC PK Length: {icc_pk_len} bytes ({icc_pk_len*8} bits)")
print(f"  ICC PK Exponent Length: {icc_pk_exp_len} bytes")
print(f"  Hash in cert: {icc_hash_result.hex()}")
print(f"  Trailer: 0x{icc_trailer:02X} (expected 0xBC)")

# Validate header and trailer
if icc_header != 0x6A:
    print(f"\n  *** ERROR: Invalid header 0x{icc_header:02X}, expected 0x6A ***")
if icc_trailer != 0xBC:
    print(f"\n  *** ERROR: Invalid trailer 0x{icc_trailer:02X}, expected 0xBC ***")
if icc_format != 0x04:
    print(f"\n  *** ERROR: Invalid format 0x{icc_format:02X}, expected 0x04 ***")

# Reconstruct ICC Public Key
print("\n[Step 7] Reconstructing ICC Public Key...")
icc_pk_leftmost = icc_pk_in_cert[:icc_pk_len - len(ICC_REMAINDER)]
icc_public_key = icc_pk_leftmost + ICC_REMAINDER
print(f"  ICC PK leftmost from cert: {len(icc_pk_leftmost)} bytes")
print(f"  ICC PK remainder: {len(ICC_REMAINDER)} bytes")
print(f"  Total ICC PK: {len(icc_public_key)} bytes")

# Verify ICC hash
print("\n[Step 8] Verifying ICC Certificate Hash...")
# For ICC cert, hash also includes static data if SDA tag list indicates
# But for basic verification, let's check the certificate structure first
icc_hash_input = (
    bytes([icc_format]) +
    icc_pan +
    icc_cert_exp +
    icc_cert_serial +
    bytes([icc_hash_algo, icc_pk_algo, icc_pk_len, icc_pk_exp_len]) +
    icc_public_key +
    bytes([ICC_PK_EXPONENT])
)
icc_computed_hash = hashlib.sha1(icc_hash_input).digest()
print(f"  Computed hash: {icc_computed_hash.hex()}")
print(f"  Hash in cert:  {icc_hash_result.hex()}")
if icc_computed_hash == icc_hash_result:
    print("  *** ICC CERTIFICATE HASH VALID ***")
else:
    print("  *** ERROR: ICC CERTIFICATE HASH MISMATCH ***")

print("\n" + "=" * 60)
print("Summary")
print("=" * 60)
print(f"  Issuer Cert Header: {'OK' if header == 0x6A else 'FAIL'}")
print(f"  Issuer Cert Trailer: {'OK' if trailer == 0xBC else 'FAIL'}")
print(f"  Issuer Cert Hash: {'OK' if computed_hash == hash_result else 'FAIL'}")
print(f"  ICC Cert Header: {'OK' if icc_header == 0x6A else 'FAIL'}")
print(f"  ICC Cert Trailer: {'OK' if icc_trailer == 0xBC else 'FAIL'}")
print(f"  ICC Cert Hash: {'OK' if icc_computed_hash == icc_hash_result else 'FAIL'}")
