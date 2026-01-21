#!/usr/bin/env python3
"""
Validate EMV Certificate Chain against CA Public Key
Per EMV Book 2 - Security and Key Management
"""

# Terminal CA Public Key (Index 92, RID A000000951) from EMV_Keys.xml
CA_MODULUS_HEX = "A3191F60C3EB54BEA99E2E7B7846E1C88ECB027C2679AD519CB713A3CD02FFB3CE7E5915407A1FAE724FBEAABA4E37326AC2FBB87583B3E4FC10E593E6F1A1B22B873A11009F16326E24B0A2F0E02D4707B92F2208863BC88DDE18DA3DFEFF3966079D38E6889B8A94AAF556CB149A11A178CE3010994FDD88D5BF0AABE283E6DA0353F2D1E6EC3AF8EDA2AE993F5C56524842D8018E76185DFB3A122460874B0E6F6F0ED13CEAA35A8085F168E911075E277907A49CE2E93A39FFE622CB55C0230790CDA1781D1B6DF82237107753DDEF1D9B582CFECE3D35752D32FCCBE023F96048DFBA6D4F9B37940FD2EE8038505F8B2D644CCB6F0D"
CA_EXPONENT = 0x03

# Card's Issuer Certificate (tag 90) from personalize-paymentapp-t1.sh
ISSUER_CERT_HEX = "210BA800A3627D444D03C9F6CDD236FAC4A3A2551868A12FD686988C8FAA7E0F96D51E449B0C7E31F39A0F35C5C9AB57DD1D8EF314C8DBF6F47A3AE331263059190C546DB48FD4852A9AA8CB5C666D96D7DE707894D456AEE04C2AD0FD5BDB24A1E777A3B6E11F3014109339CF3A030CE83B60C72D73307A0526CFB7A80C316596A691E4EB3D52CA05D7A01ADE467B25103175025DC405B1995CDF08C71D24FCC456241FEE394989B6154D90B4CACE9A1E15E4C404DF9C7E013DA78B4A3F52BFCF6F38C89F536FAEF3E43958C8312C10AF1282E7B2F75A49FA48A51225A3FB5588421D731561EFA5E44FF2EE028817061AE2D959E128C75A"

# Card's Issuer Public Key Remainder (tag 92)
ISSUER_REM_HEX = "6F807F4F021F67D013425BE300FB4A00B29CEF34B0AC9272BD74B97AC207738498DAE579"

# Card's ICC Certificate (tag 9F46)
ICC_CERT_HEX = "AA0FACEBFC1EE7CE9573BC1DA4B4308185A6C664A933CC338F830FF46744385D277AF2DE4AE4BE76393CFAD012CD55BDF9E4EC73A2F2758DE87EE17FAE32851DC498812703E7E9316E66B92DB09A908BE2762323941AEDE016A8EFDD82093AE1BB763839521884FF78EC53A14CA7DCE0F5E358999604CD9EDA5E1CD12D06726D53CF33B87CCA0681CB2F9723919ADD73B42BC6E70F746651A542A2E9E23F4AF28D577D88061B13FB3FDEB135820C24955036F9DC7BF5F4DB5AF4981C0AB6A16C9B26A4E1CD95061850F473E4809EB6CD888D2EA6637E39179C03434E3717AFCF3A7228F9981043EBE2485620CAB24D49DDF35A054EF29199"

# Card's ICC Public Key Remainder (tag 9F48)
ICC_REM_HEX = "3C2216A7BAF983DDE4E26CDA3D2D6093DB2921295573B33E86BEF841B20052689ACEE589D1F7D5BD0F25"

def hex_to_int(hex_str):
    return int(hex_str, 16)

def hex_to_bytes(hex_str):
    return bytes.fromhex(hex_str)

def rsa_recover(message_int, exponent, modulus_int):
    """RSA recovery: plaintext = message^exponent mod modulus"""
    return pow(message_int, exponent, modulus_int)

def int_to_bytes(n, length):
    return n.to_bytes(length, 'big')

def validate_issuer_cert():
    print("=" * 60)
    print("Step 1: Validate Issuer Certificate (tag 90)")
    print("=" * 60)

    ca_mod_bytes = hex_to_bytes(CA_MODULUS_HEX)
    cert_bytes = hex_to_bytes(ISSUER_CERT_HEX)

    print(f"\nCA Public Key length: {len(ca_mod_bytes)} bytes")
    print(f"Issuer Certificate length: {len(cert_bytes)} bytes")

    # Step 1: Check certificate length
    if len(cert_bytes) != len(ca_mod_bytes):
        print(f"\n[ERROR] Certificate length ({len(cert_bytes)}) != CA Key length ({len(ca_mod_bytes)})")
        return None, None

    print(f"[OK] Certificate length matches CA Key length")

    # Step 2: RSA Recovery
    print("\nPerforming RSA recovery...")
    ca_modulus = hex_to_int(CA_MODULUS_HEX)
    issuer_cert = hex_to_int(ISSUER_CERT_HEX)
    recovered_int = rsa_recover(issuer_cert, CA_EXPONENT, ca_modulus)
    recovered_bytes = int_to_bytes(recovered_int, len(ca_mod_bytes))

    print(f"\nRecovered data:")
    print(recovered_bytes.hex().upper())

    # Validate EMV certificate format
    header = recovered_bytes[0]
    cert_format = recovered_bytes[1]
    trailer = recovered_bytes[-1]

    print(f"\nHeader: 0x{header:02X} (expected 0x6A) - {'[OK]' if header == 0x6A else '[FAIL]'}")
    print(f"Format: 0x{cert_format:02X} (expected 0x02) - {'[OK]' if cert_format == 0x02 else '[FAIL]'}")
    print(f"Trailer: 0x{trailer:02X} (expected 0xBC) - {'[OK]' if trailer == 0xBC else '[FAIL]'}")

    if header != 0x6A or cert_format != 0x02 or trailer != 0xBC:
        print("\n[FAIL] Issuer Certificate validation failed!")
        print("This means the certificate was NOT signed with the CA Private Key")
        print("that matches the terminal's CA Public Key (Index 92)!")
        return None, None

    # Extract Issuer Public Key info
    issuer_id = recovered_bytes[2:6]
    pk_len = recovered_bytes[13]
    exp_len = recovered_bytes[14]

    print(f"\n--- Issuer Certificate Contents ---")
    print(f"Issuer Identifier: {issuer_id.hex().upper()}")
    print(f"Issuer PK Length: {pk_len} bytes")
    print(f"Issuer PK Exponent Length: {exp_len} bytes")

    # Extract Issuer Public Key (leftmost part from certificate + remainder)
    nca = len(ca_mod_bytes)
    pk_leftmost = recovered_bytes[15:nca-21]

    # Reconstruct full Issuer Public Key
    issuer_rem_bytes = hex_to_bytes(ISSUER_REM_HEX)
    issuer_pk_bytes = pk_leftmost + issuer_rem_bytes

    print(f"\nIssuer PK from cert: {len(pk_leftmost)} bytes")
    print(f"Issuer PK remainder: {len(issuer_rem_bytes)} bytes")
    print(f"Total Issuer PK: {len(issuer_pk_bytes)} bytes (expected {pk_len})")

    # Get exponent (usually 03 or 010001)
    issuer_exp = 0x03  # From tag 9F32 = 03

    print(f"\n[OK] Issuer Certificate VALID")

    return issuer_pk_bytes, issuer_exp

def validate_icc_cert(issuer_pk_bytes, issuer_exp):
    print("\n" + "=" * 60)
    print("Step 2: Validate ICC Certificate (tag 9F46)")
    print("=" * 60)

    icc_cert_bytes = hex_to_bytes(ICC_CERT_HEX)

    print(f"\nIssuer PK length: {len(issuer_pk_bytes)} bytes")
    print(f"ICC Certificate length: {len(icc_cert_bytes)} bytes")

    # Check certificate length
    if len(icc_cert_bytes) != len(issuer_pk_bytes):
        print(f"\n[ERROR] ICC Cert length ({len(icc_cert_bytes)}) != Issuer PK length ({len(issuer_pk_bytes)})")
        return False

    print(f"[OK] Certificate length matches Issuer PK length")

    # RSA Recovery
    print("\nPerforming RSA recovery...")
    issuer_modulus = int.from_bytes(issuer_pk_bytes, 'big')
    icc_cert_int = int.from_bytes(icc_cert_bytes, 'big')
    recovered_int = rsa_recover(icc_cert_int, issuer_exp, issuer_modulus)
    recovered_bytes = int_to_bytes(recovered_int, len(issuer_pk_bytes))

    print(f"\nRecovered data:")
    print(recovered_bytes.hex().upper())

    # Validate EMV ICC certificate format
    header = recovered_bytes[0]
    cert_format = recovered_bytes[1]
    trailer = recovered_bytes[-1]

    print(f"\nHeader: 0x{header:02X} (expected 0x6A) - {'[OK]' if header == 0x6A else '[FAIL]'}")
    print(f"Format: 0x{cert_format:02X} (expected 0x04) - {'[OK]' if cert_format == 0x04 else '[FAIL]'}")
    print(f"Trailer: 0x{trailer:02X} (expected 0xBC) - {'[OK]' if trailer == 0xBC else '[FAIL]'}")

    if header == 0x6A and cert_format == 0x04 and trailer == 0xBC:
        # Parse ICC certificate fields
        pan = recovered_bytes[2:12]
        cert_exp = recovered_bytes[12:14]
        cert_serial = recovered_bytes[14:17]
        hash_algo = recovered_bytes[17]
        pk_algo = recovered_bytes[18]
        pk_len = recovered_bytes[19]
        exp_len = recovered_bytes[20]

        print(f"\n--- ICC Certificate Contents ---")
        print(f"PAN: {pan.hex().upper()}")
        print(f"Certificate Expiry: {cert_exp.hex().upper()} (MMYY)")
        print(f"Certificate Serial: {cert_serial.hex().upper()}")
        print(f"Hash Algorithm: 0x{hash_algo:02X}")
        print(f"PK Algorithm: 0x{pk_algo:02X}")
        print(f"ICC PK Length: {pk_len} bytes")
        print(f"ICC PK Exponent Length: {exp_len} bytes")

        print(f"\n[OK] ICC Certificate VALID")
        return True
    else:
        print(f"\n[FAIL] ICC Certificate validation failed!")
        return False

def main():
    print("\n" + "=" * 60)
    print("EMV CERTIFICATE CHAIN VALIDATION")
    print("=" * 60)
    print(f"CA Public Key Index: 92")
    print(f"RID: A000000951")

    # Step 1: Validate Issuer Certificate
    issuer_pk, issuer_exp = validate_issuer_cert()

    if issuer_pk is None:
        print("\n" + "=" * 60)
        print("FINAL RESULT: [FAIL] - Issuer Certificate invalid")
        print("The certificates were NOT signed with the terminal's CA Key!")
        print("=" * 60)
        return

    # Step 2: Validate ICC Certificate
    icc_valid = validate_icc_cert(issuer_pk, issuer_exp)

    print("\n" + "=" * 60)
    if icc_valid:
        print("FINAL RESULT: [PASS] - Full certificate chain is VALID")
        print("The certificates match the terminal's CA Public Key")
        print("\nThe decline is NOT caused by certificate mismatch.")
        print("Need to investigate other causes (CDOL, Generate AC, etc.)")
    else:
        print("FINAL RESULT: [FAIL] - ICC Certificate invalid")
        print("ODA will fail even though Issuer Certificate is valid")
    print("=" * 60)

if __name__ == "__main__":
    main()
