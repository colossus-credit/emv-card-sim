# Colossus EMV Card Programming Guide

This document provides a complete end-to-end guide for programming a blank JavaCard with the Colossus payment application, including generating cryptographic keys, creating certificates, and personalizing the card for use with EMV terminals.

## Overview

The Colossus payment card uses EMV (Europay, Mastercard, Visa) standards for contact chip transactions. It implements:
- **CDA (Combined Dynamic Data Authentication)** for offline transaction authentication
- **RSA-2048** cryptographic keys for certificate chains
- **ARQC/TC** cryptograms for online/offline authorization

### Certificate Chain Structure

```
CAPK (Certificate Authority Public Key)
    |
    └─── Signs ───> Issuer Certificate
                        |
                        └─── Signs ───> ICC Certificate
                                            |
                                            └─── Card uses ICC private key to sign transactions
```

## Prerequisites

### Hardware
- **Blank JavaCard**: J2A040, J3A081, J3H145, or similar (JavaCard 2.2.1+)
- **Smart Card Reader**: USB reader supporting PC/SC (e.g., Gemalto USB SmartCard Reader)

### Software
- OpenSSL (for key generation)
- Java JDK 8+ (for JavaCard compilation)
- Gradle (build tool)
- GlobalPlatformPro (gp.jar) for card management
- opensc-tool (for APDU communication)

### Terminal Configuration
- Terminal must have the Colossus CAPK configured (RID: A000000951, Index: 92)

## Step 1: Generate CAPK (Certificate Authority Public Key)

The CAPK is the root of trust for the entire certificate chain. It's installed on terminals to verify card authenticity.

```bash
cd /path/to/emv-card-simulator

# Generate RSA-2048 CAPK
./generate-capk.sh 92

# Output files in keys/capk/:
#   - capk_private.pem      (KEEP SECURE - signs issuer certificates)
#   - capk_public.pem
#   - capk_modulus.bin      (256 bytes for RSA-2048)
#   - capk_exponent.bin     (typically 03)
#   - capk_config.yaml      (terminal configuration)
```

### CAPK Details
- **RID**: A000000951 (Colossus network identifier)
- **Index**: 92 (0x92)
- **Algorithm**: RSA-2048 (256 bytes)
- **Exponent**: 3 (0x03)

## Step 2: Generate Issuer Certificate

The Issuer certificate is signed by the CAPK and is used to sign individual card (ICC) certificates.

```bash
# Generate Issuer key and certificate
./generate-issuer-cert.sh ./keys/capk/capk_private.pem

# Output files in keys/issuer/:
#   - issuer_private.pem    (KEEP SECURE - signs ICC certificates)
#   - issuer_certificate.bin (256 bytes, signed by CAPK)
#   - issuer_remainder.bin   (36 bytes for RSA-2048)
#   - issuer_modulus.bin
#   - issuer_exponent.bin
```

### Certificate Structure (EMV Book 2)
| Field | Size | Description |
|-------|------|-------------|
| Header | 1 byte | 0x6A |
| Format | 1 byte | 0x02 (Issuer) |
| Issuer ID | 4 bytes | BIN (67676767) |
| Expiry | 2 bytes | MMYY |
| Serial | 3 bytes | Certificate serial number |
| Hash Algo | 1 byte | 0x01 (SHA-1) |
| PK Algo | 1 byte | 0x01 (RSA) |
| PK Length | 1 byte | Key size in bytes |
| Exp Length | 1 byte | Exponent size |
| Leftmost PK | 220 bytes | First part of public key |
| Hash | 20 bytes | SHA-1 hash |
| Trailer | 1 byte | 0xBC |

## Step 3: Generate ICC Certificate

Each card gets a unique ICC (Integrated Circuit Card) certificate. The ICC private key stays on the card and is used to sign transaction data.

```bash
# Generate ICC key and certificate for a specific PAN
./generate-icc-cert.sh ./keys/issuer/issuer_private.pem 6767676707626054

# Output files in keys/icc/:
#   - icc_private.pem       (LOAD TO CARD - then delete from computer)
#   - icc_certificate.bin   (256 bytes, signed by Issuer)
#   - icc_remainder.bin     (42 bytes for RSA-2048)
#   - icc_modulus.bin
#   - icc_exponent.bin
#   - icc_config.yaml       (personalization commands)
```

### ICC Certificate Structure
| Field | Size | Description |
|-------|------|-------------|
| Header | 1 byte | 0x6A |
| Format | 1 byte | 0x04 (ICC) |
| PAN | 10 bytes | Application PAN (BCD) |
| Expiry | 2 bytes | MMYY |
| Serial | 3 bytes | Certificate serial number |
| Hash Algo | 1 byte | 0x01 (SHA-1) |
| PK Algo | 1 byte | 0x01 (RSA) |
| PK Length | 1 byte | Key size (256 = 0x00) |
| Exp Length | 1 byte | Exponent size |
| Leftmost PK | 214 bytes | First part of ICC public key |
| Hash | 20 bytes | SHA-1 hash |
| Trailer | 1 byte | 0xBC |

## Step 4: Verify Certificate Chain

Before loading certificates to the card, verify the chain is cryptographically valid:

```bash
python3 verify-icc-cert.py

# Expected output:
# *** HASH MATCHES - ISSUER CERTIFICATE VALID ***
# *** HASH MATCHES - ICC CERTIFICATE VALID ***
# All certificates are valid!
```

## Step 5: Build and Deploy the JavaCard Applet

### Build the CAP file

```bash
# Build with Gradle
./gradlew cap \
    -Pjc_version="3.0.5" \
    -Ppaymentapp_cap_aid="A00000095100" \
    -Ppaymentapp_applet_aid="A0000009510001"

# Output: build/paymentapp.cap
```

### Deploy to Card

```bash
# Delete old applet (if exists)
java -jar gp.jar --delete A0000009510001
java -jar gp.jar --delete A00000095100

# Install new applet
java -jar gp.jar --install build/paymentapp.cap \
    --create A0000009510001

# Verify installation
java -jar gp.jar -l
```

### Troubleshooting Deployment
- **Error 0x6985**: Card security domain may be locked. Try with card-specific keys:
  ```bash
  java -jar gp.jar --install build/paymentapp.cap -k <card-specific-key>
  ```
- **Error 0x6A80**: CAP file incompatible with card. Check JavaCard version.

## Step 6: Personalize the Card

### 6.1 Initial Setup

```bash
# Select application
opensc-tool -s "00 A4 04 00 07 A0 00 00 09 51 00 01"

# Factory reset
opensc-tool -s "80 05 00 00 00"

# Re-select after reset
opensc-tool -s "00 A4 04 00 07 A0 00 00 09 51 00 01"
```

### 6.2 Load RSA-2048 Keys (Chained APDUs)

For RSA-2048 (256 bytes), the key must be loaded in chunks using chained APDUs:

```bash
# First 128 bytes (CLA=0x90 indicates more data follows)
opensc-tool -s "90 00 00 04 80 <first-128-bytes-hex>"

# Second 128 bytes (CLA=0x80 indicates final chunk)
opensc-tool -s "80 00 00 04 80 <second-128-bytes-hex>"
```

Same process for private exponent (setting 0x0005).

### 6.3 Enable CDA Mode

```bash
# Enable CDA (MUST be after key loading)
opensc-tool -s "80 00 00 07 01 01"
```

### 6.4 Load EMV Tags

Load required EMV data elements:

```bash
# Application Transaction Counter (ATC)
opensc-tool -s "80 01 9F 36 02 00 01"

# AID
opensc-tool -s "80 01 00 84 07 A0 00 00 09 51 00 01"

# Application Label
opensc-tool -s "80 01 00 50 08 43 4F 4C 4F 53 53 55 53"

# AIP (Application Interchange Profile) - CDA enabled
opensc-tool -s "80 01 00 82 02 3D 01"

# CA Public Key Index
opensc-tool -s "80 01 00 8F 01 92"

# ICC Public Key Exponent
opensc-tool -s "80 01 9F 47 01 03"

# Issuer Public Key Exponent
opensc-tool -s "80 01 9F 32 01 03"

# PAN (8 bytes BCD)
opensc-tool -s "80 01 00 5A 08 67 67 67 67 07 62 60 54"

# Expiration Date (YYMMDD)
opensc-tool -s "80 01 5F 24 03 27 12 31"

# ... (see full-repersonalize.sh for all tags)
```

### 6.5 Load Certificates

```bash
# ICC Certificate (256 bytes) - use chained APDUs
# Issuer Certificate (256 bytes) - use chained APDUs
# ICC Remainder (42 bytes)
# Issuer Remainder (36 bytes)
```

### 6.6 Set Up Response Templates

Configure which tags the card returns for each command:

```bash
# GPO Response Template
opensc-tool -s "80 02 00 01 04 00 82 00 94"

# DDA Response Template
opensc-tool -s "80 02 00 02 02 9F 4B"

# GENERATE AC Response Template (CDA)
opensc-tool -s "80 02 00 03 0A 9F 27 9F 36 9F 26 9F 4B 9F 10"
```

### 6.7 Set Up Record Templates

Define which EMV tags are in each file/record:

```bash
# Record 1, SFI 2 (Certificate data)
opensc-tool -s "80 03 01 14 08 00 8F 9F 32 9F 4A 00 82"

# Record 2, SFI 2 (Issuer certificate)
opensc-tool -s "80 03 02 14 04 00 90 00 92"

# Record 3, SFI 2 (ICC certificate)
opensc-tool -s "80 03 03 14 04 9F 46 9F 48"
```

## Step 7: Configure Terminal

Update the terminal's CAPK configuration with the new RSA-2048 CAPK:

### EMV_Keys.xml (Verifone)
```xml
<RID_DATA RID="A000000951">
    <KEY_DATA KeyIndex="92"
              ModulusLength="256"
              Modulus="<256-byte-hex>"
              ExponentLength="1"
              Exponent="03"
              CheckSum="<sha1-checksum>"
              HashAlgorithmIndicator="01"
              PKAlgorithmIndicator="01"/>
</RID_DATA>
```

### emvct.json (Verifone SDK)
```json
{
    "applications": [{
        "aid": "A0000009510001",
        "cdaProcessing": "01",
        "capKeys": [{
            "rid": "A000000951",
            "index": "92",
            "modulus": "<256-byte-hex>",
            "exponent": "03"
        }]
    }]
}
```

## Step 8: Test the Card

### Verify Certificate Chain
```bash
# Read card data via Gemalto reader
python3 read-card-data.py

# Verify ICC certificate decrypts correctly
python3 verify-icc-cert.py
```

### Test on Terminal
1. Insert card into terminal
2. Initiate a test transaction
3. Verify ODA (Offline Data Authentication) succeeds
4. Check for ARQC generation

### Expected Transaction Flow
1. **SELECT** - Terminal selects Colossus AID
2. **GPO** - Terminal requests processing options
3. **READ RECORD** - Terminal reads certificates and card data
4. **ODA** - Terminal verifies certificate chain (CAPK → Issuer → ICC)
5. **CVM** - Cardholder verification (PIN if amount >= threshold)
6. **GENERATE AC** - Card generates cryptogram (ARQC for online)

## Troubleshooting

### ODA Failure (EMVSTATUS_FALLBACK)
- Verify CAPK on terminal matches generated CAPK
- Check certificate hash verification with `verify-icc-cert.py`
- Ensure all certificates use same key size (RSA-2048)

### SW=6F00 (No Precise Diagnosis)
- Card may have old applet code - rebuild and redeploy
- CDA mode may be blocking non-2048 keys - disable CDA first

### SW=6985 (Conditions Not Satisfied)
- Card security domain locked
- Try with card-specific GlobalPlatform keys

### SW=6A82 (File Not Found)
- Application not installed
- Wrong AID in SELECT command

## Security Considerations

1. **CAPK Private Key**: Store in HSM for production. Never expose.
2. **Issuer Private Key**: Store in HSM. Used to sign ICC certificates.
3. **ICC Private Key**: Load to card, then delete from computer. Never extractable.
4. **PIN**: Stored on card, verified by card chip (not transmitted).
5. **Certificate Expiry**: Set appropriate expiration dates.

## File Reference

| File | Purpose |
|------|---------|
| `generate-capk.sh` | Generate Certificate Authority key pair |
| `generate-issuer-cert.sh` | Generate Issuer certificate |
| `generate-icc-cert.sh` | Generate ICC certificate for a card |
| `verify-icc-cert.py` | Verify certificate chain cryptography |
| `full-repersonalize.sh` | Complete card personalization script |
| `deploy-and-personalize.sh` | Build, deploy, and personalize |
| `program-card-from-yaml.sh` | Load card data from YAML config |

## EMV Tag Reference

### Core Tags
| Tag | Name | Length |
|-----|------|--------|
| 5A | Application PAN | 8-10 |
| 5F24 | Expiration Date | 3 |
| 82 | AIP | 2 |
| 94 | AFL | 4-252 |
| 8F | CA PK Index | 1 |

### Certificate Tags
| Tag | Name | Length |
|-----|------|--------|
| 90 | Issuer PK Certificate | 256 |
| 92 | Issuer PK Remainder | 36 |
| 9F32 | Issuer PK Exponent | 1-3 |
| 9F46 | ICC PK Certificate | 256 |
| 9F48 | ICC PK Remainder | 42 |
| 9F47 | ICC PK Exponent | 1-3 |

### Transaction Tags
| Tag | Name | Length |
|-----|------|--------|
| 9F26 | Application Cryptogram | 8 |
| 9F27 | Cryptogram Info Data | 1 |
| 9F36 | ATC | 2 |
| 9F4B | Signed Dynamic App Data | 256 |
| 9F10 | Issuer Application Data | var |

## Version History

- **v1.0**: Initial RSA-1984 implementation
- **v2.0**: Upgraded to RSA-2048 for CDA compliance
