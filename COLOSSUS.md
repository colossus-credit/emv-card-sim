# Colossus Credit Card Network - CDA Implementation

JavaCard implementation of CDA (Combined Dynamic Data Authentication) for the Colossus credit card network.

## Network Specifications

- **AID**: `A0000000951`
- **BIN**: `67676767`
- **Crypto**: RSA-2048 with SHA-256
- **Authentication**: CDA (Combined Dynamic Data Authentication)
- **Transaction Mode**: Forced online (ARQC only)
- **Message Type**: MTI 200 (SMS)
- **Specification**: [Colossus CDOL Spec](https://github.com/colossus-credit/emv-validator/blob/master/spec/ColossusCDOLSpec.md)

## Quick Start

### Prerequisites

```bash
# Requires Java 17
export JAVA_HOME=/usr/local/Cellar/openjdk@17/17.0.16/libexec/openjdk.jdk/Contents/Home
export PATH=$JAVA_HOME/bin:$PATH
```

### Certificate Generation (Production Setup)

Generate the complete EMV certificate chain for your Colossus network:

```bash
# 1. Generate CAPK (Certificate Authority Public Key) - Root of Trust
./generate-capk.sh 92 ./keys/capk
# Output: capk_private.pem, capk_public.pem, capk_modulus.bin, etc.

# 2. Generate Issuer Key and Certificate (signed by CAPK)
./generate-issuer-cert.sh ./keys/capk/capk_private.pem COLOSSUS_BANK ./keys/issuer
# Output: issuer_private.pem, issuer_certificate.bin (256 bytes), etc.

# 3. Generate ICC (Card) Key and Certificate (signed by Issuer)
./generate-icc-cert.sh ./keys/issuer/issuer_private.pem 6767676712345674 ./keys/icc
# Output: icc_private.pem, icc_certificate.bin (256 bytes), etc.

# Each script generates:
# - PEM keys (private & public)
# - Raw binary files (modulus, exponent, certificate)
# - YAML configuration for card personalization
# - Detailed information file
```

**Certificate Chain**: CAPK → Issuer → ICC  
**Key Sizes**: All RSA-2048 (256 bytes)  
**Exponent**: 3 (standard EMV)  
**Hash**: SHA-256

### Running Tests

```bash
# Run all Colossus tests
./gradlew test --tests ColossusPaymentApplicationTest

# Or use the convenience script
./run-colossus-tests.sh
```

### Deploying to JavaCard

```bash
gradle deployPaymentApp -Pjc_version=3.0.5 -Ppaymentapp_applet_aid=A0000000951
```

## CDA Implementation

### Signature Structure (Format 3)

```
Header:  0x6A
Format:  0x03 (CDA)
ARQC:    8 bytes (tag 9F26)
UN:      4 bytes (tag 9F37)
ATC:     2 bytes (tag 9F36)
Amount:  6 bytes (tag 9F02)
Currency: 2 bytes (tag 5F2A)
Date:    3 bytes (tag 9A)
Type:    1 byte (tag 9C)
TVR:     5 bytes (tag 95)
CVM:     3 bytes (tag 9F34)
TermID:  8 bytes (tag 9F1C) *Colossus custom*
MerchID: 15 bytes (tag 9F16) *Colossus custom*
AcqID:   6 bytes (tag 9F01) *Colossus custom*
Hash:    32 bytes (SHA-256)
Trailer: 0xBC
```

Total: 256 bytes, RSA-2048 signed

### Custom CDOL (54 bytes)

| Tag  | Name | Length | Offset |
|------|------|--------|--------|
| 9F02 | Amount, Authorised | 6 | 0 |
| 9F03 | Amount, Other | 6 | 6 |
| 9F1A | Terminal Country | 2 | 12 |
| 95 | TVR | 5 | 14 |
| 5F2A | Currency | 2 | 19 |
| 9A | Date | 3 | 21 |
| 9C | Type | 1 | 24 |
| 9F37 | Unpredictable Number | 4 | 25 |
| 9F1C | **Terminal ID** | 8 | 29 |
| 9F16 | **Merchant ID** | 15 | 37 |
| 9F01 | **Acquirer ID** | 6 | 52 |

## Configuration Commands

### Enable CDA Mode
```
APDU: 80 00 00 07 01 01
```

### Set RSA-2048 Key (via APDU chaining)

**Modulus** (256 bytes in 2 chunks):
```
Chunk 1: 90 00 00 04 80 [128 bytes]  // CLA=0x90 (chaining bit set)
Chunk 2: 80 00 00 04 80 [128 bytes]  // CLA=0x80 (final chunk)
```

**Exponent** (256 bytes in 2 chunks):
```
Chunk 1: 90 00 00 05 80 [128 bytes]
Chunk 2: 80 00 00 05 80 [128 bytes]
```

### Set Colossus CDOL
```
APDU: 80 01 00 8C 24 9F 02 06 9F 03 06 9F 1A 02 95 05 5F 2A 02 9A 03 9C 01 9F 37 04 9F 1C 08 9F 16 0F 9F 01 06
```

### Configure Card Data

See `src/test/java/config/colossus_card_setup_apdus.yaml` for complete configuration.

## Transaction Flow

```
1. SELECT (A0000000951)
2. GET PROCESSING OPTIONS
3. READ RECORD (get CDOL, certificates, etc.)
4. GENERATE AC (ARQC) + CDOL data (54 bytes)
   → Returns: 9F27 (cryptogram info), 9F26 (ARQC), 9F36 (ATC), 9F4B (SDAD)
5. Terminal sends to issuer for online authorization
```

## Key Features

- ✅ **RSA-2048**: Stronger cryptography via APDU chaining
- ✅ **CDA**: Combined authentication in GENERATE AC
- ✅ **Custom CDOL**: Terminal/Merchant/Acquirer tracking
- ✅ **Forced Online**: All transactions verified by issuer
- ✅ **ATC Protection**: Prevents replay attacks
- ✅ **Dynamic Data**: Unique unpredictable number per transaction

## Test Suite

All 8 tests passing:
1. Card selection with Colossus AID
2. CDA mode configuration
3. RSA-2048 key setup
4. Custom CDOL structure
5. CDA transaction with ARQC
6. Forced online transaction
7. Colossus BIN in PAN
8. ATC increment

## Technical Notes

### APDU Chaining

RSA-2048 keys (256 bytes) exceed standard APDU limits (255 bytes). Implementation uses APDU chaining:
- **Chaining Bit**: CLA bit 4 (0x10) indicates more data coming
- **First Chunk**: CLA = 0x90 (0x80 | 0x10)
- **Final Chunk**: CLA = 0x80
- **Card Side**: Buffers chained data until final chunk received

### SHA-256

Uses SHA-256 for hashing when available, falls back to SHA-1 for older JavaCard platforms.

### MTI 200 Compliance

Forced online transactions ensure all requests go through MTI 200 (Single Message System) flow.

## References

- [Colossus CDOL Specification](https://github.com/colossus-credit/emv-validator/blob/master/spec/ColossusCDOLSpec.md)
- [EMV Book 2: Security and Key Management](https://www.emvco.com/specifications/)
- [ISO 7816-4: APDU Commands](https://www.iso.org/standard/54550.html)

