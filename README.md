# emv-card-sim

JavaCard EMV card simulator for the [ColossusNet](https://colossus.credit) payment network. Produces ECDSA P-256 signatures over transaction data for on-chain verification, wrapped in a standard EMV contactless (C-2 kernel) flow with CDA.

## Prerequisites

- Java 11+ (`brew install openjdk@11`)
- [uv](https://docs.astral.sh/uv/) (`curl -LsSf https://astral.sh/uv/install.sh | sh`)
- Smart card reader (e.g., Gemalto USB)
- JCOP JavaCard (3.0.5+)
- [gp.jar](https://github.com/martinpaljak/GlobalPlatformPro) in project root

## Quick Start

```bash
# 1. Build CAP files
./gradlew cap

# 2. Install applets on card
java -jar gp.jar --force --install build/card/pse.cap
java -jar gp.jar --force --install build/card/ppse.cap
java -jar gp.jar --force --install build/card/paymentapp.cap
java -jar gp.jar --force --install build/card/paymentapp_contactless.cap

# 3. Set up Python personalization tool
cd personalize && uv venv --python 3.13 && uv pip install -e . && cd ..

# 4. Personalize card
uv run --project personalize python personalize/personalize.py \
  -p personalize/profiles/default.yaml --reader Gemalto

# 5. Run tests
./gradlew test
```

## Architecture

### Applets

| Applet | AID | Interface | Purpose |
|--------|-----|-----------|---------|
| PSE | `1PAY.SYS.DDF01` | Contact | Payment System Environment |
| PPSE | `2PAY.SYS.DDF01` | Contactless | Proximity PSE |
| RIX 0001 | `A0000009510001` | Contact | Contact payment (DDA + ECDSA) |
| RIX 1010 | `A0000009511010` | Contactless | Contactless payment (C-2 CDA + ECDSA) |

### Contactless Flow (C-2 Kernel, Full EMV + CDA)

```
SELECT PPSE  -->  PPSE FCI (AID, Kernel=C-2)
SELECT AID   -->  FCI (PDOL, Label)
GPO          -->  AIP + AFL          [ECDSA signs ATC || PDOL here]
READ RECORD  -->  Mandatory tags + 9F6E (ECDSA s)
READ RECORD  -->  RSA cert chain (CAPK -> Issuer -> ICC)
GENERATE AC  -->  CID + ATC + SDAD + 9F10 (ECDSA r)
```

### Dual Cryptography

- **RSA-1024 CDA**: Standard EMV certificate chain verified by terminal. CAPK is RSA-1984 (index 0x92), Issuer/ICC keys are RSA-1024 (mixed hierarchy for NFC frame fit).
- **ECDSA P-256**: Signs `ATC(2) || PDOL(58)` = 60 bytes at GPO time. `r` in tag 9F10 (GenAC response), `s` in tag 9F6E (READ RECORD). Verified on-chain via RIP-7212.

### Key Hierarchy

```
CAPK (RSA-1984, 248 bytes) -- loaded on terminal, index 0x92
  |
  +-- Issuer Certificate (tag 90, 248 bytes) -- in READ RECORD
  |     contains Issuer PK (RSA-1024, 128 bytes)
  |
  +-- ICC Certificate (tag 9F46, 128 bytes) -- in READ RECORD
  |     contains ICC PK (RSA-1024, 128 bytes)
  |
  +-- SDAD (tag 9F4B, 128 bytes) -- in GENERATE AC response
        signed by ICC private key

EC P-256 key -- separate, stored in secure element
  signs transaction data at GPO time
```

## Card Profile

Default profile: `personalize/profiles/default.yaml`

| Parameter | Value | Notes |
|-----------|-------|-------|
| RID | `A000000951` | ColossusNet |
| BIN | `66907500` | Fixed PAN: `6690750012345676` |
| AIP (contactless) | `1980` | CDA + CVM + TRM + EMV mode |
| CTQ | `8000` | Online PIN when CVM needed |
| AUC | `AB00` | Domestic only, ATM + non-ATM |
| Service Code | `0701` | Closed loop (bilateral agreement) |
| CAPK Index | `92` | RSA-1984 CAPK, RSA-1024 ICC |

## Personalization

```bash
# Default profile (fixed PAN, existing keys)
uv run --project personalize python personalize/personalize.py \
  -p personalize/profiles/default.yaml --reader Gemalto

# Generate fresh keys
uv run --project personalize python personalize/personalize.py \
  -p personalize/profiles/default.yaml --reader Gemalto --gen-keys

# Custom PAN
uv run --project personalize python personalize/personalize.py \
  -p personalize/profiles/default.yaml --reader Gemalto --pan 6690750012345676

# Dry run (print APDUs without sending)
uv run --project personalize python personalize/personalize.py \
  -p personalize/profiles/default.yaml --dry-run
```

## Uninstall / Reinstall

```bash
# Remove all applets
java -jar gp.jar --delete A000000951000000 --force
java -jar gp.jar --delete A000000951100000 --force
java -jar gp.jar --delete 315041592E000000000000000000 --force
java -jar gp.jar --delete 325041592E000000000000000000 --force

# Reinstall
java -jar gp.jar --force --install build/card/pse.cap
java -jar gp.jar --force --install build/card/ppse.cap
java -jar gp.jar --force --install build/card/paymentapp.cap
java -jar gp.jar --force --install build/card/paymentapp_contactless.cap
```

## Testing

```bash
# Run all tests
./gradlew test

# Run specific test class
./gradlew test --tests ColossusPaymentApplicationTest

# Build CAP files only (no tests)
./gradlew cap
```

## ECDSA Signed Message Format

The card signs 60 bytes at GPO time: `ATC(2) || PDOL(58)`

| Offset | Length | Tag | Field |
|--------|--------|-----|-------|
| 0 | 2 | 9F36 | ATC (pre-increment, N) |
| 2 | 6 | 9F02 | Amount Authorised |
| 8 | 6 | 9F03 | Amount Other |
| 14 | 2 | 9F1A | Terminal Country Code |
| 16 | 5 | 95 | Terminal Verification Results |
| 21 | 2 | 5F2A | Transaction Currency Code |
| 23 | 3 | 9A | Transaction Date |
| 26 | 1 | 9C | Transaction Type |
| 27 | 4 | 9F37 | Unpredictable Number |
| 31 | 8 | 9F1C | Terminal Identification |
| 39 | 15 | 9F16 | Merchant Identifier |
| 54 | 6 | 9F01 | Acquirer Identifier |

The GENERATE AC response contains ATC = N+1 (post-increment). The verifier subtracts 1 to reconstruct the signed message.

## Project Structure

```
emv-card-sim/
  src/main/java/emvcardsimulator/   # JavaCard applet source
  src/test/java/emvcardsimulator/   # JUnit tests (jcardsim)
  build/card/                        # Built CAP files
  personalize/                       # Python personalization tool
    emv_personalize/                 #   Python package
    profiles/                        #   YAML card profiles
    personalize.py                   #   CLI entry point
  keys/                              # RSA/EC key hierarchies (gitignored)
  gp.jar                             # GlobalPlatform tool
```

## Spec

See [ColossusNet Technical Specification](https://github.com/colossus-credit/colossusnet-spec) for the full protocol documentation.
