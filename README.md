![Build and test](https://github.com/mrautio/emv-card-simulator/workflows/Build%20and%20Test/badge.svg)

# emv-card-simulator

JavaCard implementation of an EMV card for payment terminal functional and security testing / fuzzing.

If you need a payment terminal simulator for testing, try [emvpt](https://github.com/mrautio/emvpt) project.

## Prerequisites

```bash
# Xcode Command Line Tools (compiler toolchain, needed for native Python deps)
xcode-select --install

# Java 11 (required for Gradle and JavaCard SDK)
brew install openjdk@11
export JAVA_HOME=/opt/homebrew/Cellar/openjdk@11/$(ls /opt/homebrew/Cellar/openjdk@11/)/libexec/openjdk.jdk/Contents/Home
# Add the export to ~/.zshrc to make permanent

# swig (required by pyscard to compile its C-to-Python bindings)
brew install swig

# uv (required for Python personalization tool)
curl -LsSf https://astral.sh/uv/install.sh | sh

# Smart card reader + JCOP JavaCard (3.0.5+)
# gp.jar in project root (https://github.com/martinpaljak/GlobalPlatformPro)
```

## Quick Start

```bash
# 1. Build CAP files
./gradlew cap

# 2. Deploy all applets to card (PSE, PPSE, contact, contactless)
./gradlew deploy

# 3. Personalize card with default profile
./gradlew personalize

# Custom reader or profile:
./gradlew personalize -Preader=Identiv
./gradlew personalize -Pprofile=personalize/profiles/mastercard-test.yaml

# 4. Run tests
./gradlew test
```

## Building with custom AIDs

By default, CAP files are built with the Colossus RID (`A000000951`). To build for a different RID (e.g., Visa `A000000003`):

```sh
./gradlew cap \
  -Ppaymentapp_cap_aid=A000000003000000 \
  -Ppaymentapp_applet_aid=A0000000031010 \
  -Ppaymentapp_contactless_cap_aid=A000000003100000 \
  -Ppaymentapp_contactless_applet_aid=A0000000031020
```

The applet AID is baked into the CAP file at build time.

## Colossus Credit Card Network Support

This simulator now includes full support for the **Colossus Credit Card Network** with CDA (Combined Dynamic Data Authentication):

- **RID**: `A000000951`
- **Contact AID**: `A0000009510001`, **Contactless AID**: `A0000009511010`
- **BIN**: `66907500`
- **Mixed RSA hierarchy**: CAPK RSA-1984, Issuer/ICC RSA-1024
- **CDA + ECDSA P-256**: CDA for terminal ODA, ECDSA for on-chain verification
- **Forced online transactions** (ARQC only)

See the [ColossusNet Technical Specification](https://github.com/colossus-credit/colossusnet-spec) for full protocol documentation.

## EMV PKI and Certificate Chain

EMV uses a hierarchical PKI (Public Key Infrastructure) to authenticate cards. The ICC (card) public key is not stored directly - it's embedded in a signed certificate chain.

### Certificate Hierarchy

```
┌─────────────────────────────────────────────────────────────────┐
│                    CAPK (CA Public Key)                         │
│                    Root of Trust                                │
│              Stored in terminal configuration                   │
└─────────────────────────────────────────────────────────────────┘
                              │
                              │ verifies
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│              Issuer Certificate (Tag 90)                        │
│              Signed by CAPK private key                         │
│              Contains: Issuer Public Key                        │
└─────────────────────────────────────────────────────────────────┘
                              │
                              │ verifies
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│               ICC Certificate (Tag 9F46)                        │
│              Signed by Issuer private key                       │
│              Contains: ICC Public Key                           │
└─────────────────────────────────────────────────────────────────┘
                              │
                              │ used for
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                   SDAD / DDA Signature                          │
│              Signed by ICC private key                          │
│              Verified by terminal using ICC Public Key          │
└─────────────────────────────────────────────────────────────────┘
```

### ICC Certificate Structure (Tag 9F46)

The ICC certificate is a signed container that holds the public key:

```
┌─────────────────────────────────────────┐
│ Header: 0x6A                            │
│ Format: 0x04 (ICC certificate)          │
│ PAN (Application PAN)                   │
│ Expiry Date                             │
│ Certificate Serial Number               │
│ Hash Algorithm (01=SHA-1, 02=SHA-256)   │
│ Public Key Algorithm                    │
│ Public Key Length                       │
│ Exponent Length                         │
│ ICC Public Key (or leftmost portion)    │  ← Public key embedded here
│ Padding (0xBB...)                       │
│ Hash (20 or 32 bytes)                   │
│ Trailer: 0xBC                           │
└─────────────────────────────────────────┘
        │
        └── RSA-signed with Issuer Private Key
```

### Related EMV Tags

| Tag | Name | Description |
|-----|------|-------------|
| `8F` | CA Public Key Index | Identifies which CAPK to use |
| `90` | Issuer Public Key Certificate | Issuer cert signed by CAPK |
| `92` | Issuer Public Key Remainder | Overflow bytes if key > cert space |
| `9F32` | Issuer Public Key Exponent | Usually 03 or 010001 |
| `9F46` | ICC Public Key Certificate | ICC cert signed by Issuer |
| `9F47` | ICC Public Key Exponent | Usually 03 or 010001 |
| `9F48` | ICC Public Key Remainder | Overflow bytes if key > cert space |
| `9F4B` | Signed Dynamic Application Data | SDAD signed by ICC private key |

### Public Key Recovery

To recover the ICC public key, the terminal must:

1. Look up **CAPK** using RID + CA Public Key Index (tag `8F`)
2. Decrypt **Issuer Certificate** (tag `90`) using CAPK
3. Extract Issuer public key, append **Issuer Remainder** (tag `92`) if present
4. Decrypt **ICC Certificate** (tag `9F46`) using Issuer public key
5. Extract ICC public key, append **ICC Remainder** (tag `9F48`) if present
6. Use ICC public key to verify **SDAD** (tag `9F4B`) signatures

