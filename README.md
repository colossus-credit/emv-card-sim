![Build and test](https://github.com/mrautio/emv-card-simulator/workflows/Build%20and%20Test/badge.svg)

# emv-card-simulator

JavaCard implementation of an EMV card for payment terminal functional and security testing / fuzzing.

If you need a payment terminal simulator for testing, try [emvpt](https://github.com/mrautio/emvpt) project.

## Building

### Cloning project

```sh
git clone --recurse-submodules https://github.com/mrautio/emv-card-simulator.git
```

### Docker build

If you don't want to install Java8/Gradle(>6), you may use Docker:

```sh
docker build -t emvcard-builder -f Dockerfile .
```

### Gradle build

If you have all developer tools existing, or enter to `nix-shell`, then you can just use Gradle:

```sh
gradle build
```

### Building with custom AIDs

By default, CAP files are built with the Colossus RID (`A000000951`). To build for a different RID (e.g., Visa `A000000003`):

```sh
./gradlew cap \
  -Ppaymentapp_cap_aid=A000000003000000 \
  -Ppaymentapp_applet_aid=A0000000031010 \
  -Ppaymentapp_contactless_cap_aid=A000000003100000 \
  -Ppaymentapp_contactless_applet_aid=A0000000031020
```

The applet AID is baked into the CAP file at build time. The `personalize.sh` script uses the RID from its config, so the CAP must be built with matching AIDs before personalization.

## Colossus Credit Card Network Support

This simulator now includes full support for the **Colossus Credit Card Network** with CDA (Combined Dynamic Data Authentication):

- **AID**: `A0000000951`
- **BIN**: `67676767`
- **RSA-2048 only** (RSA-1024 not supported)
- **CDA authentication** with custom CDOL
- **Forced online transactions** (ARQC only)
- **MTI 200 (SMS)** transaction type

See [COLOSSUS.md](COLOSSUS.md) for detailed documentation.

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

### Quick Start - Colossus Card

```bash
# 1. Generate Certificate Authority keys (root of trust)
./generate-capk.sh

# 2. Generate Issuer certificate (signed by CAPK)
./generate-issuer-cert.sh ./keys/capk/capk_private.pem COLOSSUS_BANK

# 3. Generate ICC (card) certificate (signed by Issuer)
./generate-icc-cert.sh ./keys/issuer/issuer_private.pem 6767676712345674

# 4. Generate additional test PANs with Colossus BIN
./generate-pan.sh 16

# 5. Run Colossus test suite
gradle test --tests ColossusPaymentApplicationTest

# 6. Deploy Colossus card to JavaCard
gradle deployPaymentApp -Pjc_version=3.0.5 -Ppaymentapp_applet_aid=A0000000951

# 7. Personalize card with generated certificates
./personalize-colossus-card.sh 6767676712345674
```

## Update dependencies

Run the [GitHub Actions Workflow](https://github.com/mrautio/emv-card-simulator/actions/workflows/update-dependencies.yml).

## Deploying to a SmartCard

If you have a SmartCard reader and a Global Platform compliant SmartCard, then you can deploy the application to an actual SmartCard. Common installation issue is to use incorrect JavaCard SDK version, set correct with jc_version.

```sh
# Deploy payment selection app to a JavaCard 2 SmartCard 
gradle deployPse -Pjc_version=2.2.2
# Deploy the payment app to a JavaCard 2 SmartCard 
gradle deployPaymentApp -Pjc_version=2.2.2
```
