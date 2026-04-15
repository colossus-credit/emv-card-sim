# JavaCard Deployment Guide

## Quick Start

### Complete Deployment (Build + Deploy + Personalize)
```bash
./deploy-and-personalize.sh [jc_version]
```

**Examples:**
```bash
# Use JavaCard 3.0.5 (recommended)
./deploy-and-personalize.sh 3.0.5

# Use JavaCard 3.0.4
./deploy-and-personalize.sh 3.0.4
```

### Manual Deployment Steps

#### 1. Build and Deploy Colossus Applet

**IMPORTANT:** You must specify the Colossus AIDs - the defaults are test AIDs!

```bash
./gradlew deployPaymentApp \
  -Pjc_version=3.0.5 \
  -Ppaymentapp_cap_aid=A00000095100 \
  -Ppaymentapp_applet_aid=A0000009510001
```

#### 2. Personalize Card
```bash
./personalize-colossus-card.sh
```

#### 3. Verify Installation
```bash
java -jar gp.jar -l
```

Expected output:
```
APP: A0000009510001 (SELECTABLE)    # Colossus Payment App
APP: 315041592E5359532E4444463031 (SELECTABLE)    # PSE
PKG: A00000095100 (LOADED)    # Colossus package
```

## Critical: AID Configuration

The gradle build has **default test AIDs** that are NOT the Colossus AIDs:

| Parameter | Default (Test) | Colossus (Production) |
|-----------|----------------|----------------------|
| `paymentapp_cap_aid` | `AFFFFFFFFF0000` | `A00000095100` |
| `paymentapp_applet_aid` | `AFFFFFFFFF1234` | `A0000009510001` |

**Always specify Colossus AIDs when deploying for EMV terminal testing!**

## What Gets Deployed

### Colossus Applet Configuration
- **Package AID:** `A00000095100` (RID: A000000951)
- **Applet AID:** `A0000009510001`
- **JavaCard Version:** 3.0.4 or 3.0.5

### Card Configuration (After Personalization)

#### Network Details
- **Network:** Colossus Credit
- **Network AID:** `A0000000951`
- **BIN:** `67676767`
- **Issuer:** Colossus Financial Services

#### Card Data
- **PAN:** `6767676712345678`
- **Expiry:** December 31, 2025
- **Cardholder:** COLOSSUS/CARDHOLDER
- **PIN:** 1234 (optional)

#### Security Features
- **Cryptography:** RSA-2048
- **CDA:** Enabled (Combined Dynamic Data Authentication)
- **Transaction Mode:** Forced Online (ARQC only)
- **Key Size:** 2048-bit RSA keys

#### EMV Configuration
- **CDOL Structure:** Custom Colossus CDOL (54 bytes)
  - Amount Authorized (6 bytes)
  - Amount Other (6 bytes)
  - Terminal Country Code (2 bytes)
  - TVR (5 bytes)
  - Transaction Currency (2 bytes)
  - Transaction Date (3 bytes)
  - Transaction Type (1 byte)
  - Unpredictable Number (4 bytes)
  - Terminal ID (8 bytes)
  - Merchant ID (15 bytes)
  - Acquirer ID (6 bytes)

## Requirements

### Hardware
- JavaCard reader (PC/SC compatible)
- JavaCard 3.0.4 or 3.0.5 Classic
- Physical JavaCard inserted in reader

### Software
- Java 17+ installed
- Gradle (via gradlew)
- gp.jar (GlobalPlatformPro) - auto-downloaded

## Troubleshooting

### Wrong AID Deployed (Most Common Issue!)

**Symptom:** Card list shows `AFFFFFFFFF1234` instead of `A0000009510001`
```
APP: AFFFFFFFFF1234 (SELECTABLE)    # WRONG - this is test AID
```

**Cause:** Deployed without specifying Colossus AIDs

**Solution:**
```bash
# 1. Delete the wrong applet
java -jar gp.jar --delete AFFFFFFFFF1234 --delete AFFFFFFFFF0000

# 2. Redeploy with correct Colossus AIDs
./gradlew deployPaymentApp \
  -Ppaymentapp_cap_aid=A00000095100 \
  -Ppaymentapp_applet_aid=A0000009510001

# 3. Verify
java -jar gp.jar -l | grep A0000009510001
```

### Colossus AID Missing After Deploy

**Symptom:** Package loaded but no APP entry for A0000009510001

**Cause:** `--install` only loads CAP, doesn't create instance

**Solution:**
```bash
java -jar gp.jar --install build/paymentapp.cap \
  --create A0000009510001 \
  --package A00000095100 \
  --applet A0000009510001
```

### "Could not delete AID - Some app still active"

**Solution:** Select ISD first to deselect active applet:
```bash
java -jar gp.jar -a "00A4040000"
java -jar gp.jar --delete <AID>
```

### "No card reader found"
- Check reader is connected
- Verify card is inserted
- Run: `java -jar gp.jar --list` to check

### "Deployment failed - unsupported class file format"
- Use JavaCard 3.0.5 instead of 3.0.4
- Or install Java 8/11 for 3.0.4 support

### "Personalization failed"
- Ensure applet was deployed first with **Colossus AID** (A0000009510001)
- Check card has enough memory (needs ~10KB)
- Verify card supports RSA-1984

### Card Returns Zeros Over T=0 (But Works Over T=1)

**Symptom:** USB reader (T=1) shows correct data, but Verifone terminal (T=0) shows zeros

**Cause:** Known T=0 protocol handling issue under investigation

**Workaround:** None yet - active debugging in progress

**Verify T=1 works:**
```bash
java -jar gp.jar -a "00A4040007A0000009510001" -a "00B2020C00" -d
```

### "APDU response error"
- Card may already be personalized
- Run factory reset: `java -jar gp.jar -a "00A4040007A0000009510001" -a "80050000"`
- Then retry personalization

## Advanced Usage

### Custom AID Deployment
```bash
./gradlew deployPaymentApp \
  -Pjc_version=3.0.5 \
  -Ppaymentapp_cap_aid=A000000123456 \
  -Ppaymentapp_applet_aid=A000000123457
```

### Verify Deployment
```bash
# List installed applets
java -jar gp.jar --list

# Check applet info
java -jar gp.jar --applet AFFFFFFFFF1234 --info
```

### Send Custom APDU
```bash
# Example: Get card data
java -jar gp.jar --applet AFFFFFFFFF1234 --apdu 00A4040006A0000000951
```

### Delete Applet
```bash
java -jar gp.jar --delete AFFFFFFFFF1234 --force
```

## Card Lifecycle

1. **Deploy** - Install applet on card
2. **Personalize** - Configure card data and keys
3. **Use** - Process EMV transactions
4. **Reset** - Factory reset for re-personalization
5. **Delete** - Remove applet from card

## Testing

After deployment and personalization:

```bash
# Run simulator tests
./gradlew test

# Run Colossus-specific tests
./gradlew test --tests ColossusPaymentApplicationTest
```

## Security Notes

⚠️ **Important:** The RSA-2048 keys in the personalization script are **TEST KEYS ONLY**.

For production:
1. Generate proper RSA-2048 key pairs
2. Use secure key injection procedures
3. Never commit real keys to version control
4. Follow PCI DSS and EMV security requirements

## Additional Resources

- See `COLOSSUS.md` for Colossus network specifications
- See `README.md` for project overview
- GlobalPlatformPro: https://github.com/martinpaljak/GlobalPlatformPro

