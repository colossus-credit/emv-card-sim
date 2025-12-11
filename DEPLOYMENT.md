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

#### 1. Build and Deploy Applet
```bash
./gradlew deployPaymentApp -Pjc_version=3.0.5
```

#### 2. Personalize Card
```bash
./personalize-colossus-card.sh
```

## What Gets Deployed

### Applet Configuration
- **Package AID:** `AFFFFFFFFF0000`
- **Applet AID:** `AFFFFFFFFF1234`
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

### "No card reader found"
- Check reader is connected
- Verify card is inserted
- Run: `java -jar gp.jar --list` to check

### "Deployment failed - unsupported class file format"
- Use JavaCard 3.0.5 instead of 3.0.4
- Or install Java 8/11 for 3.0.4 support

### "Personalization failed"
- Ensure applet was deployed first
- Check card has enough memory (needs ~10KB)
- Verify card supports RSA-2048

### "APDU response error"
- Card may already be personalized
- Run factory reset: `java -jar gp.jar --applet AFFFFFFFFF1234 --apdu 80050000`
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

