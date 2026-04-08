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

## Colossus Credit Card Network Support

This simulator now includes full support for the **Colossus Credit Card Network** with CDA (Combined Dynamic Data Authentication):

- **AID**: `A0000000951`
- **BIN**: `42069420`
- **RSA-2048 only** (RSA-1024 not supported)
- **CDA authentication** with custom CDOL
- **Forced online transactions** (ARQC only)
- **MTI 200 (SMS)** transaction type

See [COLOSSUS.md](COLOSSUS.md) for detailed documentation.

### Quick Start - Colossus Card

```bash
# 1. Generate Certificate Authority keys (root of trust)
./generate-capk.sh

# 2. Generate Issuer certificate (signed by CAPK)
./generate-issuer-cert.sh ./keys/capk/capk_private.pem COLOSSUS_BANK

# 3. Generate ICC (card) certificate (signed by Issuer)
./generate-icc-cert.sh ./keys/issuer/issuer_private.pem 4206942012345674

# 4. Generate additional test PANs with Colossus BIN
./generate-pan.sh 16

# 5. Run Colossus test suite
gradle test --tests ColossusPaymentApplicationTest

# 6. Deploy Colossus card to JavaCard
gradle deployPaymentApp -Pjc_version=3.0.5 -Ppaymentapp_applet_aid=A0000000951

# 7. Personalize card with generated certificates
./personalize-colossus-card.sh 4206942012345674
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
