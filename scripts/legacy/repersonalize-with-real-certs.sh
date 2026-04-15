#!/bin/bash

# Repersonalize Colossus card with REAL certificates
# This script loads the actual generated certificates onto the card

set -e

echo "================================================"
echo "Repersonalizing Colossus Card with Real Certificates"
echo "================================================"
echo ""

# Check if card is present
if ! opensc-tool -l | grep -q "Yes"; then
    echo "ERROR: No card detected in reader"
    exit 1
fi

# Certificate files
ICC_CERT="keys/icc/icc_certificate.bin"
ICC_REMAINDER="keys/icc/icc_remainder.bin"
ICC_EXPONENT="keys/icc/icc_exponent.bin"
ICC_MODULUS="keys/icc/icc_modulus.bin"
ICC_PRIVATE="keys/icc/icc_private.pem"

ISSUER_CERT="keys/issuer/issuer_certificate.bin"
ISSUER_REMAINDER="keys/issuer/issuer_remainder.bin"
ISSUER_EXPONENT="keys/issuer/issuer_exponent.bin"

# Verify files exist
for f in "$ICC_CERT" "$ICC_REMAINDER" "$ICC_EXPONENT" "$ICC_MODULUS" "$ICC_PRIVATE" "$ISSUER_CERT" "$ISSUER_REMAINDER" "$ISSUER_EXPONENT"; do
    if [ ! -f "$f" ]; then
        echo "ERROR: Missing file: $f"
        exit 1
    fi
done

echo "Certificate files found:"
echo "  ICC Certificate:     $(stat -f%z "$ICC_CERT" 2>/dev/null || stat -c%s "$ICC_CERT") bytes"
echo "  ICC Remainder:       $(stat -f%z "$ICC_REMAINDER" 2>/dev/null || stat -c%s "$ICC_REMAINDER") bytes"
echo "  ICC Modulus:         $(stat -f%z "$ICC_MODULUS" 2>/dev/null || stat -c%s "$ICC_MODULUS") bytes"
echo "  Issuer Certificate:  $(stat -f%z "$ISSUER_CERT" 2>/dev/null || stat -c%s "$ISSUER_CERT") bytes"
echo "  Issuer Remainder:    $(stat -f%z "$ISSUER_REMAINDER" 2>/dev/null || stat -c%s "$ISSUER_REMAINDER") bytes"
echo ""

# Convert binary files to hex with spaces
icc_cert_hex=$(xxd -p "$ICC_CERT" | tr -d '\n' | sed 's/../& /g' | sed 's/ $//')
icc_remainder_hex=$(xxd -p "$ICC_REMAINDER" | tr -d '\n' | sed 's/../& /g' | sed 's/ $//')
icc_exponent_hex=$(xxd -p "$ICC_EXPONENT" | tr -d '\n')
icc_modulus_hex=$(xxd -p "$ICC_MODULUS" | tr -d '\n' | sed 's/../& /g' | sed 's/ $//')
issuer_cert_hex=$(xxd -p "$ISSUER_CERT" | tr -d '\n' | sed 's/../& /g' | sed 's/ $//')
issuer_remainder_hex=$(xxd -p "$ISSUER_REMAINDER" | tr -d '\n' | sed 's/../& /g' | sed 's/ $//')
issuer_exponent_hex=$(xxd -p "$ISSUER_EXPONENT" | tr -d '\n')

icc_cert_len=$(stat -f%z "$ICC_CERT" 2>/dev/null || stat -c%s "$ICC_CERT")
icc_remainder_len=$(stat -f%z "$ICC_REMAINDER" 2>/dev/null || stat -c%s "$ICC_REMAINDER")
issuer_cert_len=$(stat -f%z "$ISSUER_CERT" 2>/dev/null || stat -c%s "$ISSUER_CERT")
issuer_remainder_len=$(stat -f%z "$ISSUER_REMAINDER" 2>/dev/null || stat -c%s "$ISSUER_REMAINDER")
icc_modulus_len=$(stat -f%z "$ICC_MODULUS" 2>/dev/null || stat -c%s "$ICC_MODULUS")

# Get ICC private key exponent for card
icc_private_exp_hex=$(openssl rsa -in "$ICC_PRIVATE" -noout -text 2>/dev/null | grep -A 100 "privateExponent:" | head -50 | tail -49 | tr -d ' :\n')

echo "Step 1: Selecting Colossus application..."
result=$(opensc-tool -r 0 -s "00 A4 04 00 07 A0 00 00 09 51 00 01" 2>&1)
if ! echo "$result" | grep -q "SW1=0x90"; then
    echo "ERROR: Failed to select application"
    echo "$result"
    exit 1
fi
echo "  OK"

# Load ICC RSA private key modulus (setting 0x0004)
echo "Step 2: Loading ICC RSA modulus ($icc_modulus_len bytes)..."
# For 248-byte modulus (RSA-1984), use FF length
apdu="80 04 00 04 F8 $icc_modulus_hex"
result=$(opensc-tool -r 0 -s "$apdu" 2>&1)
if ! echo "$result" | grep -q "SW1=0x90"; then
    echo "ERROR: Failed to load ICC modulus"
    echo "$result"
    exit 1
fi
echo "  OK"

# Load ICC RSA private key exponent (setting 0x0005)
# Need to get the private exponent from the PEM file
echo "Step 3: Loading ICC RSA private exponent..."
# Extract private exponent - it's 248 bytes for RSA-1984
# openssl outputs in big-endian, might have leading zeros
icc_priv_exp=$(openssl rsa -in "$ICC_PRIVATE" -noout -text 2>/dev/null | grep -A 100 "privateExponent:" | head -50 | grep -v "privateExponent:" | tr -d ' :\n' | sed 's/^0*//')
# Pad to 248 bytes (496 hex chars)
while [ ${#icc_priv_exp} -lt 496 ]; do
    icc_priv_exp="0$icc_priv_exp"
done
icc_priv_exp_spaced=$(echo -n "$icc_priv_exp" | sed 's/../& /g' | sed 's/ $//')

apdu="80 04 00 05 F8 $icc_priv_exp_spaced"
result=$(opensc-tool -r 0 -s "$apdu" 2>&1)
if ! echo "$result" | grep -q "SW1=0x90"; then
    echo "ERROR: Failed to load ICC private exponent"
    echo "$result"
    exit 1
fi
echo "  OK"

# Load ICC Public Key Certificate (tag 9F46)
echo "Step 4: Loading ICC Public Key Certificate ($icc_cert_len bytes)..."
apdu="80 01 9F 46 F8 $icc_cert_hex"
result=$(opensc-tool -r 0 -s "$apdu" 2>&1)
if ! echo "$result" | grep -q "SW1=0x90"; then
    echo "ERROR: Failed to load ICC certificate"
    echo "$result"
    exit 1
fi
echo "  OK"

# Load ICC Public Key Exponent (tag 9F47)
echo "Step 5: Loading ICC Public Key Exponent..."
apdu="80 01 9F 47 01 $icc_exponent_hex"
result=$(opensc-tool -r 0 -s "$apdu" 2>&1)
if ! echo "$result" | grep -q "SW1=0x90"; then
    echo "ERROR: Failed to load ICC exponent"
    echo "$result"
    exit 1
fi
echo "  OK"

# Load ICC Public Key Remainder (tag 9F48)
if [ $icc_remainder_len -gt 0 ]; then
    echo "Step 6: Loading ICC Public Key Remainder ($icc_remainder_len bytes)..."
    icc_rem_len_hex=$(printf '%02X' $icc_remainder_len)
    apdu="80 01 9F 48 $icc_rem_len_hex $icc_remainder_hex"
    result=$(opensc-tool -r 0 -s "$apdu" 2>&1)
    if ! echo "$result" | grep -q "SW1=0x90"; then
        echo "ERROR: Failed to load ICC remainder"
        echo "$result"
        exit 1
    fi
    echo "  OK"
else
    echo "Step 6: No ICC remainder needed"
fi

# Load Issuer Public Key Certificate (tag 90)
echo "Step 7: Loading Issuer Public Key Certificate ($issuer_cert_len bytes)..."
apdu="80 01 00 90 F8 $issuer_cert_hex"
result=$(opensc-tool -r 0 -s "$apdu" 2>&1)
if ! echo "$result" | grep -q "SW1=0x90"; then
    echo "ERROR: Failed to load Issuer certificate"
    echo "$result"
    exit 1
fi
echo "  OK"

# Load Issuer Public Key Exponent (tag 9F32)
echo "Step 8: Loading Issuer Public Key Exponent..."
apdu="80 01 9F 32 01 $issuer_exponent_hex"
result=$(opensc-tool -r 0 -s "$apdu" 2>&1)
if ! echo "$result" | grep -q "SW1=0x90"; then
    echo "ERROR: Failed to load Issuer exponent"
    echo "$result"
    exit 1
fi
echo "  OK"

# Load Issuer Public Key Remainder (tag 92)
if [ $issuer_remainder_len -gt 0 ]; then
    echo "Step 9: Loading Issuer Public Key Remainder ($issuer_remainder_len bytes)..."
    iss_rem_len_hex=$(printf '%02X' $issuer_remainder_len)
    apdu="80 01 00 92 $iss_rem_len_hex $issuer_remainder_hex"
    result=$(opensc-tool -r 0 -s "$apdu" 2>&1)
    if ! echo "$result" | grep -q "SW1=0x90"; then
        echo "ERROR: Failed to load Issuer remainder"
        echo "$result"
        exit 1
    fi
    echo "  OK"
else
    echo "Step 9: No Issuer remainder needed"
fi

echo ""
echo "================================================"
echo "Certificate Loading Complete!"
echo "================================================"
echo ""
echo "The card now has:"
echo "  - ICC Certificate (9F46): $icc_cert_len bytes - signed by Issuer"
echo "  - ICC Remainder (9F48):   $icc_remainder_len bytes"
echo "  - ICC Exponent (9F47):    0x$icc_exponent_hex"
echo "  - Issuer Certificate (90): $issuer_cert_len bytes - signed by CAPK"
echo "  - Issuer Remainder (92):   $issuer_remainder_len bytes"
echo "  - Issuer Exponent (9F32):  0x$issuer_exponent_hex"
echo ""
echo "The certificate chain is now:"
echo "  CAPK (index 92) → Issuer Certificate → ICC Certificate"
echo ""
echo "You can now test the card on the Verifone terminal!"
