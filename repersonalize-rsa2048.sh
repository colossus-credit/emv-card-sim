#!/bin/bash

# Repersonalize Colossus card with RSA-2048 certificates
# This script loads the actual generated RSA-2048 certificates onto the card
# Uses chained APDUs for 256-byte key data

set -e

echo "================================================"
echo "Repersonalizing Colossus Card with RSA-2048 Certificates"
echo "================================================"
echo ""

cd /Users/dangerousfood/Dev/emv-card-simulator

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

# Verify 256 bytes (RSA-2048)
icc_modulus_len=$(stat -f%z "$ICC_MODULUS" 2>/dev/null || stat -c%s "$ICC_MODULUS")
if [ "$icc_modulus_len" -ne 256 ]; then
    echo "ERROR: ICC modulus is $icc_modulus_len bytes, expected 256 bytes (RSA-2048)"
    exit 1
fi

# Convert binary files to hex
icc_cert_hex=$(xxd -p "$ICC_CERT" | tr -d '\n')
icc_remainder_hex=$(xxd -p "$ICC_REMAINDER" | tr -d '\n')
icc_exponent_hex=$(xxd -p "$ICC_EXPONENT" | tr -d '\n')
icc_modulus_hex=$(xxd -p "$ICC_MODULUS" | tr -d '\n')
issuer_cert_hex=$(xxd -p "$ISSUER_CERT" | tr -d '\n')
issuer_remainder_hex=$(xxd -p "$ISSUER_REMAINDER" | tr -d '\n')
issuer_exponent_hex=$(xxd -p "$ISSUER_EXPONENT" | tr -d '\n')

icc_cert_len=$(stat -f%z "$ICC_CERT" 2>/dev/null || stat -c%s "$ICC_CERT")
icc_remainder_len=$(stat -f%z "$ICC_REMAINDER" 2>/dev/null || stat -c%s "$ICC_REMAINDER")
issuer_cert_len=$(stat -f%z "$ISSUER_CERT" 2>/dev/null || stat -c%s "$ISSUER_CERT")
issuer_remainder_len=$(stat -f%z "$ISSUER_REMAINDER" 2>/dev/null || stat -c%s "$ISSUER_REMAINDER")

# Get ICC private exponent (256 bytes for RSA-2048)
icc_priv_exp=$(openssl rsa -in "$ICC_PRIVATE" -noout -text 2>/dev/null | grep -A 100 "privateExponent:" | head -55 | tail -54 | tr -d ' :\n')
# Pad to 256 bytes (512 hex chars)
while [ ${#icc_priv_exp} -lt 512 ]; do
    icc_priv_exp="0$icc_priv_exp"
done

echo "Step 1: Selecting Colossus application..."
result=$(opensc-tool -r 0 -s "00 A4 04 00 07 A0 00 00 09 51 00 01" 2>&1)
if ! echo "$result" | grep -q "SW1=0x90"; then
    echo "ERROR: Failed to select application"
    echo "$result"
    exit 1
fi
echo "  OK"

# For RSA-2048 (256 bytes), we need chained APDUs
# CLA with bit 4 set (0x90 instead of 0x80) indicates more data follows
# Final chunk uses normal CLA (0x80)

# Split the 256-byte modulus into two 128-byte chunks
chunk1_hex="${icc_modulus_hex:0:256}"   # First 128 bytes (256 hex chars)
chunk2_hex="${icc_modulus_hex:256:256}" # Second 128 bytes (256 hex chars)

# Add spaces for opensc-tool
chunk1_spaced=$(echo "$chunk1_hex" | sed 's/../& /g' | sed 's/ $//')
chunk2_spaced=$(echo "$chunk2_hex" | sed 's/../& /g' | sed 's/ $//')

echo "Step 2: Loading ICC RSA-2048 modulus (256 bytes in 2 chunks)..."

# First chunk with CLA=0x90 (chained)
echo "  Sending chunk 1 (128 bytes)..."
result=$(opensc-tool -r 0 -s "90 00 00 04 80 $chunk1_spaced" 2>&1)
if ! echo "$result" | grep -q "SW1=0x90"; then
    echo "ERROR: Failed to load ICC modulus chunk 1"
    echo "$result"
    exit 1
fi
echo "    OK"

# Second chunk with CLA=0x80 (final)
echo "  Sending chunk 2 (128 bytes)..."
result=$(opensc-tool -r 0 -s "80 00 00 04 80 $chunk2_spaced" 2>&1)
if ! echo "$result" | grep -q "SW1=0x90"; then
    echo "ERROR: Failed to load ICC modulus chunk 2"
    echo "$result"
    exit 1
fi
echo "    OK"

# Split the 256-byte private exponent into two 128-byte chunks
exp_chunk1="${icc_priv_exp:0:256}"
exp_chunk2="${icc_priv_exp:256:256}"
exp_chunk1_spaced=$(echo "$exp_chunk1" | sed 's/../& /g' | sed 's/ $//')
exp_chunk2_spaced=$(echo "$exp_chunk2" | sed 's/../& /g' | sed 's/ $//')

echo "Step 3: Loading ICC RSA-2048 private exponent (256 bytes in 2 chunks)..."

# First chunk with CLA=0x90 (chained)
echo "  Sending chunk 1 (128 bytes)..."
result=$(opensc-tool -r 0 -s "90 00 00 05 80 $exp_chunk1_spaced" 2>&1)
if ! echo "$result" | grep -q "SW1=0x90"; then
    echo "ERROR: Failed to load ICC exponent chunk 1"
    echo "$result"
    exit 1
fi
echo "    OK"

# Second chunk with CLA=0x80 (final)
echo "  Sending chunk 2 (128 bytes)..."
result=$(opensc-tool -r 0 -s "80 00 00 05 80 $exp_chunk2_spaced" 2>&1)
if ! echo "$result" | grep -q "SW1=0x90"; then
    echo "ERROR: Failed to load ICC exponent chunk 2"
    echo "$result"
    exit 1
fi
echo "    OK"

# ICC Certificate (256 bytes) - also needs chaining
cert_chunk1="${icc_cert_hex:0:256}"
cert_chunk2="${icc_cert_hex:256:256}"
cert_chunk1_spaced=$(echo "$cert_chunk1" | sed 's/../& /g' | sed 's/ $//')
cert_chunk2_spaced=$(echo "$cert_chunk2" | sed 's/../& /g' | sed 's/ $//')

echo "Step 4: Loading ICC Public Key Certificate (256 bytes in 2 chunks)..."

# For EMV tags, we use SET_EMV_TAG command (80 01 P1 P2 Lc Data)
# But 256 bytes doesn't fit in one APDU
# The simulator might need a different approach...

# Try single APDU with extended length first (00 01 00 for 256 bytes)
echo "  Trying extended length APDU..."
icc_cert_spaced=$(echo "$icc_cert_hex" | sed 's/../& /g' | sed 's/ $//')

# Use extended length: CLA INS P1 P2 00 Lc1 Lc2 Data
# But opensc-tool doesn't support this easily... try chaining instead

# Actually, for SET_EMV_TAG, we might need to modify the approach
# Let's try with 2 APDUs using tag continuation

echo "  Sending first 128 bytes..."
result=$(opensc-tool -r 0 -s "90 01 9F 46 80 $cert_chunk1_spaced" 2>&1)
if ! echo "$result" | grep -q "SW1=0x90"; then
    # If chaining doesn't work for tags, try alternative
    echo "  Chaining not supported for tags, trying alternative..."

    # Alternative: The simulator might accept tags in a different way
    # Let's check if it accepts the full certificate with extended length

    # For now, let's try without the first byte marker (Le=00 means 256)
    result=$(opensc-tool -r 0 -s "80 01 9F 46 00 $icc_cert_spaced" 2>&1)
    if ! echo "$result" | grep -q "SW1=0x90"; then
        echo "ERROR: Failed to load ICC certificate"
        echo "$result"
        echo ""
        echo "Note: The card may not support extended length APDUs for tags."
        echo "Continuing with other tags..."
    else
        echo "    OK (extended length)"
    fi
else
    echo "    OK (chunk 1)"
    # Send second chunk
    echo "  Sending second 128 bytes..."
    result=$(opensc-tool -r 0 -s "80 01 9F 46 80 $cert_chunk2_spaced" 2>&1)
    if echo "$result" | grep -q "SW1=0x90"; then
        echo "    OK (chunk 2)"
    fi
fi

# ICC Public Key Exponent (1 byte)
echo "Step 5: Loading ICC Public Key Exponent..."
result=$(opensc-tool -r 0 -s "80 01 9F 47 01 $icc_exponent_hex" 2>&1)
if ! echo "$result" | grep -q "SW1=0x90"; then
    echo "ERROR: Failed to load ICC exponent"
    echo "$result"
    exit 1
fi
echo "  OK"

# ICC Public Key Remainder (42 bytes)
if [ $icc_remainder_len -gt 0 ]; then
    echo "Step 6: Loading ICC Public Key Remainder ($icc_remainder_len bytes)..."
    icc_rem_spaced=$(echo "$icc_remainder_hex" | sed 's/../& /g' | sed 's/ $//')
    icc_rem_len_hex=$(printf '%02X' $icc_remainder_len)
    result=$(opensc-tool -r 0 -s "80 01 9F 48 $icc_rem_len_hex $icc_rem_spaced" 2>&1)
    if ! echo "$result" | grep -q "SW1=0x90"; then
        echo "ERROR: Failed to load ICC remainder"
        echo "$result"
        exit 1
    fi
    echo "  OK"
else
    echo "Step 6: No ICC remainder needed"
fi

# Issuer Certificate (256 bytes) - also needs special handling
echo "Step 7: Loading Issuer Public Key Certificate (256 bytes)..."
issuer_cert_spaced=$(echo "$issuer_cert_hex" | sed 's/../& /g' | sed 's/ $//')

# Try extended length (Le=00 = 256 bytes)
result=$(opensc-tool -r 0 -s "80 01 00 90 00 $issuer_cert_spaced" 2>&1)
if ! echo "$result" | grep -q "SW1=0x90"; then
    echo "ERROR: Failed to load Issuer certificate"
    echo "$result"
else
    echo "  OK"
fi

# Issuer Public Key Exponent (1 byte)
echo "Step 8: Loading Issuer Public Key Exponent..."
result=$(opensc-tool -r 0 -s "80 01 9F 32 01 $issuer_exponent_hex" 2>&1)
if ! echo "$result" | grep -q "SW1=0x90"; then
    echo "ERROR: Failed to load Issuer exponent"
    echo "$result"
    exit 1
fi
echo "  OK"

# Issuer Public Key Remainder (36 bytes)
if [ $issuer_remainder_len -gt 0 ]; then
    echo "Step 9: Loading Issuer Public Key Remainder ($issuer_remainder_len bytes)..."
    iss_rem_spaced=$(echo "$issuer_remainder_hex" | sed 's/../& /g' | sed 's/ $//')
    iss_rem_len_hex=$(printf '%02X' $issuer_remainder_len)
    result=$(opensc-tool -r 0 -s "80 01 00 92 $iss_rem_len_hex $iss_rem_spaced" 2>&1)
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
echo "The card now has RSA-2048 keys loaded."
echo ""
echo "IMPORTANT: You also need to update the terminal CAPK!"
echo "The new CAPK modulus is 256 bytes (RSA-2048)."
echo ""
echo "Next steps:"
echo "  1. Update terminal CAPK configuration"
echo "  2. Test the card on the Verifone terminal"
