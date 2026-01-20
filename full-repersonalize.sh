#!/bin/bash

# Full Colossus Card Repersonalization with RSA-2048 Certificates
# This script performs a complete card personalization from scratch
#
# Order of operations:
# 1. Select application
# 2. Factory reset (clears CDA flag)
# 3. Load RSA-2048 keys (before enabling CDA)
# 4. Enable CDA
# 5. Load certificates and other data

set -e

cd /Users/dangerousfood/Dev/emv-card-simulator

echo "================================================"
echo "Full Colossus Card Repersonalization (RSA-2048)"
echo "================================================"
echo ""

# Check if card is present
if ! opensc-tool -l | grep -q "Yes"; then
    echo "ERROR: No card detected in reader"
    exit 1
fi

send_apdu() {
    local apdu="$1"
    local description="$2"

    result=$(opensc-tool -r 0 -s "$apdu" 2>&1)
    if echo "$result" | grep -q "SW1=0x90"; then
        return 0
    else
        echo "FAILED: $description"
        echo "$result"
        return 1
    fi
}

echo "Step 1: Selecting Colossus application..."
send_apdu "00 A4 04 00 07 A0 00 00 09 51 00 01" "SELECT" || exit 1
echo "  OK"

echo "Step 2: Factory reset..."
send_apdu "80 05 00 00 00" "FACTORY RESET" || exit 1
echo "  OK"

# Re-select after reset
echo "Step 3: Re-selecting application..."
send_apdu "00 A4 04 00 07 A0 00 00 09 51 00 01" "SELECT" || exit 1
echo "  OK"

# CRITICAL: Disable CDA first (cdaEnabled persists across factory reset)
echo "Step 3b: Disabling CDA mode for key loading..."
send_apdu "80 00 00 07 01 00" "CDA Disable" || exit 1
echo "  OK"

# Load ICC RSA-2048 keys BEFORE enabling CDA
# The modulus and exponent are 256 bytes each, need chained APDUs
echo "Step 4: Loading ICC RSA-2048 modulus (256 bytes)..."

# Get modulus hex
icc_modulus_hex=$(xxd -p keys/icc/icc_modulus.bin | tr -d '\n')

# Split into 2 chunks of 128 bytes each
chunk1="${icc_modulus_hex:0:256}"
chunk2="${icc_modulus_hex:256:256}"

chunk1_spaced=$(echo "$chunk1" | sed 's/../& /g' | sed 's/ $//')
chunk2_spaced=$(echo "$chunk2" | sed 's/../& /g' | sed 's/ $//')

# Send first chunk with CLA=0x90 (chained)
echo "  Chunk 1 (128 bytes)..."
send_apdu "90 00 00 04 80 $chunk1_spaced" "Modulus chunk 1" || exit 1
echo "  OK"

# Send second chunk with CLA=0x80 (final)
echo "  Chunk 2 (128 bytes)..."
send_apdu "80 00 00 04 80 $chunk2_spaced" "Modulus chunk 2" || exit 1
echo "  OK"

# Get private exponent hex
echo "Step 5: Loading ICC RSA-2048 private exponent (256 bytes)..."
icc_priv_exp=$(openssl rsa -in keys/icc/icc_private.pem -noout -text 2>/dev/null | grep -A 100 "privateExponent:" | head -55 | tail -54 | tr -d ' :\n')
# Pad to 256 bytes (512 hex chars)
while [ ${#icc_priv_exp} -lt 512 ]; do
    icc_priv_exp="0$icc_priv_exp"
done

exp_chunk1="${icc_priv_exp:0:256}"
exp_chunk2="${icc_priv_exp:256:256}"
exp_chunk1_spaced=$(echo "$exp_chunk1" | sed 's/../& /g' | sed 's/ $//')
exp_chunk2_spaced=$(echo "$exp_chunk2" | sed 's/../& /g' | sed 's/ $//')

# Send first chunk with CLA=0x90 (chained)
echo "  Chunk 1 (128 bytes)..."
send_apdu "90 00 00 05 80 $exp_chunk1_spaced" "Exponent chunk 1" || exit 1
echo "  OK"

# Send second chunk with CLA=0x80 (final)
echo "  Chunk 2 (128 bytes)..."
send_apdu "80 00 00 05 80 $exp_chunk2_spaced" "Exponent chunk 2" || exit 1
echo "  OK"

# Now enable CDA (setting 0x0007)
echo "Step 6: Enabling CDA mode..."
send_apdu "80 00 00 07 01 01" "CDA Enable" || exit 1
echo "  OK"

# Set PIN code
echo "Step 7: Setting PIN code (1234)..."
send_apdu "80 00 00 01 02 12 34" "PIN Code" || exit 1
echo "  OK"

# Set response template tag (77)
echo "Step 8: Setting response template (tag 77)..."
send_apdu "80 00 00 02 02 00 77" "Response Template" || exit 1
echo "  OK"

# Load EMV tags
echo "Step 9: Loading EMV tags..."

# ATC (Application Transaction Counter)
send_apdu "80 01 9F 36 02 00 01" "ATC" || exit 1
echo "  ATC OK"

# AID
send_apdu "80 01 00 84 07 A0 00 00 09 51 00 01" "AID" || exit 1
echo "  AID OK"

# Application Label
send_apdu "80 01 00 50 08 43 4F 4C 4F 53 53 55 53" "App Label" || exit 1
echo "  App Label OK"

# Language Preference
send_apdu "80 01 5F 2D 02 65 6E" "Language" || exit 1
echo "  Language OK"

# Priority Indicator
send_apdu "80 01 00 87 01 01" "Priority" || exit 1
echo "  Priority OK"

# Preferred Name
send_apdu "80 01 9F 12 0F 43 4F 4C 4F 53 53 55 53 20 43 52 45 44 49 54" "Preferred Name" || exit 1
echo "  Preferred Name OK"

# Code Table Index
send_apdu "80 01 9F 11 01 01" "Code Table" || exit 1
echo "  Code Table OK"

# AIP (Application Interchange Profile) - CDA enabled
send_apdu "80 01 00 82 02 3D 01" "AIP" || exit 1
echo "  AIP OK"

# AFL (Application File Locator)
send_apdu "80 01 00 94 0C 08 02 02 00 10 01 05 01 18 01 03 00" "AFL" || exit 1
echo "  AFL OK"

# Track 2 Equivalent Data (for our PAN: 6767676707626054)
send_apdu "80 01 00 57 13 67 67 67 67 07 62 60 54 D2 71 22 01 00 00 00 00 00 00 0F" "Track 2" || exit 1
echo "  Track 2 OK"

# Cardholder Name
send_apdu "80 01 5F 20 14 43 4F 4C 4F 53 53 55 53 2F 43 41 52 44 48 4F 4C 44 45 52 20" "Cardholder Name" || exit 1
echo "  Cardholder Name OK"

# CA Public Key Index (0x92)
send_apdu "80 01 00 8F 01 92" "CA PK Index" || exit 1
echo "  CA PK Index OK"

# Issuer Public Key Exponent (03)
send_apdu "80 01 9F 32 01 03" "Issuer PK Exp" || exit 1
echo "  Issuer PK Exp OK"

# SDA Tag List
send_apdu "80 01 9F 4A 01 82" "SDA Tag List" || exit 1
echo "  SDA Tag List OK"

# ICC Public Key Exponent (03)
send_apdu "80 01 9F 47 01 03" "ICC PK Exp" || exit 1
echo "  ICC PK Exp OK"

# DDOL
send_apdu "80 01 9F 49 03 9F 37 04" "DDOL" || exit 1
echo "  DDOL OK"

# Now load certificates (256 bytes each)
echo "Step 10: Loading ICC Certificate (256 bytes)..."
icc_cert_hex=$(xxd -p keys/icc/icc_certificate.bin | tr -d '\n')
cert_chunk1="${icc_cert_hex:0:256}"
cert_chunk2="${icc_cert_hex:256:256}"
cert_chunk1_spaced=$(echo "$cert_chunk1" | sed 's/../& /g' | sed 's/ $//')
cert_chunk2_spaced=$(echo "$cert_chunk2" | sed 's/../& /g' | sed 's/ $//')

# For 256-byte tags, use chained APDUs with tag command
echo "  Chunk 1..."
send_apdu "90 01 9F 46 80 $cert_chunk1_spaced" "ICC Cert chunk 1" || { echo "  Note: Chaining may not work for tags"; }
echo "  Chunk 2..."
send_apdu "80 01 9F 46 80 $cert_chunk2_spaced" "ICC Cert chunk 2" || { echo "  Note: Tag continuation may fail"; }

# ICC Remainder (42 bytes)
echo "Step 11: Loading ICC Remainder (42 bytes)..."
icc_remainder_hex=$(xxd -p keys/icc/icc_remainder.bin | tr -d '\n')
icc_remainder_spaced=$(echo "$icc_remainder_hex" | sed 's/../& /g' | sed 's/ $//')
send_apdu "80 01 9F 48 2A $icc_remainder_spaced" "ICC Remainder" || exit 1
echo "  OK"

# Issuer Certificate (256 bytes)
echo "Step 12: Loading Issuer Certificate (256 bytes)..."
issuer_cert_hex=$(xxd -p keys/issuer/issuer_certificate.bin | tr -d '\n')
iss_cert_chunk1="${issuer_cert_hex:0:256}"
iss_cert_chunk2="${issuer_cert_hex:256:256}"
iss_cert_chunk1_spaced=$(echo "$iss_cert_chunk1" | sed 's/../& /g' | sed 's/ $//')
iss_cert_chunk2_spaced=$(echo "$iss_cert_chunk2" | sed 's/../& /g' | sed 's/ $//')

echo "  Chunk 1..."
send_apdu "90 01 00 90 80 $iss_cert_chunk1_spaced" "Issuer Cert chunk 1" || { echo "  Note: Chaining may not work for tags"; }
echo "  Chunk 2..."
send_apdu "80 01 00 90 80 $iss_cert_chunk2_spaced" "Issuer Cert chunk 2" || { echo "  Note: Tag continuation may fail"; }

# Issuer Remainder (36 bytes)
echo "Step 13: Loading Issuer Remainder (36 bytes)..."
issuer_remainder_hex=$(xxd -p keys/issuer/issuer_remainder.bin | tr -d '\n')
issuer_remainder_spaced=$(echo "$issuer_remainder_hex" | sed 's/../& /g' | sed 's/ $//')
send_apdu "80 01 00 92 24 $issuer_remainder_spaced" "Issuer Remainder" || exit 1
echo "  OK"

# Expiration Date
echo "Step 14: Loading card data..."
send_apdu "80 01 5F 24 03 27 12 31" "Expiry Date" || exit 1
echo "  Expiry Date OK"

# PAN
send_apdu "80 01 00 5A 08 67 67 67 67 07 62 60 54" "PAN" || exit 1
echo "  PAN OK"

# PAN Sequence Number
send_apdu "80 01 5F 34 01 01" "PAN Seq" || exit 1
echo "  PAN Seq OK"

# Application Usage Control
send_apdu "80 01 9F 07 02 FF 00" "AUC" || exit 1
echo "  AUC OK"

# IAC Default
send_apdu "80 01 9F 0D 05 FC 68 8C 98 00" "IAC Default" || exit 1
echo "  IAC Default OK"

# IAC Denial
send_apdu "80 01 9F 0E 05 00 10 00 00 00" "IAC Denial" || exit 1
echo "  IAC Denial OK"

# IAC Online
send_apdu "80 01 9F 0F 05 FC 68 8C F8 00" "IAC Online" || exit 1
echo "  IAC Online OK"

# Issuer Country Code
send_apdu "80 01 5F 28 02 08 40" "Country Code" || exit 1
echo "  Country Code OK"

# Application Version
send_apdu "80 01 9F 08 02 00 01" "App Version" || exit 1
echo "  App Version OK"

# CDOL1
send_apdu "80 01 00 8C 1E 9F 02 06 9F 03 06 9F 1A 02 95 05 5F 2A 02 9A 03 9C 01 9F 37 04 9F 1C 08 9F 16 0F 9F 01 06" "CDOL1" || exit 1
echo "  CDOL1 OK"

# CDOL2
send_apdu "80 01 00 8D 20 8A 02 9F 02 06 9F 03 06 9F 1A 02 95 05 5F 2A 02 9A 03 9C 01 9F 37 04 9F 1C 08 9F 16 0F 9F 01 06" "CDOL2" || exit 1
echo "  CDOL2 OK"

# CVM List (PIN required for amounts >= $20)
send_apdu "80 01 00 8E 0A 00 00 00 00 00 00 00 00 1F 00" "CVM List" || exit 1
echo "  CVM List OK"

# IAD (Issuer Application Data)
send_apdu "80 01 9F 10 07 06 01 0A 03 A4 A0 02" "IAD" || exit 1
echo "  IAD OK"

# Set up templates
echo "Step 15: Setting up response templates..."

# Template 1: GPO Response
send_apdu "80 02 00 01 04 00 82 00 94" "GPO Template" || exit 1
echo "  GPO Template OK"

# Template 2: DDA Response
send_apdu "80 02 00 02 02 9F 4B" "DDA Template" || exit 1
echo "  DDA Template OK"

# Template 3: GENERATE AC Response
send_apdu "80 02 00 03 0A 9F 27 9F 36 9F 26 9F 4B 9F 10" "GenAC Template" || exit 1
echo "  GenAC Template OK"

# Template 4: FCI Template
send_apdu "80 02 00 04 04 00 84 00 A5" "FCI Template" || exit 1
echo "  FCI Template OK"

# Template 5: A5 FCI Template
send_apdu "80 02 00 05 0A 00 50 5F 2D 00 87 9F 12 9F 11" "A5 FCI Template" || exit 1
echo "  A5 FCI Template OK"

# Record templates
echo "Step 16: Setting up record templates..."

# Record 1, SFI 1 (Track data)
send_apdu "80 03 02 0C 06 00 57 5F 20 9F 1F" "Record 2 SFI 1" || exit 1
echo "  Record 2 SFI 1 OK"

# Record 1, SFI 2 (ICC cert data)
send_apdu "80 03 01 14 08 00 8F 9F 32 9F 4A 00 82" "Record 1 SFI 2" || exit 1
echo "  Record 1 SFI 2 OK"

# Record 2, SFI 2 (Issuer cert data)
send_apdu "80 03 02 14 04 00 90 00 92" "Record 2 SFI 2" || exit 1
echo "  Record 2 SFI 2 OK"

# Record 3, SFI 2 (ICC cert - need separate record for 9F46)
send_apdu "80 03 03 14 04 9F 46 9F 48" "Record 3 SFI 2" || exit 1
echo "  Record 3 SFI 2 OK"

# Record 4, SFI 2 (ICC exponent, DDOL)
send_apdu "80 03 04 14 04 9F 47 9F 49" "Record 4 SFI 2" || exit 1
echo "  Record 4 SFI 2 OK"

# Record 1, SFI 3 (Card data)
send_apdu "80 03 01 1C 14 5F 24 00 5A 5F 34 9F 07 00 8E 9F 0D 9F 0E 9F 0F 5F 28 9F 4A" "Record 1 SFI 3" || exit 1
echo "  Record 1 SFI 3 OK"

# Record 2, SFI 3 (CDOL data)
send_apdu "80 03 02 1C 08 00 8C 00 8D 9F 08 9F 10" "Record 2 SFI 3" || exit 1
echo "  Record 2 SFI 3 OK"

echo ""
echo "================================================"
echo "Card Repersonalization Complete!"
echo "================================================"
echo ""
echo "IMPORTANT: You must also update the terminal CAPK!"
echo "The new CAPK modulus is 256 bytes (RSA-2048)."
echo ""
echo "New CAPK details:"
echo "  Index: 92"
echo "  RID: A000000951"
echo "  Modulus: $(xxd -p keys/capk/capk_modulus.bin | head -c 64)..."
echo "  Exponent: $(xxd -p keys/capk/capk_exponent.bin)"
echo ""
