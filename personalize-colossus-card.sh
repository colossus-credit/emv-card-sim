#!/bin/bash

# Colossus Card Personalization Script
# Personalizes a JavaCard with Colossus payment application (RSA-1984, CDA enabled)
#
# Usage: ./personalize-colossus-card.sh [PAN]
#
# Arguments:
#   PAN (optional) - 16-digit PAN to use. If not provided, generates random PAN with Colossus BIN
#
# Examples:
#   ./personalize-colossus-card.sh                    # Auto-generate random PAN
#   ./personalize-colossus-card.sh 6767676712345674   # Use specific PAN
#
# Requirements:
# - JavaCard with deployed paymentapp.cap
# - gp.jar (GlobalPlatformPro tool)
# - Card reader connected

set -e  # Exit on error

# Configuration
APPLET_AID="A0000009510001"  # Colossus AID - must match deployed applet
PSE_AID="315041592E5359532E4444463031"  # 1PAY.SYS.DDF01 in hex
CARDHOLDER_NAME="COLOSSUS/CARDHOLDER"
EXPIRY_DATE="271231"          # YYMMDD format
PIN_CODE="1234"               # Optional PIN

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

# Luhn checksum calculation (for generating check digit)
calculate_luhn() {
    local number="$1"
    local sum=0
    local length=${#number}
    
    # Process from right to left, double every second digit
    for ((i=length-1; i>=0; i--)); do
        digit=${number:$i:1}
        position=$(( (length - 1 - i) % 2 ))
        
        if [ $position -eq 0 ]; then
            # Double this digit (it's at odd position from right)
            digit=$(( digit * 2 ))
            if [ $digit -gt 9 ]; then
                digit=$(( digit - 9 ))
            fi
        fi
        
        sum=$(( sum + digit ))
    done
    
    checksum=$(( (10 - (sum % 10)) % 10 ))
    echo $checksum
}

# Verify Luhn checksum (for complete PAN)
verify_luhn() {
    local number="$1"
    local sum=0
    local length=${#number}
    
    # Process from right to left, double every second digit starting from second-to-last
    for ((i=length-1; i>=0; i--)); do
        digit=${number:$i:1}
        position=$(( (length - 1 - i) % 2 ))
        
        if [ $position -eq 1 ]; then
            # Double this digit (it's at even position from right, but not rightmost)
            digit=$(( digit * 2 ))
            if [ $digit -gt 9 ]; then
                digit=$(( digit - 9 ))
            fi
        fi
        
        sum=$(( sum + digit ))
    done
    
    [ $(( sum % 10 )) -eq 0 ]
}

# Generate random digits
generate_random_digits() {
    local count=$1
    local result=""
    for ((i=0; i<count; i++)); do
        result="${result}$(( RANDOM % 10 ))"
    done
    echo "$result"
}

# Generate random 16-digit PAN with Colossus BIN
generate_random_pan() {
    local bin="67676767"  # Colossus BIN
    local account=$(generate_random_digits 7)
    local base="${bin}${account}"
    local checksum=$(calculate_luhn "$base")
    echo "${base}${checksum}"
}

# Function to send APDU via gp.jar
send_apdu() {
    local description="$1"
    local apdu="$2"
    local expected_sw="${3:-9000}"
    
    print_info "$description"
    
    # Remove spaces and newlines from APDU for gp.jar
    apdu_clean=$(echo "$apdu" | tr -d ' \n')
    
    # Send APDU with debug flag to see response
    output=$(java -jar gp.jar --applet "$APPLET_AID" --apdu "${apdu_clean}" -d 2>&1)
    
    # Extract response SW from "A<<" line (format: "A<< (0000+2) (76ms) 9000")
    response_sw=$(echo "$output" | grep "A<<" | tail -1 | grep -oE '[0-9A-F]{4}$')
    
    if [ -z "$response_sw" ]; then
        print_error "✗ No response received"
        echo "$output" | head -5
        return 1
    elif [ "$response_sw" = "$expected_sw" ]; then
        print_success "✓ $expected_sw"
        return 0
    else
        print_error "✗ Got $response_sw, expected $expected_sw"
        return 1
    fi
}

# Function to send APDU to PSE applet
send_apdu_pse() {
    local description="$1"
    local apdu="$2"
    local expected_sw="${3:-9000}"

    print_info "$description"

    # Remove spaces and newlines from APDU for gp.jar
    apdu_clean=$(echo "$apdu" | tr -d ' \n')

    # Send APDU to PSE applet
    output=$(java -jar gp.jar --applet "$PSE_AID" --apdu "${apdu_clean}" -d 2>&1)

    # Extract response SW from "A<<" line
    response_sw=$(echo "$output" | grep "A<<" | tail -1 | grep -oE '[0-9A-F]{4}$')

    if [ -z "$response_sw" ]; then
        print_error "✗ No response received"
        echo "$output" | head -5
        return 1
    elif [ "$response_sw" = "$expected_sw" ]; then
        print_success "✓ $expected_sw"
        return 0
    else
        print_error "✗ Got $response_sw, expected $expected_sw"
        return 1
    fi
}

# Parse PAN parameter or generate random
if [ -n "$1" ]; then
    # PAN provided as parameter
    PAN="$1"
    # Remove spaces and validate
    PAN=$(echo "$PAN" | tr -d ' -')
    
    # Validate PAN length
    if [ ${#PAN} -lt 8 ] || [ ${#PAN} -gt 19 ]; then
        print_error "Invalid PAN length: ${#PAN}. Must be 8-19 digits."
        exit 1
    fi
    
    # Validate PAN is numeric
    if ! [[ "$PAN" =~ ^[0-9]+$ ]]; then
        print_error "Invalid PAN: must contain only digits"
        exit 1
    fi
    
    # Verify Luhn checksum
    if ! verify_luhn "$PAN"; then
        print_error "Invalid PAN: Luhn checksum failed"
        exit 1
    fi
    
    print_info "Using provided PAN: $PAN"
else
    # Generate random PAN
    PAN=$(generate_random_pan)
    print_success "Generated random PAN: $PAN"
fi

# Check if gp.jar exists
if [ ! -f "gp.jar" ]; then
    print_error "gp.jar not found. Run './gradlew downloadGp' first."
    exit 1
fi

# Check for issuer key (required for PAN signing)
ISSUER_KEY="./keys/issuer/issuer_private.pem"
if [ ! -f "$ISSUER_KEY" ]; then
    print_error "Issuer private key not found at $ISSUER_KEY"
    print_error "Run './generate-issuer-cert.sh' first to create issuer keys."
    exit 1
fi

print_info "========================================"
print_info "Colossus Card Personalization Script"
print_info "========================================"
print_info "Applet AID: $APPLET_AID"
print_info "PAN: $PAN"
print_info "Cardholder: $CARDHOLDER_NAME"
print_info "Expiry: $EXPIRY_DATE"
print_info "========================================"
echo ""

# Step 0: Generate ICC certificate with correct PAN
print_info "Step 0: Generating ICC Certificate for PAN $PAN"
if ./generate-icc-cert.sh "$ISSUER_KEY" "$PAN" "./keys/icc" > /dev/null 2>&1; then
    print_success "ICC certificate generated with PAN $PAN"
else
    print_error "Failed to generate ICC certificate"
    print_info "Trying with verbose output..."
    ./generate-icc-cert.sh "$ISSUER_KEY" "$PAN" "./keys/icc"
    exit 1
fi
echo ""

# Step 1: Factory Reset (both applets)
print_info "Step 1: Factory Reset"
send_apdu "Factory reset (Colossus)" "80 05 00 00 00"
send_apdu_pse "Factory reset (PSE)" "80 05 00 00 00"
echo ""

# Step 1b: Configure PSE (Payment System Environment)
print_info "Step 1b: Configure PSE for Colossus"
# PSE needs to return proper FCI and directory entry containing Colossus AID

# PSE AID (tag 84) = 1PAY.SYS.DDF01 (14 bytes)
send_apdu_pse "PSE AID (84)" "80 01 00 84 0E 31 50 41 59 2E 53 59 53 2E 44 44 46 30 31"

# PSE SFI of Directory (tag 88) = 01
send_apdu_pse "PSE SFI (88)" "80 01 00 88 01 01"

# PSE Language Preference (tag 5F2D) = "en"
send_apdu_pse "PSE Language (5F2D)" "80 01 5F 2D 02 65 6E"

# PSE FCI templates
# Template 5: A5 = tag 88 (SFI of Directory)
send_apdu_pse "PSE Template A5" "80 02 00 05 02 00 88"

# Template 4: 6F = tags 84 (DF Name) + A5 (FCI Proprietary)
send_apdu_pse "PSE Template 6F" "80 02 00 04 04 00 84 00 A5"

# PSE READ RECORD template for SFI 1, Record 1 (P1P2=0104)
# Contains directory entry with Colossus AID
# We'll store the directory entry as raw data using a tag template

# Directory Entry (tag 61) containing:
#   4F (ADF Name) = A0 00 00 09 51 00 01 (7 bytes)
#   50 (Application Label) = "COLOSSUS" (8 bytes)
#   87 (Application Priority) = 01
# Format: 61 16 4F 07 A0 00 00 09 51 00 01 50 08 43 4F 4C 4F 53 53 55 53 87 01 01
# Total 22 bytes (0x16): 4F(9) + 50(10) + 87(3)
send_apdu_pse "PSE Directory Entry (61)" "80 01 00 61 16 4F 07 A0 00 00 09 51 00 01 50 08 43 4F 4C 4F 53 53 55 53 87 01 01"

# PSE READ RECORD template for SFI1 Rec1 (P1P2=010C): returns full directory entry TLV
# PSE uses copyDataToArray (raw copy), not expandTlvToArray, so we must include full TLV data
send_apdu_pse "PSE Record Template" "80 03 01 0C 18 61 16 4F 07 A0 00 00 09 51 00 01 50 08 43 4F 4C 4F 53 53 55 53 87 01 01"

echo ""

# Step 2: Enable Random Mode (CDA/DDA enabled automatically when RSA keys are loaded)
print_info "Step 2: Configure Flags (enable random mode)"
# FLAGS setting (0x0003): bit 0 = useRandom (1=enabled)
send_apdu "Enable random mode" "80 00 00 03 02 00 01"
echo ""

# Step 3: Setup RSA-1984 Keys (loaded from generated ICC key files)
print_info "Step 3: Loading RSA-1984 Keys from ./keys/icc/"

# Read ICC modulus from generated file
ICC_MODULUS_FILE="./keys/icc/icc_modulus.bin"
if [ ! -f "$ICC_MODULUS_FILE" ]; then
    print_error "ICC modulus file not found: $ICC_MODULUS_FILE"
    exit 1
fi

# Read ICC private exponent from generated file (extract from PEM)
ICC_PRIVATE_FILE="./keys/icc/icc_private.pem"
if [ ! -f "$ICC_PRIVATE_FILE" ]; then
    print_error "ICC private key file not found: $ICC_PRIVATE_FILE"
    exit 1
fi

# Convert modulus to hex (RSA-1984 = 248 bytes fits in single APDU)
ICC_MODULUS_HEX=$(xxd -p "$ICC_MODULUS_FILE" | tr -d '\n' | tr 'a-f' 'A-F')
ICC_MODULUS_LEN=$((${#ICC_MODULUS_HEX} / 2))
ICC_MODULUS_LEN_HEX=$(printf '%02X' $ICC_MODULUS_LEN)
ICC_MODULUS_SPACED=$(echo "$ICC_MODULUS_HEX" | sed 's/../& /g' | sed 's/ $//')

# Extract private exponent from PEM (RSA-1984 = 248 bytes)
ICC_EXPONENT_HEX=$(openssl rsa -in "$ICC_PRIVATE_FILE" -text -noout 2>/dev/null | \
    sed -n '/privateExponent:/,/prime1:/p' | \
    grep -E '^\s+[0-9a-f:]+' | \
    tr -d ' \n:' | \
    tr 'a-f' 'A-F' | \
    sed 's/^00//')

# Pad exponent to 248 bytes (496 hex chars) if needed
while [ ${#ICC_EXPONENT_HEX} -lt 496 ]; do
    ICC_EXPONENT_HEX="00${ICC_EXPONENT_HEX}"
done

ICC_EXPONENT_LEN=$((${#ICC_EXPONENT_HEX} / 2))
ICC_EXPONENT_LEN_HEX=$(printf '%02X' $ICC_EXPONENT_LEN)
ICC_EXPONENT_SPACED=$(echo "$ICC_EXPONENT_HEX" | sed 's/../& /g' | sed 's/ $//')

# Load modulus in single APDU (RSA-1984 = 248 bytes fits in standard APDU)
send_apdu "RSA modulus (248 bytes)" "80 00 00 04 $ICC_MODULUS_LEN_HEX $ICC_MODULUS_SPACED"

# Load private exponent in single APDU
send_apdu "RSA exponent (248 bytes)" "80 00 00 05 $ICC_EXPONENT_LEN_HEX $ICC_EXPONENT_SPACED"

print_success "RSA-1984 keys loaded from generated files"
echo ""

# Step 4: Load Certificate Chain for CDA
print_info "Step 4: Loading Certificate Chain (CDA)"

# CA Public Key Index (tag 8F) - indicates which CAPK to use (0x92)
send_apdu "CA Public Key Index (8F)" "80 01 00 8F 01 92"

# Issuer Public Key Exponent (tag 9F32) - exponent 3
send_apdu "Issuer PK Exponent (9F32)" "80 01 9F 32 01 03"

# Read Issuer certificate from generated file
ISSUER_CERT_FILE="./keys/issuer/issuer_certificate.bin"
ISSUER_REM_FILE="./keys/issuer/issuer_remainder.bin"
if [ ! -f "$ISSUER_CERT_FILE" ]; then
    print_error "Issuer certificate not found: $ISSUER_CERT_FILE"
    exit 1
fi

ISSUER_CERT_HEX=$(xxd -p "$ISSUER_CERT_FILE" | tr -d '\n' | tr 'a-f' 'A-F' | sed 's/../& /g' | sed 's/ $//')
ISSUER_CERT_LEN=$(stat -f%z "$ISSUER_CERT_FILE" 2>/dev/null || stat -c%s "$ISSUER_CERT_FILE")
ISSUER_CERT_LEN_HEX=$(printf '%02X' $ISSUER_CERT_LEN)

# Issuer Public Key Certificate (tag 90) - 248 bytes in single APDU (read from file)
send_apdu "Issuer PK Cert (90)" "80 01 00 90 $ISSUER_CERT_LEN_HEX $ISSUER_CERT_HEX"

# Issuer Public Key Remainder (tag 92) - read from file
if [ -f "$ISSUER_REM_FILE" ] && [ -s "$ISSUER_REM_FILE" ]; then
    ISSUER_REM_HEX=$(xxd -p "$ISSUER_REM_FILE" | tr -d '\n' | tr 'a-f' 'A-F' | sed 's/../& /g' | sed 's/ $//')
    ISSUER_REM_LEN=$(stat -f%z "$ISSUER_REM_FILE" 2>/dev/null || stat -c%s "$ISSUER_REM_FILE")
    ISSUER_REM_LEN_HEX=$(printf '%02X' $ISSUER_REM_LEN)
    send_apdu "Issuer PK Remainder (92)" "80 01 00 92 $ISSUER_REM_LEN_HEX $ISSUER_REM_HEX"
fi

# ICC Public Key Exponent (tag 9F47) - exponent 3
send_apdu "ICC PK Exponent (9F47)" "80 01 9F 47 01 03"

# Read ICC certificate from generated file
ICC_CERT_FILE="./keys/icc/icc_certificate.bin"
ICC_REM_FILE="./keys/icc/icc_remainder.bin"
if [ ! -f "$ICC_CERT_FILE" ]; then
    print_error "ICC certificate not found: $ICC_CERT_FILE"
    exit 1
fi

ICC_CERT_HEX=$(xxd -p "$ICC_CERT_FILE" | tr -d '\n' | tr 'a-f' 'A-F' | sed 's/../& /g' | sed 's/ $//')
ICC_CERT_LEN=$(stat -f%z "$ICC_CERT_FILE" 2>/dev/null || stat -c%s "$ICC_CERT_FILE")
ICC_CERT_LEN_HEX=$(printf '%02X' $ICC_CERT_LEN)

# ICC Public Key Certificate (tag 9F46) - read from file
send_apdu "ICC PK Cert (9F46)" "80 01 9F 46 $ICC_CERT_LEN_HEX $ICC_CERT_HEX"

# ICC Public Key Remainder (tag 9F48) - read from file
if [ -f "$ICC_REM_FILE" ] && [ -s "$ICC_REM_FILE" ]; then
    ICC_REM_HEX=$(xxd -p "$ICC_REM_FILE" | tr -d '\n' | tr 'a-f' 'A-F' | sed 's/../& /g' | sed 's/ $//')
    ICC_REM_LEN=$(stat -f%z "$ICC_REM_FILE" 2>/dev/null || stat -c%s "$ICC_REM_FILE")
    ICC_REM_LEN_HEX=$(printf '%02X' $ICC_REM_LEN)
    send_apdu "ICC PK Remainder (9F48)" "80 01 9F 48 $ICC_REM_LEN_HEX $ICC_REM_HEX"
fi

print_success "Certificate chain loaded"
echo ""

# Step 5: Configure Settings
print_info "Step 5: Configure Settings"
send_apdu "Set PIN code" "80 00 00 01 02 12 34"
send_apdu "Use response template 77" "80 00 00 02 02 00 77"
echo ""

# Step 6: Setup Templates
print_info "Step 6: Setup Response Templates"
send_apdu "Template 1: GPO response" "80 02 00 01 04 00 82 00 94"
send_apdu "Template 2: DDA response" "80 02 00 02 02 9F 4B"
send_apdu "Template 3: GENERATE AC (CDA enabled)" "80 02 00 03 0A 9F 27 9F 36 9F 26 9F 10 9F 4B"
# FCI Templates for SELECT response
send_apdu "Template 5: A5 FCI Proprietary" "80 02 00 05 04 00 50 00 87"
send_apdu "Template 4: 6F FCI Template" "80 02 00 04 04 00 84 00 A5"
echo ""

# Step 6b: Setup READ RECORD Templates (Visa-like structure)
# AFL: 08 02 02 00 10 01 05 01 18 01 03 00
# SFI 1 (08), Record 2, 0 ODA: Track2, Cardholder
# SFI 2 (10), Records 1-5, 1 ODA: ODA certificates
# SFI 3 (18), Records 1-3, 0 ODA: PAN, Expiry, CDOL, CVM, IACs
print_info "Step 6b: Setup READ RECORD Templates"
# SFI 1, Record 2 (P1P2=020C): Track2 + Cardholder only (like Visa)
send_apdu "Record SFI1 Rec2: Track2/Cardholder" "80 03 02 0C 04 00 57 5F 20"
# SFI 2, Record 1 (P1P2=0114): CA PK Index + Issuer Exp + SDA tag list
send_apdu "Record SFI2 Rec1: CAPK/Exp/9F4A" "80 03 01 14 06 00 8F 9F 32 9F 4A"
# SFI 2, Record 2 (P1P2=0214): Issuer certificate only
send_apdu "Record SFI2 Rec2: Issuer cert" "80 03 02 14 02 00 90"
# SFI 2, Record 3 (P1P2=0314): Issuer remainder only
send_apdu "Record SFI2 Rec3: Issuer rem" "80 03 03 14 02 00 92"
# SFI 2, Record 4 (P1P2=0414): ICC certificate only
send_apdu "Record SFI2 Rec4: ICC cert" "80 03 04 14 02 9F 46"
# SFI 2, Record 5 (P1P2=0514): ICC exponent + remainder
send_apdu "Record SFI2 Rec5: ICC exp+rem" "80 03 05 14 04 9F 47 9F 48"
# SFI 3, Record 1 (P1P2=011C): PAN, Expiry, Effective, Country, PAN Seq, AUC, IACs, Version (like Visa)
send_apdu "Record SFI3 Rec1: PAN/Expiry/IACs" "80 03 01 1C 14 00 5A 5F 24 5F 25 5F 28 5F 34 9F 07 9F 0D 9F 0E 9F 0F 9F 08"
# SFI 3, Record 2 (P1P2=021C): CDOL1, CDOL2, CVM List
send_apdu "Record SFI3 Rec2: CDOL/CVM" "80 03 02 1C 06 00 8C 00 8D 00 8E"
# SFI 3, Record 3 (P1P2=031C): AIP, AFL, ATC, IAD
send_apdu "Record SFI3 Rec3: AIP/AFL/ATC/IAD" "80 03 03 1C 08 00 82 00 94 9F 36 9F 10"
echo ""

# Step 7: Setup Card Data (using individual send_apdu calls like working Visa script)
print_info "Step 7: Setup Card Data"

send_apdu "ATC (counter)" "80 01 9F 36 02 00 01"
send_apdu "AID (A0000009510001)" "80 01 00 84 07 A0 00 00 09 51 00 01"

# Format PAN for APDU (BCD encoding: 2 digits = 1 byte)
pan_formatted=$(echo "$PAN" | sed 's/../& /g' | sed 's/ $//')
pan_byte_length=$(( ${#PAN} / 2 ))
pan_length=$(printf '%02X' $pan_byte_length)
send_apdu "PAN ($PAN)" "80 01 00 5A $pan_length $pan_formatted"

send_apdu "Expiry date (2027-12-31)" "80 01 5F 24 03 27 12 31"
send_apdu "PAN sequence" "80 01 5F 34 01 01"

# Track 2 equivalent data: PAN D YYMM SERVICE_CODE DISCRETIONARY F-padded
track2_raw="${PAN}D2712201"
track2_padded=$(printf "%-37s" "$track2_raw" | tr ' ' '0')
track2_padded="${track2_padded}F"
track2_formatted=$(echo "$track2_padded" | sed 's/../& /g' | sed 's/ $//')
send_apdu "Track 2 Equivalent" "80 01 00 57 13 $track2_formatted"

send_apdu "Application label" "80 01 00 50 08 43 4F 4C 4F 53 53 55 53"
send_apdu "Application Priority Indicator" "80 01 00 87 01 01"
send_apdu "Cardholder name" "80 01 5F 20 14 43 4F 4C 4F 53 53 55 53 2F 43 41 52 44 48 4F 4C 44 45 52 20"
send_apdu "Application Version Number (9F08)" "80 01 9F 08 02 00 01"
send_apdu "Application Effective Date (5F25)" "80 01 5F 25 03 24 01 01"
send_apdu "Issuer Country Code (5F28)" "80 01 5F 28 02 08 40"
send_apdu "Application Usage Control (9F07)" "80 01 9F 07 02 FF 00"
echo ""

# Step 8: Setup AIP and AFL
print_info "Step 8: Setup AIP and AFL"
send_apdu "AIP (DDA+CDA supported)" "80 01 00 82 02 3D 01"
send_apdu "AFL" "80 01 00 94 0C 08 02 02 00 10 01 05 01 18 01 03 00"
send_apdu "Static Data Auth Tag List (9F4A)" "80 01 9F 4A 01 82"
echo ""

# Step 9: Setup Colossus CDOL
print_info "Step 9: Setup Colossus Custom CDOL Structure"
send_apdu "CDOL1" "80 01 00 8C 1E 9F 02 06 9F 03 06 9F 1A 02 95 05 5F 2A 02 9A 03 9C 01 9F 37 04 9F 1C 08 9F 16 0F 9F 01 06"
send_apdu "CDOL2" "80 01 00 8D 20 8A 02 9F 02 06 9F 03 06 9F 1A 02 95 05 5F 2A 02 9A 03 9C 01 9F 37 04 9F 1C 08 9F 16 0F 9F 01 06"
# CVM List: No CVM required (Amount X=0, Amount Y=0, Rule=1F00 "No CVM")
send_apdu "CVM List (No CVM required)" "80 01 00 8E 0A 00 00 00 00 00 00 00 00 1F 00"

# Issuer Action Codes - Use realistic values similar to Visa
# IAC-Default (9F0D): FC 68 8C 98 00 - Standard default action code
send_apdu "IAC-Default" "80 01 9F 0D 05 FC 68 8C 98 00"
# IAC-Denial (9F0E): 00 10 00 00 00 - Deny if service not allowed
send_apdu "IAC-Denial" "80 01 9F 0E 05 00 10 00 00 00"
# IAC-Online (9F0F): FC 68 8C F8 00 - Go online for these conditions
send_apdu "IAC-Online" "80 01 9F 0F 05 FC 68 8C F8 00"
echo ""

# Step 10: Setup IAD
print_info "Step 10: Setup Issuer Application Data"
send_apdu "IAD" "80 01 9F 10 07 06 01 0A 03 A4 A0 02"
echo ""

print_success "========================================"
print_success "Card Personalization Complete!"
print_success "========================================"
print_info ""
print_info "Card Details:"
print_info "  Network: Colossus Credit"
print_info "  AID: A0000009510001"
print_info "  PSE: 1PAY.SYS.DDF01 (configured)"
print_info "  PAN: $PAN"
print_info "  Expiry: 12/31/2027"
print_info "  Features: RSA-1984, DDA+CDA, Offline Data Authentication"
print_info ""
print_success "The card is now ready for use!"
print_info ""
print_info "Note: Both PSE and Colossus applets must be installed on the card."
print_info "If you see errors, run: java -jar gp.jar --list to verify applets."

