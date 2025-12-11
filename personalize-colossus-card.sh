#!/bin/bash

# Colossus Card Personalization Script
# Personalizes a JavaCard with Colossus payment application (RSA-2048, CDA enabled)
#
# Usage: ./personalize-colossus-card.sh [OPTIONS]
#
# Requirements:
# - JavaCard with deployed paymentapp.cap
# - gp.jar (GlobalPlatformPro tool)
# - Card reader connected

set -e  # Exit on error

# Configuration
APPLET_AID="AFFFFFFFFF1234"  # Default from build.gradle
PAN="6767676712345678"        # Colossus BIN 67676767
CARDHOLDER_NAME="COLOSSUS/CARDHOLDER"
EXPIRY_DATE="251231"          # YYMMDD format
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

# Check if gp.jar exists
if [ ! -f "gp.jar" ]; then
    print_error "gp.jar not found. Run './gradlew downloadGp' first."
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

# Step 1: Factory Reset
print_info "Step 1: Factory Reset"
send_apdu "Factory reset" "80 05 00 00 00"
echo ""

# Step 2: Enable CDA Mode
print_info "Step 2: Enable CDA Mode (RSA-2048 required)"
send_apdu "Enable CDA" "80 00 00 07 01 01"
echo ""

# Step 3: Setup RSA-2048 Keys
print_info "Step 3: Loading RSA-2048 Keys (via APDU chaining)"

# RSA-2048 modulus from Rsa2048Test.java (256 bytes)
# Chunk 1 (128 bytes) - with chaining bit
send_apdu "RSA modulus chunk 1/2" \
"90 00 00 04 80 \
F2 11 62 23 50 48 40 5F 99 72 9D EA 3B 35 E9 C9 \
28 DD 15 B0 3E 24 13 2D 0B BF 61 FB 6C 0C 9B E0 \
8F 8C B8 1E F8 B4 A7 E3 B3 50 BD 76 F0 CF 1C B2 \
51 2F 0D 4D 08 E6 BE F2 BB 2B 51 7B 53 8D 4E 98 \
88 52 30 DE 9A B8 10 6D F9 FB 07 41 7D BC 0F 36 \
43 10 48 82 FA 07 33 84 E4 88 6B 07 FE 57 A7 5F \
E2 4E 30 BF 41 49 32 AF F5 A6 14 31 92 AA 14 93 \
17 99 18 1C 77 88 24 A1 53 ED 21 7E 26 0D 2D 89"

# Chunk 2 (128 bytes) - final
send_apdu "RSA modulus chunk 2/2" \
"80 00 00 04 80 \
09 10 24 AB 81 2E D6 63 99 11 45 A6 CD 43 92 56 \
5B DB B2 CB B1 E1 C9 88 40 2D 74 E6 80 C9 0F A7 \
C8 AB FC 65 F1 0A 4C AC 9B D0 11 59 05 79 EE 39 \
29 85 7B A9 D9 A3 16 CC 84 90 DE A9 35 2D 5D 39 \
9A A3 85 32 DC D1 FE 8B A4 C8 49 A1 7E CF 9F 0A \
31 59 7E 66 7C 92 3E BE AD B7 2B C2 49 CF 9C 77 \
75 73 7E E4 64 8C 60 D8 E3 63 F7 DB D6 A5 ED D7 \
18 55 C2 87 C7 1C F2 C0 C3 BD 62 BB 33 6C C2 FF"

# RSA-2048 private exponent (256 bytes)
# Chunk 1 (128 bytes) - with chaining bit
send_apdu "RSA exponent chunk 1/2" \
"90 00 00 05 80 \
A1 0B 41 17 35 30 2A 3F 66 4C 69 9C 28 23 9B 86 \
1B 93 0E 75 29 16 0C 1E 07 7F 41 A5 48 08 66 96 \
05 5D 7A 12 A5 78 71 95 76 34 7E 50 A0 88 12 76 \
35 1F 08 30 05 97 7D A1 7B 1B 34 50 36 5C 31 64 \
5B 36 20 93 66 7B 06 48 A6 A7 04 2B 52 7C 0A 24 \
2C 0D 31 54 A0 04 22 57 E4 5B 46 04 AA 3A 71 3F \
95 32 20 7A 27 0D 21 66 A1 4C 09 1C 61 72 0A 62 \
0F 66 10 12 50 5B 16 68 36 9E 14 53 17 08 1E 5C"

# Chunk 2 (128 bytes) - final
send_apdu "RSA exponent chunk 2/2" \
"80 00 00 05 80 \
06 0B 16 72 54 1F 8F 42 66 0B 2E 6F 88 2C 61 3A \
3C 92 76 88 76 94 86 5B 2B 1E 4E 99 54 86 0A 6F \
85 72 AA 43 A1 07 32 74 65 8D 0B 3C 03 53 99 26 \
1C 5B 52 75 96 6F 0F 88 5B 60 93 75 23 1E 3E 26 \
66 6F 5B 21 92 8D AA 5B 6B 85 30 68 51 88 66 07 \
20 3C 53 44 52 61 29 7D 72 78 1B 81 30 66 65 50 \
4F 4C 53 97 42 5C 40 91 96 42 A4 92 93 6F 99 8F \
0F 3B 81 5B 84 12 A1 80 82 7E 41 78 22 48 81 AA"

print_success "RSA-2048 keys loaded"
echo ""

# Step 4: Configure Settings
print_info "Step 4: Configure Settings"
send_apdu "Set PIN code" "80 00 00 01 02 12 34"
send_apdu "Use response template 77" "80 00 00 02 02 00 77"
echo ""

# Step 5: Setup Templates
print_info "Step 5: Setup Response Templates"
send_apdu "Template 1: GPO response" "80 02 00 01 04 00 82 00 94"
send_apdu "Template 2: DDA response" "80 02 00 02 02 9F 4B"
send_apdu "Template 3: GENERATE AC (CDA)" "80 02 00 03 0A 9F 27 9F 36 9F 26 9F 4B 9F 10"
echo ""

# Step 6: Setup Card Data
print_info "Step 6: Setup Card Data"
send_apdu "ATC (counter)" "80 01 9F 36 02 00 01"
send_apdu "AID (A0000000951)" "80 01 00 84 06 A0 00 00 00 09 51"
send_apdu "PAN" "80 01 00 5A 08 67 67 67 67 12 34 56 78"
send_apdu "Expiry date" "80 01 5F 24 03 25 12 31"
send_apdu "PAN sequence" "80 01 5F 34 01 01"
send_apdu "Application label" "80 01 00 50 08 43 4F 4C 4F 53 53 55 53"
send_apdu "Cardholder name" "80 01 5F 20 14 43 4F 4C 4F 53 53 55 53 2F 43 41 52 44 48 4F 4C 44 45 52 20"
echo ""

# Step 7: Setup AIP and AFL
print_info "Step 7: Setup AIP and AFL"
send_apdu "AIP (CDA supported)" "80 01 00 82 02 3C 01"
send_apdu "AFL" "80 01 00 94 0C 08 02 02 00 10 01 02 00 18 01 02 01"
echo ""

# Step 8: Setup Colossus CDOL
print_info "Step 8: Setup Colossus Custom CDOL Structure"
send_apdu "CDOL1" "80 01 00 8C 1E 9F 02 06 9F 03 06 9F 1A 02 95 05 5F 2A 02 9A 03 9C 01 9F 37 04 9F 1C 08 9F 16 0F 9F 01 06"
send_apdu "CDOL2" "80 01 00 8D 20 8A 02 9F 02 06 9F 03 06 9F 1A 02 95 05 5F 2A 02 9A 03 9C 01 9F 37 04 9F 1C 08 9F 16 0F 9F 01 06"
echo ""

# Step 9: Setup IAD
print_info "Step 9: Setup Issuer Application Data"
send_apdu "IAD" "80 01 9F 10 07 06 01 0A 03 A4 A0 02"
echo ""

print_success "========================================"
print_success "Card Personalization Complete!"
print_success "========================================"
print_info ""
print_info "Card Details:"
print_info "  Network: Colossus Credit"
print_info "  AID: A0000000951"
print_info "  PAN: $PAN"
print_info "  Expiry: 12/31/2025"
print_info "  Features: RSA-2048, CDA, Forced Online (ARQC)"
print_info ""
print_success "The card is now ready for use!"

