#!/bin/bash
# Diagnostic script to verify card data storage

APPLET_AID="A0000009510001"

RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

print_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
print_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
print_error() { echo -e "${RED}[ERROR]${NC} $1"; }
print_warning() { echo -e "${YELLOW}[WARNING]${NC} $1"; }

echo ""
print_info "========================================"
print_info "Card Data Diagnostic Tool"
print_info "========================================"
echo ""

# Test 1: List installed applets
print_info "Test 1: List installed applets on card..."
java -jar gp.jar -l 2>&1 | grep -E "AID|APP"
echo ""

# Test 2: SELECT the Colossus applet and show full response
print_info "Test 2: SELECT Colossus applet (A0000009510001)..."
echo "Full gp.jar output:"
java -jar gp.jar --applet "$APPLET_AID" -d -a "00A4040007A0000009510001" 2>&1 | grep -E "A>>|A<<"
echo ""

# Test 3: Send GPO and READ RECORD in single session
print_info "Test 3: Full transaction simulation (GPO + READ RECORD)..."
echo ""
print_info "Sending: SELECT, GPO, READ RECORD SFI1 Rec2, READ RECORD SFI2 Rec1"
echo ""

output=$(java -jar gp.jar --applet "$APPLET_AID" -d \
    -a "80A8000002830000" \
    -a "00B2020C00" \
    -a "00B2011400" \
    2>&1)

echo "All APDU exchanges:"
echo "$output" | grep -E "A>>|A<<" | while read line; do
    echo "  $line"
done
echo ""

# Test 4: Check for zeros in READ RECORD responses
print_info "Test 4: Analyzing responses for zero patterns..."
echo ""

# Extract just the READ RECORD responses (skip first response which is GPO)
read_record_responses=$(echo "$output" | grep "A<<" | tail -2)

echo "READ RECORD responses:"
echo "$read_record_responses" | while read line; do
    echo "  $line"
    # Check for 8 consecutive zero bytes (typical pattern for zeroed PAN)
    if echo "$line" | grep -qE "00 ?00 ?00 ?00 ?00 ?00 ?00 ?00|0000000000000000"; then
        print_error "  ^ Contains suspicious zero pattern!"
    fi
done
echo ""

# Test 5: Detailed record dump
print_info "Test 5: Detailed READ RECORD for SFI 1 Record 2 (should contain PAN)..."
echo ""
output=$(java -jar gp.jar --applet "$APPLET_AID" -d -a "00B2020C00" 2>&1)
echo "Command: 00 B2 02 0C 00 (READ RECORD SFI=1 Record=2)"
echo "$output" | grep -E "A>>|A<<"
echo ""

# Parse the response to show tag breakdown
response_data=$(echo "$output" | grep "A<<" | grep -oE '[0-9A-Fa-f ]+9000' | head -1 | sed 's/9000$//')
if [ -n "$response_data" ]; then
    print_info "Response data breakdown:"
    echo "  Raw: $response_data"

    # Check for tag 70 (Record Template)
    if echo "$response_data" | grep -qi "^70"; then
        print_success "Response starts with tag 70 (Record Template) - correct format"
    elif echo "$response_data" | grep -qi "^6F"; then
        print_warning "Response starts with tag 6F (FCI) - this is SELECT response, not READ RECORD!"
    fi
fi

echo ""
print_info "========================================"
print_info "Diagnosis complete"
print_info "========================================"
