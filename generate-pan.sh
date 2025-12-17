#!/bin/bash

# Generate Random PAN with Luhn Checksum
# Supports Colossus BIN (42069420) and custom formats
#
# Usage:
#   ./generate-pan.sh [length] [prefix]
#
# Examples:
#   ./generate-pan.sh 8              # Random 8-digit PAN
#   ./generate-pan.sh 16             # 16-digit PAN with Colossus BIN (42069420)
#   ./generate-pan.sh 16 12345678    # 16-digit PAN with custom BIN
#   ./generate-pan.sh 12 4111        # 12-digit PAN starting with 4111

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
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

# Format PAN with spaces for readability
format_pan() {
    local pan="$1"
    echo "$pan" | sed 's/\(....\)/\1 /g' | sed 's/ $//'
}

# Show help if requested
if [ "$1" = "-h" ] || [ "$1" = "--help" ]; then
    echo "Generate Random PAN with Luhn Checksum"
    echo ""
    echo "Usage:"
    echo "  ./generate-pan.sh [length] [prefix]"
    echo ""
    echo "Examples:"
    echo "  ./generate-pan.sh                # 16-digit PAN with Colossus BIN (default)"
    echo "  ./generate-pan.sh 8              # Random 8-digit PAN"
    echo "  ./generate-pan.sh 16             # 16-digit PAN with Colossus BIN (42069420)"
    echo "  ./generate-pan.sh 16 12345678    # 16-digit PAN with custom BIN"
    echo "  ./generate-pan.sh 12 4111        # 12-digit PAN starting with 4111"
    echo ""
    echo "Default: 16-digit PAN with Colossus BIN (42069420)"
    exit 0
fi

# Parse arguments
MODE="${1:-16}"  # Default: 16-digit PAN
CUSTOM_PREFIX="${2:-}"

case "$MODE" in
    8)
        # Generate 8-digit PAN (7 digits + Luhn)
        if [ -n "$CUSTOM_PREFIX" ]; then
            # Use custom prefix
            prefix="$CUSTOM_PREFIX"
            needed=$(( 7 - ${#prefix} ))
            if [ $needed -lt 0 ]; then
                print_info "Prefix too long, truncating to 7 digits"
                prefix="${prefix:0:7}"
                needed=0
            fi
        else
            # Random 7 digits
            prefix=$(generate_random_digits 7)
            needed=0
        fi
        
        if [ $needed -gt 0 ]; then
            prefix="${prefix}$(generate_random_digits $needed)"
        fi
        
        checksum=$(calculate_luhn "$prefix")
        pan="${prefix}${checksum}"
        ;;
        
    16)
        # Generate 16-digit PAN with Colossus BIN (8 + 7 + 1 Luhn)
        BIN="42069420"  # Colossus BIN
        
        if [ -n "$CUSTOM_PREFIX" ]; then
            # Override BIN
            BIN="$CUSTOM_PREFIX"
        fi
        
        # Generate 7 random account digits
        account=$(generate_random_digits 7)
        
        # Calculate Luhn checksum
        base="${BIN}${account}"
        checksum=$(calculate_luhn "$base")
        pan="${base}${checksum}"
        ;;
        
    *)
        # Custom length
        length=$MODE
        if [ "$length" -lt 8 ] || [ "$length" -gt 19 ]; then
            echo "Error: PAN length must be between 8 and 19 digits"
            exit 1
        fi
        
        prefix="${CUSTOM_PREFIX}"
        needed=$(( length - 1 - ${#prefix} ))
        
        if [ $needed -lt 0 ]; then
            echo "Error: Prefix too long for requested length"
            exit 1
        fi
        
        if [ $needed -gt 0 ]; then
            prefix="${prefix}$(generate_random_digits $needed)"
        fi
        
        checksum=$(calculate_luhn "$prefix")
        pan="${prefix}${checksum}"
        ;;
esac

# Output
echo ""
print_success "Generated PAN: $(format_pan $pan)"
echo ""
print_info "PAN Details:"
echo "  Raw:      $pan"
echo "  Length:   ${#pan} digits"
if [ "$MODE" = "16" ] && [ -z "$CUSTOM_PREFIX" ]; then
    echo "  BIN:      42069420 (Colossus)"
    echo "  Account:  ${pan:8:7}"
    echo "  Checksum: ${pan:15:1}"
elif [ "$MODE" = "16" ]; then
    echo "  BIN:      ${pan:0:8}"
    echo "  Account:  ${pan:8:7}"
    echo "  Checksum: ${pan:15:1}"
else
    echo "  Number:   ${pan:0:$((${#pan}-1))}"
    echo "  Checksum: ${pan:$((${#pan}-1)):1}"
fi
echo ""

# Verify Luhn
if verify_luhn "$pan"; then
    print_success "✓ Luhn checksum valid"
else
    echo -e "${RED}✗ Luhn checksum invalid${NC}"
    exit 1
fi

# Show APDU command for personalization
echo ""
print_info "To set this PAN on your card, run:"
echo ""
# Format PAN as hex with spaces between bytes
pan_hex=$(echo "$pan" | sed 's/../& /g' | sed 's/ $//')
echo "  java -jar gp.jar --applet AFFFFFFFFF1234 --apdu \"80 01 00 5A $(printf '%02X' ${#pan}) $pan_hex\""
echo ""
print_info "Or update personalize-colossus-card.sh with this PAN"
echo ""

