#!/bin/bash

# Generate CAPK (Certificate Authority Public Key) for Colossus Network
# Creates the root Certificate Authority keys for the EMV certificate chain
#
# Usage:
#   ./generate-capk.sh [ca_index] [output_dir]
#
# Arguments:
#   ca_index   - CA index (default: 92, must be 2-digit hex)
#   output_dir - Output directory for CAPK keys (default: ./keys/capk)
#
# Examples:
#   ./generate-capk.sh
#   ./generate-capk.sh 92
#   ./generate-capk.sh 92 ./keys/capk
#
# Outputs:
#   - capk_private.pem      - CAPK private key (KEEP SECURE!)
#   - capk_public.pem       - CAPK public key in PEM format
#   - capk_modulus.bin      - Raw modulus (248 bytes)
#   - capk_exponent.bin     - Raw exponent
#   - capk_info.txt         - Key details
#   - capk_config.yaml      - YAML configuration for card setup

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
NC='\033[0m'

print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_header() {
    echo -e "${CYAN}$1${NC}"
}

print_step() {
    echo -e "${MAGENTA}[STEP]${NC} $1"
}

# Show help
if [ "$1" = "-h" ] || [ "$1" = "--help" ]; then
    echo "Generate CAPK (Certificate Authority Public Key) for Colossus Network"
    echo ""
    echo "Usage:"
    echo "  ./generate-capk.sh [ca_index] [output_dir]"
    echo ""
    echo "Arguments:"
    echo "  ca_index   - CA index (default: 92, 2-digit hex)"
    echo "  output_dir - Output directory (default: ./keys/capk)"
    echo ""
    echo "Examples:"
    echo "  ./generate-capk.sh"
    echo "  ./generate-capk.sh 92"
    echo "  ./generate-capk.sh 92 ./keys/capk"
    echo ""
    echo "Output Files:"
    echo "  capk_private.pem      - CAPK private key (KEEP SECURE!)"
    echo "  capk_public.pem       - CAPK public key"
    echo "  capk_modulus.bin      - Raw 256-byte modulus"
    echo "  capk_exponent.bin     - Raw exponent"
    echo "  capk_info.txt         - Key details and information"
    echo "  capk_config.yaml      - YAML configuration for card setup"
    echo ""
    echo "Prerequisites:"
    echo "  - OpenSSL installed"
    echo ""
    exit 0
fi

# Parse arguments
CA_INDEX="${1:-92}"
OUTPUT_DIR="${2:-./keys/capk}"

# Validate CA index
if ! [[ "$CA_INDEX" =~ ^[0-9A-Fa-f]{1,2}$ ]]; then
    print_error "Invalid CA index: $CA_INDEX (must be 1-2 hex digits)"
    exit 1
fi

# Ensure CA index is 2 digits
CA_INDEX=$(printf "%02X" $((16#$CA_INDEX)))

# Configuration
# NOTE: Using RSA-1984 (248 bytes) because:
# 1. Verifone SDK supports max 248 bytes for CAPK modulus
# 2. Original EmvTag code supports max 255 bytes
# 3. Standard APDU LC field supports max 255 bytes without extended APDU
KEY_SIZE=1984
EXPONENT=3  # Standard EMV exponent
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

# Create output directory
mkdir -p "$OUTPUT_DIR"

# Show banner
echo ""
print_header "═══════════════════════════════════════════════════════════"
print_header "  Colossus CAPK Generator (RSA-1984)"
print_header "═══════════════════════════════════════════════════════════"
echo ""

print_info "Configuration:"
echo "  CA Index:       0x$CA_INDEX"
echo "  Key Size:       RSA-$KEY_SIZE"
echo "  Public Exp:     $EXPONENT (0x$(printf '%02X' $EXPONENT))"
echo "  Output Dir:     $OUTPUT_DIR"
echo ""

# Check for OpenSSL
if ! command -v openssl &> /dev/null; then
    print_error "OpenSSL not found. Please install OpenSSL."
    exit 1
fi

# Define output files
CAPK_PRIVATE_KEY="$OUTPUT_DIR/capk_private.pem"
CAPK_PUBLIC_KEY="$OUTPUT_DIR/capk_public.pem"
CAPK_MODULUS="$OUTPUT_DIR/capk_modulus.bin"
CAPK_EXPONENT="$OUTPUT_DIR/capk_exponent.bin"
INFO_FILE="$OUTPUT_DIR/capk_info.txt"
CONFIG_FILE="$OUTPUT_DIR/capk_config.yaml"

# Step 1: Generate CAPK RSA-1984 key pair
print_step "1/4 Generating CAPK RSA-1984 key pair..."
openssl genrsa -out "$CAPK_PRIVATE_KEY" -3 $KEY_SIZE 2>&1 | grep -v "^[.+]" || true
print_success "CAPK private key generated"

# Step 2: Extract public key
print_step "2/4 Extracting CAPK public key..."
openssl rsa -in "$CAPK_PRIVATE_KEY" -pubout -out "$CAPK_PUBLIC_KEY" 2>/dev/null
print_success "CAPK public key extracted"

# Step 3: Extract modulus and exponent
print_step "3/4 Extracting modulus and exponent..."
openssl rsa -in "$CAPK_PRIVATE_KEY" -noout -modulus 2>/dev/null | \
    sed 's/Modulus=//' | \
    xxd -r -p > "$CAPK_MODULUS"

CAPK_MODULUS_SIZE=$(stat -f%z "$CAPK_MODULUS" 2>/dev/null || stat -c%s "$CAPK_MODULUS" 2>/dev/null)
print_success "Modulus extracted: $CAPK_MODULUS_SIZE bytes"

CAPK_EXPONENT_HEX=$(openssl rsa -in "$CAPK_PRIVATE_KEY" -noout -text 2>/dev/null | \
    grep "publicExponent:" | \
    sed 's/.*0x//' | \
    sed 's/).*//')

# Ensure even number of hex digits (pad with leading zero if needed)
if [ $(( ${#CAPK_EXPONENT_HEX} % 2 )) -ne 0 ]; then
    CAPK_EXPONENT_HEX="0$CAPK_EXPONENT_HEX"
fi

echo -n "$CAPK_EXPONENT_HEX" | xxd -r -p > "$CAPK_EXPONENT"
CAPK_EXPONENT_DEC=$((16#$CAPK_EXPONENT_HEX))
print_success "Exponent extracted: $CAPK_EXPONENT_DEC (0x$CAPK_EXPONENT_HEX)"

# Step 4: Generate info and config files
print_step "4/4 Generating information and configuration files..."

# Generate info file
cat > "$INFO_FILE" << EOF
Colossus Network CAPK
=====================

Generated: $(date)
CA Index: 0x$CA_INDEX
Algorithm: RSA-$KEY_SIZE
Hash Algorithm: SHA-256

CAPK Parameters:
----------------
Modulus Size:     $CAPK_MODULUS_SIZE bytes ($(($CAPK_MODULUS_SIZE * 8)) bits)
Public Exponent:  $CAPK_EXPONENT_DEC (0x$CAPK_EXPONENT_HEX)

File Locations:
---------------
Private Key:      $CAPK_PRIVATE_KEY
Public Key:       $CAPK_PUBLIC_KEY
Modulus (binary): $CAPK_MODULUS
Exponent (binary): $CAPK_EXPONENT

CAPK Modulus (Hex):
$(xxd -p -c 32 "$CAPK_MODULUS")

CAPK Public Exponent (Hex):
$(xxd -p "$CAPK_EXPONENT")

Security Notice:
----------------
⚠️  THIS IS THE ROOT CERTIFICATE AUTHORITY KEY!
⚠️  The CAPK private key signs all issuer certificates
⚠️  Store $CAPK_PRIVATE_KEY securely - it controls the entire network
⚠️  In production, use HSM for key storage
⚠️  Limit access to authorized personnel only

EMV Usage:
----------
1. This CAPK will be stored in payment terminals
2. Terminals use this CAPK to verify issuer certificates
3. Issuer certificates are signed with this CAPK private key
4. The certificate chain: CAPK → Issuer → ICC

Certificate Chain:
------------------
CAPK (this) → Signs issuer certificates
Issuer Key → Signs ICC (card) certificates
ICC Key → Signs transaction data (DDA/CDA)

Next Steps:
-----------
1. ✓ CAPK generated (this step)
2. → Generate issuer keys and certificates
3. → Generate ICC keys for cards
4. → Load certificates onto cards via personalization
5. → Deploy CAPK to terminals for verification

For more information, see COLOSSUS.md
EOF

print_success "Information file: $INFO_FILE"

# Generate YAML config
CAPK_MODULUS_HEX=$(xxd -p "$CAPK_MODULUS" | tr -d '\n' | sed 's/../& /g' | sed 's/ $//')

cat > "$CONFIG_FILE" << EOF
# Colossus Network CAPK Configuration
# Generated: $(date)
# CA Index: 0x$CA_INDEX

# CAPK Public Key Exponent (tag 9F32)
- req: '80 01 9F 32 01 $(printf '%02X' $CAPK_EXPONENT_DEC)'
  res: '90 00'

# CAPK Modulus (tag 9F06) - 248 bytes for RSA-1984
- req: '80 01 00 06 00 $CAPK_MODULUS_HEX'
  res: '90 00'

EOF

print_success "YAML configuration: $CONFIG_FILE"

echo ""
print_header "─────────────────────────────────────────────────────────"
print_header "  CAPK Generation Complete"
print_header "─────────────────────────────────────────────────────────"
echo ""

print_info "CAPK files generated successfully!"
echo ""
echo "  Private Key: $CAPK_PRIVATE_KEY"
echo "  Public Key:  $CAPK_PUBLIC_KEY"
echo "  Modulus:     $CAPK_MODULUS"
echo "  Exponent:    $CAPK_EXPONENT"
echo ""
echo "  View details:"
echo "    cat $INFO_FILE"
echo ""
echo "  View public key:"
echo "    openssl rsa -pubin -in $CAPK_PUBLIC_KEY -noout -text"
echo ""

print_header "─────────────────────────────────────────────────────────"
print_header "  Security Warnings"
print_header "─────────────────────────────────────────────────────────"
echo ""

print_warning "CRITICAL SECURITY NOTICES:"
echo ""
echo "  1. 🔒 The CAPK private key is the ROOT OF TRUST for your network"
echo "  2. 🔒 $CAPK_PRIVATE_KEY signs all issuer certificates"
echo "  3. 🔒 Store this key in a secure location"
echo "  4. 🔒 In production, use Hardware Security Module (HSM)"
echo "  5. 🔒 Limit access to authorized personnel only"
echo "  6. 🔒 This key validates the entire certificate chain"
echo ""

print_header "─────────────────────────────────────────────────────────"
print_header "  Next Steps"
print_header "─────────────────────────────────────────────────────────"
echo ""

print_info "Your CAPK is ready! Next steps:"
echo ""
echo "  1. ✓ CAPK generated (this step)"
echo "  2. → Generate issuer certificate:"
echo "       ./generate-issuer-cert.sh $CAPK_PRIVATE_KEY"
echo "  3. → Generate ICC certificates for cards:"
echo "       ./generate-icc-cert.sh ./keys/issuer/issuer_private.pem <PAN>"
echo "  4. → Personalize cards with full certificate chain"
echo ""

print_success "✓ CAPK generation complete!"
echo ""