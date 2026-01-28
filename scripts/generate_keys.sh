#!/bin/bash
# Generate EMV certificate hierarchy: CAPK -> Issuer -> ICC

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
KEYS_DIR="${PROJECT_ROOT}/keys"

# Key sizes (in bits)
# CAPK and Issuer: RSA-1984 (248 bytes) - terminal CAPK storage limitation
# ICC: RSA-2048 (256 bytes) - for CDA signing
CAPK_KEY_SIZE=1984
CAPK_KEY_SIZE_BYTES=$((CAPK_KEY_SIZE / 8))  # 248 bytes

ISSUER_KEY_SIZE=1984
ISSUER_KEY_SIZE_BYTES=$((ISSUER_KEY_SIZE / 8))  # 248 bytes

ICC_KEY_SIZE=1984
ICC_KEY_SIZE_BYTES=$((ICC_KEY_SIZE / 8))  # 248 bytes

# Certificate math (from spec):
# Issuer cert (90) = CAPK modulus len = 248 bytes
# Issuer remainder (92) = Issuer modulus - (CAPK - 36) = 248 - 212 = 36 bytes
# ICC cert (9F46) = Issuer modulus len = 248 bytes
# ICC remainder (9F48) = ICC modulus - (Issuer - 42) = 256 - 206 = 50 bytes

# Default values
DEFAULT_RID="A000000951"
DEFAULT_CAPK_INDEX="92"
DEFAULT_ISSUER_ID="66907500"  # Must match first 8 digits of PAN (BIN)
DEFAULT_EXPIRY="1227"  # December 2027 (MMYY format)

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Generate CAPK (CA Public Key) - RSA-1984
generate_capk() {
    local output_dir="${KEYS_DIR}/capk"
    mkdir -p "$output_dir"

    log_info "Generating CAPK (CA Public Key) - RSA-${CAPK_KEY_SIZE} (${CAPK_KEY_SIZE_BYTES} bytes)..."

    # Generate RSA key pair (1984 bits)
    openssl genrsa -3 -out "${output_dir}/capk_private.pem" $CAPK_KEY_SIZE 2>/dev/null

    # Extract public key
    openssl rsa -in "${output_dir}/capk_private.pem" -pubout -out "${output_dir}/capk_public.pem" 2>/dev/null

    # Extract modulus (binary)
    openssl rsa -in "${output_dir}/capk_private.pem" -noout -modulus 2>/dev/null | \
        cut -d'=' -f2 | xxd -r -p > "${output_dir}/capk_modulus.bin"

    # Extract public exponent (binary) - typically 03 for EMV
    printf '\x03' > "${output_dir}/capk_exponent.bin"

    # Verify modulus size
    local actual_size=$(wc -c < "${output_dir}/capk_modulus.bin" | tr -d ' ')
    if [[ "$actual_size" -ne "$CAPK_KEY_SIZE_BYTES" ]]; then
        log_error "CAPK modulus size mismatch: expected ${CAPK_KEY_SIZE_BYTES}, got ${actual_size}"
        return 1
    fi

    # Create config file
    cat > "${output_dir}/capk_config.yaml" << EOF
rid: ${DEFAULT_RID}
index: ${DEFAULT_CAPK_INDEX}
key_size: ${CAPK_KEY_SIZE}
key_size_bytes: ${CAPK_KEY_SIZE_BYTES}
exponent: 03
hash_algorithm: SHA-1
EOF

    # Create info file
    openssl rsa -in "${output_dir}/capk_private.pem" -noout -text > "${output_dir}/capk_info.txt" 2>/dev/null

    log_info "CAPK generated in ${output_dir} (${actual_size} bytes)"
}

# Generate Issuer key pair and certificate - RSA-1984
generate_issuer() {
    local output_dir="${KEYS_DIR}/issuer"
    local capk_dir="${KEYS_DIR}/capk"
    mkdir -p "$output_dir"

    if [[ ! -f "${capk_dir}/capk_private.pem" ]]; then
        log_error "CAPK not found. Generate CAPK first."
        return 1
    fi

    log_info "Generating Issuer key pair and certificate - RSA-${ISSUER_KEY_SIZE} (${ISSUER_KEY_SIZE_BYTES} bytes)..."

    # Generate RSA key pair for issuer (1984 bits)
    openssl genrsa -3 -out "${output_dir}/issuer_private.pem" $ISSUER_KEY_SIZE 2>/dev/null

    # Extract public key
    openssl rsa -in "${output_dir}/issuer_private.pem" -pubout -out "${output_dir}/issuer_public.pem" 2>/dev/null

    # Extract modulus
    local issuer_modulus_hex=$(openssl rsa -in "${output_dir}/issuer_private.pem" -noout -modulus 2>/dev/null | cut -d'=' -f2)
    echo -n "$issuer_modulus_hex" | xxd -r -p > "${output_dir}/issuer_modulus.bin"

    # Extract public exponent
    printf '\x03' > "${output_dir}/issuer_exponent.bin"

    # Verify modulus size
    local actual_size=$(wc -c < "${output_dir}/issuer_modulus.bin" | tr -d ' ')
    if [[ "$actual_size" -ne "$ISSUER_KEY_SIZE_BYTES" ]]; then
        log_error "Issuer modulus size mismatch: expected ${ISSUER_KEY_SIZE_BYTES}, got ${actual_size}"
        return 1
    fi

    # Create issuer certificate (signed by CAPK)
    # Certificate length = CAPK modulus length = 248 bytes
    # Overhead = 36 bytes, so modulus fragment = 248 - 36 = 212 bytes
    # Issuer modulus = 248 bytes, so remainder = 248 - 212 = 36 bytes
    local capk_modulus_len=$CAPK_KEY_SIZE_BYTES  # 248

    local header="6A"
    local format="02"  # Issuer Public Key Certificate format
    local issuer_id="${DEFAULT_ISSUER_ID}"  # 4 bytes (8 hex chars), must match PAN BIN
    local expiry="${DEFAULT_EXPIRY}"
    local serial="000001"
    local hash_algo="01"  # SHA-1
    local pk_algo="01"    # RSA
    # EMV spec: PK length in bytes (248 = 0xF8)
    local pk_len=$(printf '%02X' $ISSUER_KEY_SIZE_BYTES)
    local pk_exp_len="01"

    # Calculate how much of the issuer public key fits in the certificate
    # Overhead: Header(1) + Format(1) + IssuerID(4) + Expiry(2) + Serial(3) + HashAlgo(1) + PKAlgo(1) + PKLen(1) + PKExpLen(1) + Hash(20) + Trailer(1) = 36
    local pk_in_cert_len=$((capk_modulus_len - 36))  # 248 - 36 = 212 bytes
    local issuer_modulus_len_bytes=$((${#issuer_modulus_hex} / 2))

    local remainder_len=$((issuer_modulus_len_bytes - pk_in_cert_len))  # 248 - 212 = 36 bytes
    log_info "Issuer cert: ${pk_in_cert_len} bytes in cert, ${remainder_len} bytes in remainder"

    # Get the portion of issuer modulus that goes in certificate (leftmost 212 bytes)
    local pk_in_cert="${issuer_modulus_hex:0:$((pk_in_cert_len * 2))}"

    # No padding needed since issuer modulus (248) > space available (212)
    local padding=""

    # Get remainder (rightmost 36 bytes) and exponent
    local remainder_hex=""
    if (( remainder_len > 0 )); then
        remainder_hex="${issuer_modulus_hex:$((pk_in_cert_len * 2))}"
    fi
    local exponent_hex="03"  # Standard EMV exponent

    # Build data to hash (EMV spec: Format || ... || PK Data || Remainder || Exponent)
    local data_in_cert="${format}${issuer_id}${expiry}${serial}${hash_algo}${pk_algo}${pk_len}${pk_exp_len}${pk_in_cert}${padding}"
    local data_to_hash="${data_in_cert}${remainder_hex}${exponent_hex}"

    # Calculate SHA-1 hash
    local hash=$(echo -n "$data_to_hash" | xxd -r -p | openssl dgst -sha1 -binary | xxd -p | tr -d '\n')

    # Build complete certificate data (data in cert + hash)
    local cert_content="${data_in_cert}${hash}"
    local trailer="BC"

    # Create the data block to sign
    local sign_block="${header}${cert_content}${trailer}"

    # Verify sign block size
    local sign_block_size=$((${#sign_block} / 2))
    if [[ "$sign_block_size" -ne "$capk_modulus_len" ]]; then
        log_error "Issuer cert sign block size mismatch: expected ${capk_modulus_len}, got ${sign_block_size}"
        return 1
    fi

    # Sign with CAPK private key (RSA raw signature)
    echo -n "$sign_block" | xxd -r -p > /tmp/issuer_cert_data.bin
    openssl rsautl -sign -inkey "${capk_dir}/capk_private.pem" -in /tmp/issuer_cert_data.bin -out "${output_dir}/issuer_certificate.bin" -raw 2>/dev/null

    # Save remainder (36 bytes)
    if (( remainder_len > 0 )); then
        echo -n "$remainder_hex" | xxd -r -p > "${output_dir}/issuer_remainder.bin"
        log_info "Issuer remainder: ${remainder_len} bytes saved"
    else
        : > "${output_dir}/issuer_remainder.bin"
    fi

    # Create config file
    cat > "${output_dir}/issuer_config.yaml" << EOF
issuer_id: ${DEFAULT_ISSUER_ID}
key_size: ${ISSUER_KEY_SIZE}
key_size_bytes: ${ISSUER_KEY_SIZE_BYTES}
exponent: 03
expiry: ${DEFAULT_EXPIRY}
serial: 000001
capk_index: ${DEFAULT_CAPK_INDEX}
rid: ${DEFAULT_RID}
certificate_size: ${capk_modulus_len}
remainder_size: ${remainder_len}
EOF

    # Create info file
    openssl rsa -in "${output_dir}/issuer_private.pem" -noout -text > "${output_dir}/issuer_info.txt" 2>/dev/null

    rm -f /tmp/issuer_cert_data.bin

    log_info "Issuer certificate generated in ${output_dir}"
}

# Generate ICC key pair and certificate - RSA-2048
generate_icc() {
    local pan="$1"
    local expiry="${2:-271231}"  # Default expiry YYMMDD
    local output_dir="${KEYS_DIR}/icc"
    local issuer_dir="${KEYS_DIR}/issuer"
    mkdir -p "$output_dir"

    if [[ ! -f "${issuer_dir}/issuer_private.pem" ]]; then
        log_error "Issuer key not found. Generate Issuer key first."
        return 1
    fi

    log_info "Generating ICC key pair and certificate - RSA-${ICC_KEY_SIZE} (${ICC_KEY_SIZE_BYTES} bytes)..."

    # Generate RSA key pair for ICC (2048 bits)
    openssl genrsa -3 -out "${output_dir}/icc_private.pem" $ICC_KEY_SIZE 2>/dev/null

    # Extract public key
    openssl rsa -in "${output_dir}/icc_private.pem" -pubout -out "${output_dir}/icc_public.pem" 2>/dev/null

    # Extract modulus
    local icc_modulus_hex=$(openssl rsa -in "${output_dir}/icc_private.pem" -noout -modulus 2>/dev/null | cut -d'=' -f2)
    echo -n "$icc_modulus_hex" | xxd -r -p > "${output_dir}/icc_modulus.bin"

    # Extract public exponent
    printf '\x03' > "${output_dir}/icc_exponent.bin"

    # Verify modulus size
    local actual_size=$(wc -c < "${output_dir}/icc_modulus.bin" | tr -d ' ')
    if [[ "$actual_size" -ne "$ICC_KEY_SIZE_BYTES" ]]; then
        log_error "ICC modulus size mismatch: expected ${ICC_KEY_SIZE_BYTES}, got ${actual_size}"
        return 1
    fi

    # Create ICC certificate (signed by Issuer)
    # Certificate length = Issuer modulus length = 248 bytes
    # Overhead = 42 bytes, so modulus fragment = 248 - 42 = 206 bytes
    # ICC modulus = 256 bytes, so remainder = 256 - 206 = 50 bytes
    local issuer_modulus_len=$ISSUER_KEY_SIZE_BYTES  # 248

    local header="6A"
    local format="04"  # ICC Public Key Certificate format

    # PAN in certificate (full PAN, BCD encoded, padded to 10 bytes with F)
    local pan_cert="${pan}"
    while (( ${#pan_cert} < 20 )); do
        pan_cert+="F"
    done

    local cert_expiry="${expiry:2:2}${expiry:0:2}"  # MMYY (from YYMMDD input)
    local serial="000001"
    local hash_algo="01"  # SHA-1
    local pk_algo="01"    # RSA
    # EMV spec: PK length in bytes mod 256
    local icc_modulus_len_bytes=$((${#icc_modulus_hex} / 2))
    local pk_len=$(printf '%02X' $((icc_modulus_len_bytes % 256)))
    local pk_exp_len="01"

    # Calculate how much of ICC public key fits in certificate
    # Overhead: Header(1) + Format(1) + PAN(10) + Expiry(2) + Serial(3) + HashAlgo(1) + PKAlgo(1) + PKLen(1) + PKExpLen(1) + Hash(20) + Trailer(1) = 42
    local pk_in_cert_len=$((issuer_modulus_len - 42))  # 248 - 42 = 206 bytes

    local remainder_len=0
    local padding=""
    local pk_in_cert=""
    local remainder_hex=""

    if (( icc_modulus_len_bytes > pk_in_cert_len )); then
        # ICC modulus larger than space: use leftmost bytes, remainder gets the rest
        remainder_len=$((icc_modulus_len_bytes - pk_in_cert_len))
        pk_in_cert="${icc_modulus_hex:0:$((pk_in_cert_len * 2))}"
        remainder_hex="${icc_modulus_hex:$((pk_in_cert_len * 2))}"
        log_info "ICC cert: ${pk_in_cert_len} bytes in cert, ${remainder_len} bytes in remainder"
    else
        # ICC modulus fits in cert: use full modulus + BB padding
        local padding_len=$((pk_in_cert_len - icc_modulus_len_bytes))
        pk_in_cert="${icc_modulus_hex}"
        padding=$(printf 'BB%.0s' $(seq 1 $padding_len))
        log_info "ICC cert: ${icc_modulus_len_bytes} bytes in cert, ${padding_len} bytes padding, no remainder"
    fi
    local exponent_hex="03"  # Standard EMV exponent

    # Static Data to be Authenticated (for CDA)
    # This MUST include ALL offline data auth records from AFL:
    #   - SFI 2 Record 1: 8F (CAPK Index), 9F32 (Issuer PK Exp), 9F4A (SDA Tag List)
    #   - SFI 2 Record 2: 90 (Issuer Certificate) - now 248 bytes
    #   - SFI 2 Record 3: 92 (Issuer PK Remainder) - now 36 bytes
    #   - AIP value (because 9F4A=82 says to include tag 82)
    local static_data_auth=""

    if [[ -z "$STATIC_DATA_AUTH" ]]; then
        # SDA (Static Data to be Authenticated) depends on AFL ODA records
        # Since AFL has ODA count=0 for all SFIs, only 9F4A-specified data is included
        # 9F4A = 82 means include AIP (tag 82) only
        # AIP value (tag 82 value) - must match what's programmed on card
        local aip="3101"
        static_data_auth="${aip}"
        log_info "SDA data: AIP only (${#static_data_auth} hex chars / $(( ${#static_data_auth} / 2 )) bytes)"
    else
        static_data_auth="$STATIC_DATA_AUTH"
    fi

    # Build data to hash (EMV spec: Format || ... || PK Data || Remainder || Exponent || Static Data Auth)
    local data_in_cert="${format}${pan_cert}${cert_expiry}${serial}${hash_algo}${pk_algo}${pk_len}${pk_exp_len}${pk_in_cert}${padding}"
    local data_to_hash="${data_in_cert}${remainder_hex}${exponent_hex}${static_data_auth}"

    # Calculate SHA-1 hash
    local hash=$(echo -n "$data_to_hash" | xxd -r -p | openssl dgst -sha1 -binary | xxd -p | tr -d '\n')

    # Build complete certificate data (data in cert + hash)
    local cert_content="${data_in_cert}${hash}"
    local trailer="BC"

    local sign_block="${header}${cert_content}${trailer}"

    # Verify sign block size
    local sign_block_size=$((${#sign_block} / 2))
    if [[ "$sign_block_size" -ne "$issuer_modulus_len" ]]; then
        log_error "ICC cert sign block size mismatch: expected ${issuer_modulus_len}, got ${sign_block_size}"
        return 1
    fi

    # Sign with Issuer private key
    echo -n "$sign_block" | xxd -r -p > /tmp/icc_cert_data.bin
    openssl rsautl -sign -inkey "${issuer_dir}/issuer_private.pem" -in /tmp/icc_cert_data.bin -out "${output_dir}/icc_certificate.bin" -raw 2>/dev/null

    # Save remainder (50 bytes)
    if (( remainder_len > 0 )); then
        echo -n "$remainder_hex" | xxd -r -p > "${output_dir}/icc_remainder.bin"
        log_info "ICC remainder: ${remainder_len} bytes saved"
    else
        : > "${output_dir}/icc_remainder.bin"
    fi

    # Create config file
    cat > "${output_dir}/icc_config.yaml" << EOF
pan: ${pan}
key_size: ${ICC_KEY_SIZE}
key_size_bytes: ${ICC_KEY_SIZE_BYTES}
exponent: 03
expiry: ${expiry}
serial: 000001
certificate_size: ${issuer_modulus_len}
remainder_size: ${remainder_len}
sdad_size: ${ICC_KEY_SIZE_BYTES}
EOF

    # Create info file
    openssl rsa -in "${output_dir}/icc_private.pem" -noout -text > "${output_dir}/icc_info.txt" 2>/dev/null

    rm -f /tmp/icc_cert_data.bin

    log_info "ICC certificate generated in ${output_dir}"
}

# Generate all keys
generate_all() {
    local pan="${1:-6690750012345678}"
    local expiry="${2:-271231}"

    log_info "Generating complete certificate hierarchy..."
    log_info "  CAPK:   RSA-${CAPK_KEY_SIZE} (${CAPK_KEY_SIZE_BYTES} bytes)"
    log_info "  Issuer: RSA-${ISSUER_KEY_SIZE} (${ISSUER_KEY_SIZE_BYTES} bytes)"
    log_info "  ICC:    RSA-${ICC_KEY_SIZE} (${ICC_KEY_SIZE_BYTES} bytes)"
    log_info ""
    generate_capk
    generate_issuer
    generate_icc "$pan" "$expiry"
    log_info ""
    log_info "Certificate hierarchy generation complete!"
    log_info "Key sizes summary:"
    log_info "  - CAPK modulus:        ${CAPK_KEY_SIZE_BYTES} bytes (terminal CAPK)"
    log_info "  - Issuer cert (90):    ${CAPK_KEY_SIZE_BYTES} bytes"
    log_info "  - Issuer remainder(92): 36 bytes"
    log_info "  - ICC cert (9F46):     ${ISSUER_KEY_SIZE_BYTES} bytes"
    log_info "  - ICC remainder(9F48): 50 bytes"
    log_info "  - SDAD (9F4B):         ${ICC_KEY_SIZE_BYTES} bytes"
}

# CLI interface
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    case "$1" in
        capk)
            generate_capk
            ;;
        issuer)
            generate_issuer
            ;;
        icc)
            generate_icc "$2" "$3"
            ;;
        all)
            generate_all "$2" "$3"
            ;;
        *)
            echo "Usage: $0 {capk|issuer|icc|all} [pan] [expiry]"
            echo ""
            echo "Commands:"
            echo "  capk              - Generate CA Public Key"
            echo "  issuer            - Generate Issuer key pair and certificate (requires CAPK)"
            echo "  icc <pan> [exp]   - Generate ICC key pair and certificate (requires Issuer)"
            echo "  all [pan] [exp]   - Generate complete certificate hierarchy"
            echo ""
            echo "Arguments:"
            echo "  pan    - Primary Account Number (default: 6690750012345678)"
            echo "  exp    - Expiry date YYMMDD (default: 271231)"
            exit 1
            ;;
    esac
fi
