#!/bin/bash
# Generate EMV certificate hierarchy: CAPK -> Issuer -> ICC

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
KEYS_DIR="${PROJECT_ROOT}/keys"

# Key sizes (in bits) - RSA-2048 for EMV compatibility
KEY_SIZE=2048
KEY_SIZE_BYTES=$((KEY_SIZE / 8))

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

# Generate CAPK (CA Public Key)
generate_capk() {
    local output_dir="${KEYS_DIR}/capk"
    mkdir -p "$output_dir"

    log_info "Generating CAPK (CA Public Key)..."

    # Generate RSA key pair
    openssl genrsa -3 -out "${output_dir}/capk_private.pem" $KEY_SIZE 2>/dev/null

    # Extract public key
    openssl rsa -in "${output_dir}/capk_private.pem" -pubout -out "${output_dir}/capk_public.pem" 2>/dev/null

    # Extract modulus (binary)
    openssl rsa -in "${output_dir}/capk_private.pem" -noout -modulus 2>/dev/null | \
        cut -d'=' -f2 | xxd -r -p > "${output_dir}/capk_modulus.bin"

    # Extract public exponent (binary) - typically 03 for EMV
    printf '\x03' > "${output_dir}/capk_exponent.bin"

    # Create config file
    cat > "${output_dir}/capk_config.yaml" << EOF
rid: ${DEFAULT_RID}
index: ${DEFAULT_CAPK_INDEX}
key_size: ${KEY_SIZE}
exponent: 03
hash_algorithm: SHA-1
EOF

    # Create info file
    openssl rsa -in "${output_dir}/capk_private.pem" -noout -text > "${output_dir}/capk_info.txt" 2>/dev/null

    log_info "CAPK generated in ${output_dir}"
}

# Generate Issuer key pair and certificate
generate_issuer() {
    local output_dir="${KEYS_DIR}/issuer"
    local capk_dir="${KEYS_DIR}/capk"
    mkdir -p "$output_dir"

    if [[ ! -f "${capk_dir}/capk_private.pem" ]]; then
        log_error "CAPK not found. Generate CAPK first."
        return 1
    fi

    log_info "Generating Issuer key pair and certificate..."

    # Generate RSA key pair for issuer
    openssl genrsa -3 -out "${output_dir}/issuer_private.pem" $KEY_SIZE 2>/dev/null

    # Extract public key
    openssl rsa -in "${output_dir}/issuer_private.pem" -pubout -out "${output_dir}/issuer_public.pem" 2>/dev/null

    # Extract modulus
    local issuer_modulus_hex=$(openssl rsa -in "${output_dir}/issuer_private.pem" -noout -modulus 2>/dev/null | cut -d'=' -f2)
    echo -n "$issuer_modulus_hex" | xxd -r -p > "${output_dir}/issuer_modulus.bin"

    # Extract public exponent
    printf '\x03' > "${output_dir}/issuer_exponent.bin"

    # Create issuer certificate (signed by CAPK)
    # Certificate format per EMV spec
    local capk_modulus_len=$KEY_SIZE_BYTES
    local cert_data_len=$((capk_modulus_len - 36))  # Header(6) + Hash(20) + Trailer(1) + padding adjustment

    # Build certificate data to sign
    # Format: Header(1) + Format(1) + Issuer ID(4) + Expiry(2) + Serial(3) + Hash Algo(1) + PK Algo(1) + PK Len(1) + PK Exp Len(1) + PK or leftmost + Hash(20) + Trailer(1)

    local header="6A"
    local format="02"  # Issuer Public Key Certificate format
    local issuer_id="${DEFAULT_ISSUER_ID}"  # 4 bytes (8 hex chars), must match PAN BIN
    local expiry="${DEFAULT_EXPIRY}"
    local serial="000001"
    local hash_algo="01"  # SHA-1
    local pk_algo="01"    # RSA
    # EMV spec: PK length mod 256 (so 256 bytes = 0x00)
    local pk_len=$(printf '%02X' $((KEY_SIZE_BYTES % 256)))
    local pk_exp_len="01"

    # Calculate how much of the issuer public key fits in the certificate
    local pk_in_cert_len=$((capk_modulus_len - 36))
    local issuer_modulus_len=${#issuer_modulus_hex}
    issuer_modulus_len=$((issuer_modulus_len / 2))

    local remainder_len=$((issuer_modulus_len - pk_in_cert_len))
    if (( remainder_len < 0 )); then
        remainder_len=0
        pk_in_cert_len=$issuer_modulus_len
    fi

    # Get the portion of issuer modulus that goes in certificate
    local pk_in_cert="${issuer_modulus_hex:0:$((pk_in_cert_len * 2))}"

    # Pad with BB if needed
    local padding_len=$((capk_modulus_len - 36 - pk_in_cert_len))
    local padding=""
    for ((i=0; i<padding_len; i++)); do
        padding+="BB"
    done

    # Get remainder and exponent hex values
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

    # Build complete certificate data (data in cert + hash, no remainder/exponent)
    local cert_content="${data_in_cert}${hash}"
    local trailer="BC"

    # Create the data block to sign
    local sign_block="${header}${cert_content}${trailer}"

    # Sign with CAPK private key (RSA raw signature)
    echo -n "$sign_block" | xxd -r -p > /tmp/issuer_cert_data.bin
    openssl rsautl -sign -inkey "${capk_dir}/capk_private.pem" -in /tmp/issuer_cert_data.bin -out "${output_dir}/issuer_certificate.bin" -raw 2>/dev/null

    # Save remainder if any
    if (( remainder_len > 0 )); then
        echo -n "$remainder_hex" | xxd -r -p > "${output_dir}/issuer_remainder.bin"
    else
        : > "${output_dir}/issuer_remainder.bin"
    fi

    # Create config file
    cat > "${output_dir}/issuer_config.yaml" << EOF
issuer_id: ${DEFAULT_ISSUER_ID}
key_size: ${KEY_SIZE}
exponent: 03
expiry: ${DEFAULT_EXPIRY}
serial: 000001
capk_index: ${DEFAULT_CAPK_INDEX}
rid: ${DEFAULT_RID}
EOF

    # Create info file
    openssl rsa -in "${output_dir}/issuer_private.pem" -noout -text > "${output_dir}/issuer_info.txt" 2>/dev/null

    rm -f /tmp/issuer_cert_data.bin

    log_info "Issuer certificate generated in ${output_dir}"
}

# Generate ICC key pair and certificate
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

    log_info "Generating ICC key pair and certificate..."

    # Generate RSA key pair for ICC
    openssl genrsa -3 -out "${output_dir}/icc_private.pem" $KEY_SIZE 2>/dev/null

    # Extract public key
    openssl rsa -in "${output_dir}/icc_private.pem" -pubout -out "${output_dir}/icc_public.pem" 2>/dev/null

    # Extract modulus
    local icc_modulus_hex=$(openssl rsa -in "${output_dir}/icc_private.pem" -noout -modulus 2>/dev/null | cut -d'=' -f2)
    echo -n "$icc_modulus_hex" | xxd -r -p > "${output_dir}/icc_modulus.bin"

    # Extract public exponent
    printf '\x03' > "${output_dir}/icc_exponent.bin"

    # Create ICC certificate (signed by Issuer)
    local issuer_modulus_len=$KEY_SIZE_BYTES

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
    # EMV spec: PK length mod 256 (so 256 bytes = 0x00)
    local pk_len=$(printf '%02X' $((KEY_SIZE_BYTES % 256)))
    local pk_exp_len="01"

    # Calculate how much of ICC public key fits
    local pk_in_cert_len=$((issuer_modulus_len - 42))
    local icc_modulus_len_bytes=$((${#icc_modulus_hex} / 2))

    local remainder_len=$((icc_modulus_len_bytes - pk_in_cert_len))
    if (( remainder_len < 0 )); then
        remainder_len=0
        pk_in_cert_len=$icc_modulus_len_bytes
    fi

    local pk_in_cert="${icc_modulus_hex:0:$((pk_in_cert_len * 2))}"

    # Pad with BB if needed
    local padding_len=$((issuer_modulus_len - 42 - pk_in_cert_len))
    local padding=""
    for ((i=0; i<padding_len; i++)); do
        padding+="BB"
    done

    # Get remainder and exponent hex values
    local remainder_hex=""
    if (( remainder_len > 0 )); then
        remainder_hex="${icc_modulus_hex:$((pk_in_cert_len * 2))}"
    fi
    local exponent_hex="03"  # Standard EMV exponent

    # Static Data to be Authenticated (for CDA)
    # This MUST include ALL offline data auth records from AFL:
    #   - SFI 2 Record 1: 8F (CAPK Index), 9F32 (Issuer PK Exp), 9F4A (SDA Tag List)
    #   - SFI 2 Record 2: 90 (Issuer Certificate)
    #   - SFI 2 Record 3: 92 (Issuer PK Remainder)
    #   - AIP value (because 9F4A=82 says to include tag 82)
    local static_data_auth=""

    if [[ -z "$STATIC_DATA_AUTH" ]]; then
        # Build SDA from actual certificate files
        # Record 1: 8F 01 92 9F32 01 03 9F4A 01 82
        local record1="8F01929F3201039F4A0182"

        # Record 2: Issuer Certificate with TLV encoding (90 82 01 00 + 256 bytes)
        local issuer_cert_hex=$(xxd -p "${issuer_dir}/issuer_certificate.bin" | tr -d '\n')
        local issuer_cert_size=$((${#issuer_cert_hex} / 2))
        local record2=""
        if (( issuer_cert_size > 255 )); then
            # Length encoding: 82 XX XX for > 255 bytes
            record2=$(printf '9082%04X' $issuer_cert_size)
        elif (( issuer_cert_size >= 128 )); then
            # Length encoding: 81 XX for 128-255 bytes
            record2=$(printf '9081%02X' $issuer_cert_size)
        else
            record2=$(printf '90%02X' $issuer_cert_size)
        fi
        record2+="$issuer_cert_hex"

        # Record 3: Issuer Remainder with TLV encoding (92 XX + remainder bytes)
        local issuer_rem_hex=$(xxd -p "${issuer_dir}/issuer_remainder.bin" | tr -d '\n')
        local issuer_rem_size=$((${#issuer_rem_hex} / 2))
        local record3=""
        if (( issuer_rem_size > 0 )); then
            record3=$(printf '92%02X' $issuer_rem_size)
            record3+="$issuer_rem_hex"
        fi

        # AIP value (tag 82 value)
        local aip="3D01"

        static_data_auth="${record1}${record2}${record3}${aip}"
        log_info "Computed SDA data (${#static_data_auth} hex chars / $(( ${#static_data_auth} / 2 )) bytes)"
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

    # Sign with Issuer private key
    echo -n "$sign_block" | xxd -r -p > /tmp/icc_cert_data.bin
    openssl rsautl -sign -inkey "${issuer_dir}/issuer_private.pem" -in /tmp/icc_cert_data.bin -out "${output_dir}/icc_certificate.bin" -raw 2>/dev/null

    # Save remainder
    if (( remainder_len > 0 )); then
        echo -n "$remainder_hex" | xxd -r -p > "${output_dir}/icc_remainder.bin"
    else
        : > "${output_dir}/icc_remainder.bin"
    fi

    # Create config file
    cat > "${output_dir}/icc_config.yaml" << EOF
pan: ${pan}
key_size: ${KEY_SIZE}
exponent: 03
expiry: ${expiry}
serial: 000001
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
    generate_capk
    generate_issuer
    generate_icc "$pan" "$expiry"
    log_info "Certificate hierarchy generation complete!"
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
