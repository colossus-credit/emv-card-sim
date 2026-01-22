#!/bin/bash
# Validate EMV certificate chain: CAPK -> Issuer -> ICC

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
KEYS_DIR="${PROJECT_ROOT}/keys"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }
log_pass() { echo -e "${GREEN}[PASS]${NC} $1"; }
log_fail() { echo -e "${RED}[FAIL]${NC} $1"; }

# Validate Issuer certificate against CAPK
validate_issuer_cert() {
    local capk_dir="${KEYS_DIR}/capk"
    local issuer_dir="${KEYS_DIR}/issuer"

    log_info "Validating Issuer Certificate..."

    if [[ ! -f "${issuer_dir}/issuer_certificate.bin" ]]; then
        log_fail "Issuer certificate not found"
        return 1
    fi

    if [[ ! -f "${capk_dir}/capk_public.pem" ]]; then
        log_fail "CAPK public key not found"
        return 1
    fi

    # Decrypt the certificate using CAPK public key
    local decrypted=$(openssl rsautl -verify -inkey "${capk_dir}/capk_public.pem" -pubin -in "${issuer_dir}/issuer_certificate.bin" -raw 2>/dev/null | xxd -p | tr -d '\n')

    # Check header and trailer
    local header="${decrypted:0:2}"
    local trailer="${decrypted: -2}"

    if [[ "$header" != "6a" ]]; then
        log_fail "Invalid certificate header: $header (expected 6a)"
        return 1
    fi

    if [[ "$trailer" != "bc" ]]; then
        log_fail "Invalid certificate trailer: $trailer (expected bc)"
        return 1
    fi

    # Check format byte
    local format="${decrypted:2:2}"
    if [[ "$format" != "02" ]]; then
        log_fail "Invalid certificate format: $format (expected 02 for Issuer)"
        return 1
    fi

    # Extract hash from certificate (last 40 hex chars before trailer)
    local cert_hash="${decrypted: -42:40}"

    # Extract data to verify (everything between header and hash)
    # EMV hash is computed over: Format || Issuer ID || Expiry || Serial || Hash Algo || PK Algo || PK Len || Exp Len || PK Data || Remainder || Exponent
    local data_len=$((${#decrypted} - 2 - 40 - 2))  # minus header, hash, trailer
    local data_in_cert="${decrypted:2:$data_len}"

    # Get the remainder and exponent (these are part of the hash but stored separately)
    local remainder_hex=""
    local exponent_hex=""

    if [[ -f "${issuer_dir}/issuer_remainder.bin" && -s "${issuer_dir}/issuer_remainder.bin" ]]; then
        remainder_hex=$(xxd -p "${issuer_dir}/issuer_remainder.bin" | tr -d '\n')
    fi

    if [[ -f "${issuer_dir}/issuer_exponent.bin" ]]; then
        exponent_hex=$(xxd -p "${issuer_dir}/issuer_exponent.bin" | tr -d '\n')
    fi

    # Build complete data to hash: cert data + remainder + exponent
    local data_to_verify="${data_in_cert}${remainder_hex}${exponent_hex}"

    # Calculate hash of data
    local calculated_hash=$(echo -n "$data_to_verify" | xxd -r -p | openssl dgst -sha1 -binary | xxd -p | tr -d '\n')

    if [[ "$cert_hash" == "$calculated_hash" ]]; then
        log_pass "Issuer certificate hash verified"
    else
        log_fail "Issuer certificate hash mismatch"
        log_error "  Expected: $cert_hash"
        log_error "  Got:      $calculated_hash"
        return 1
    fi

    log_pass "Issuer certificate validation complete"
    return 0
}

# Validate ICC certificate against Issuer
validate_icc_cert() {
    local issuer_dir="${KEYS_DIR}/issuer"
    local icc_dir="${KEYS_DIR}/icc"

    log_info "Validating ICC Certificate..."

    if [[ ! -f "${icc_dir}/icc_certificate.bin" ]]; then
        log_fail "ICC certificate not found"
        return 1
    fi

    if [[ ! -f "${issuer_dir}/issuer_public.pem" ]]; then
        log_fail "Issuer public key not found"
        return 1
    fi

    # Decrypt the certificate using Issuer public key
    local decrypted=$(openssl rsautl -verify -inkey "${issuer_dir}/issuer_public.pem" -pubin -in "${icc_dir}/icc_certificate.bin" -raw 2>/dev/null | xxd -p | tr -d '\n')

    # Check header and trailer
    local header="${decrypted:0:2}"
    local trailer="${decrypted: -2}"

    if [[ "$header" != "6a" ]]; then
        log_fail "Invalid certificate header: $header (expected 6a)"
        return 1
    fi

    if [[ "$trailer" != "bc" ]]; then
        log_fail "Invalid certificate trailer: $trailer (expected bc)"
        return 1
    fi

    # Check format byte
    local format="${decrypted:2:2}"
    if [[ "$format" != "04" ]]; then
        log_fail "Invalid certificate format: $format (expected 04 for ICC)"
        return 1
    fi

    # Extract hash from certificate
    local cert_hash="${decrypted: -42:40}"

    # Extract data to verify (cert data without header, hash, and trailer)
    # EMV hash is computed over: Format || PAN || Expiry || Serial || Hash Algo || PK Algo || PK Len || Exp Len || PK Data || Remainder || Exponent || Static Data Auth
    local data_len=$((${#decrypted} - 2 - 40 - 2))
    local data_in_cert="${decrypted:2:$data_len}"

    # Get the remainder and exponent (these are part of the hash but stored separately)
    local remainder_hex=""
    local exponent_hex=""

    if [[ -f "${icc_dir}/icc_remainder.bin" && -s "${icc_dir}/icc_remainder.bin" ]]; then
        remainder_hex=$(xxd -p "${icc_dir}/icc_remainder.bin" | tr -d '\n')
    fi

    if [[ -f "${icc_dir}/icc_exponent.bin" ]]; then
        exponent_hex=$(xxd -p "${icc_dir}/icc_exponent.bin" | tr -d '\n')
    fi

    # Static Data to be Authenticated (for CDA cards)
    # This consists of data auth records + AIP (if listed in 9F4A)
    # Default values from legacy script: Record=8F01929F3201039F4A0182, AIP=3D01
    local static_data_auth="${STATIC_DATA_AUTH:-8F01929F3201039F4A01823D01}"

    # Build complete data to hash: cert data + remainder + exponent + static data auth
    local data_to_verify="${data_in_cert}${remainder_hex}${exponent_hex}${static_data_auth}"

    # Calculate hash
    local calculated_hash=$(echo -n "$data_to_verify" | xxd -r -p | openssl dgst -sha1 -binary | xxd -p | tr -d '\n')

    if [[ "$cert_hash" == "$calculated_hash" ]]; then
        log_pass "ICC certificate hash verified"
    else
        # Try without static data auth (in case certificates were generated differently)
        local data_to_verify_no_sda="${data_in_cert}${remainder_hex}${exponent_hex}"
        local calculated_hash_no_sda=$(echo -n "$data_to_verify_no_sda" | xxd -r -p | openssl dgst -sha1 -binary | xxd -p | tr -d '\n')

        if [[ "$cert_hash" == "$calculated_hash_no_sda" ]]; then
            log_pass "ICC certificate hash verified (no static data auth)"
        else
            log_fail "ICC certificate hash mismatch"
            log_error "  Expected: $cert_hash"
            log_error "  Got (with SDA): $calculated_hash"
            log_error "  Got (no SDA):   $calculated_hash_no_sda"
            return 1
        fi
    fi

    log_pass "ICC certificate validation complete"
    return 0
}

# Validate complete certificate chain
validate_chain() {
    log_info "Validating complete certificate chain..."
    echo ""

    local errors=0

    # Check all required files exist
    local required_files=(
        "${KEYS_DIR}/capk/capk_public.pem"
        "${KEYS_DIR}/capk/capk_modulus.bin"
        "${KEYS_DIR}/issuer/issuer_certificate.bin"
        "${KEYS_DIR}/issuer/issuer_public.pem"
        "${KEYS_DIR}/issuer/issuer_remainder.bin"
        "${KEYS_DIR}/icc/icc_certificate.bin"
        "${KEYS_DIR}/icc/icc_public.pem"
        "${KEYS_DIR}/icc/icc_remainder.bin"
    )

    for f in "${required_files[@]}"; do
        if [[ ! -f "$f" ]]; then
            log_fail "Missing file: $f"
            ((errors++))
        fi
    done

    if (( errors > 0 )); then
        log_error "Missing $errors required files"
        return 1
    fi

    log_pass "All required certificate files present"
    echo ""

    # Validate Issuer certificate
    if ! validate_issuer_cert; then
        ((errors++))
    fi
    echo ""

    # Validate ICC certificate
    if ! validate_icc_cert; then
        ((errors++))
    fi
    echo ""

    if (( errors == 0 )); then
        log_pass "Certificate chain validation PASSED"
        return 0
    else
        log_fail "Certificate chain validation FAILED with $errors errors"
        return 1
    fi
}

# Print certificate info
print_cert_info() {
    log_info "Certificate Information:"
    echo ""

    if [[ -f "${KEYS_DIR}/capk/capk_config.yaml" ]]; then
        echo "=== CAPK ==="
        cat "${KEYS_DIR}/capk/capk_config.yaml"
        echo ""
    fi

    if [[ -f "${KEYS_DIR}/issuer/issuer_config.yaml" ]]; then
        echo "=== Issuer ==="
        cat "${KEYS_DIR}/issuer/issuer_config.yaml"
        echo ""
    fi

    if [[ -f "${KEYS_DIR}/icc/icc_config.yaml" ]]; then
        echo "=== ICC ==="
        cat "${KEYS_DIR}/icc/icc_config.yaml"
        echo ""
    fi
}

# CLI interface
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    case "$1" in
        issuer)
            validate_issuer_cert
            ;;
        icc)
            validate_icc_cert
            ;;
        chain|all)
            validate_chain
            ;;
        info)
            print_cert_info
            ;;
        *)
            echo "Usage: $0 {issuer|icc|chain|info}"
            echo ""
            echo "Commands:"
            echo "  issuer  - Validate Issuer certificate against CAPK"
            echo "  icc     - Validate ICC certificate against Issuer"
            echo "  chain   - Validate complete certificate chain"
            echo "  info    - Print certificate information"
            exit 1
            ;;
    esac
fi
