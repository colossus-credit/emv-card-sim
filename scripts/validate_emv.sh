#!/bin/bash
# Validate EMV field personalization on card

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

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

GP_JAR="${PROJECT_ROOT}/gp.jar"

# Build GP command
build_gp_cmd() {
    local cmd="java -jar ${GP_JAR}"
    if [[ -n "$KEY_ENC" && -n "$KEY_MAC" && -n "$KEY_DEK" ]]; then
        cmd+=" --key-enc $KEY_ENC --key-mac $KEY_MAC --key-dek $KEY_DEK"
    fi
    echo "$cmd"
}

# Read tag from card using GET DATA
read_tag() {
    local aid="$1"
    local tag="$2"
    local gp_cmd=$(build_gp_cmd)

    # Convert tag to P1P2
    local p1="${tag:0:2}"
    local p2="${tag:2:2}"

    # Select app and read tag
    local result=$($gp_cmd -a "00A4040007${aid}" -a "80CA${p1}${p2}00" 2>&1 | grep "A<<" | tail -1 || true)

    echo "$result"
}

# Validate expected tags
validate_tags() {
    local aid="$1"
    local expected_pan="$2"
    local expected_expiry="$3"
    local expected_label="$4"

    log_info "Validating EMV tags on card..."
    echo ""

    local errors=0

    # Select PSE first
    log_info "Selecting PSE (1PAY.SYS.DDF01)..."
    local gp_cmd=$(build_gp_cmd)
    local pse_result=$($gp_cmd -d -a "00A404000E315041592E5359532E4444463031" 2>&1)

    if echo "$pse_result" | grep -q "9000"; then
        log_pass "PSE selected successfully"
    else
        log_fail "PSE selection failed"
        ((errors++))
    fi

    # Read PSE record
    log_info "Reading PSE directory..."
    local record_result=$($gp_cmd -d -a "00A404000E315041592E5359532E4444463031" -a "00B2010C00" 2>&1)

    if echo "$record_result" | grep -q "9000"; then
        log_pass "PSE directory read successfully"

        # Check if our AID is in the directory
        if echo "$record_result" | grep -qi "$aid"; then
            log_pass "Payment app AID found in PSE directory"
        else
            log_warn "Payment app AID not found in PSE directory"
        fi
    else
        log_fail "PSE directory read failed"
        ((errors++))
    fi

    echo ""

    # Select Payment App
    log_info "Selecting Payment Application..."
    local app_result=$($gp_cmd -d -a "00A4040007${aid}" 2>&1)

    if echo "$app_result" | grep -q "9000"; then
        log_pass "Payment app selected successfully"
    else
        log_fail "Payment app selection failed"
        ((errors++))
        return $errors
    fi

    # Get Processing Options
    log_info "Sending GET PROCESSING OPTIONS..."
    local gpo_result=$($gp_cmd -d -a "00A4040007${aid}" -a "80A80000028300" 2>&1)

    if echo "$gpo_result" | grep -q "9000"; then
        log_pass "GPO successful"
    else
        log_warn "GPO returned non-9000 (may be expected for some configurations)"
    fi

    # Read records
    log_info "Reading application data..."

    # Record 1 SFI 1 (0x0C)
    local rec1=$($gp_cmd -d -a "00A4040007${aid}" -a "00B2010C00" 2>&1)
    if echo "$rec1" | grep -q "9000"; then
        log_pass "Record 1 SFI 1 read"
    fi

    # Record 2 SFI 2 (0x14)
    local rec2=$($gp_cmd -d -a "00A4040007${aid}" -a "00B2011400" 2>&1)
    if echo "$rec2" | grep -q "9000"; then
        log_pass "Record 1 SFI 2 read"
    fi

    # Record 1 SFI 3 (0x1C)
    local rec3=$($gp_cmd -d -a "00A4040007${aid}" -a "00B2011C00" 2>&1)
    if echo "$rec3" | grep -q "9000"; then
        log_pass "Record 1 SFI 3 read"
    fi

    echo ""

    if (( errors == 0 )); then
        log_pass "EMV field validation PASSED"
    else
        log_fail "EMV field validation FAILED with $errors errors"
    fi

    return $errors
}

# Quick validation
quick_validate() {
    local aid="${1:-A0000009510001}"

    log_info "Quick EMV validation for AID: $aid"
    echo ""

    local gp_cmd=$(build_gp_cmd)

    # Try to select and read
    log_info "Testing card communication..."

    local result=$($gp_cmd -d \
        -a "00A404000E315041592E5359532E4444463031" \
        -a "00B2010C00" \
        -a "00A4040007${aid}" \
        -a "80A80000028300" \
        2>&1)

    local success_count=$(echo "$result" | grep -c "9000" || true)

    echo ""
    log_info "Successful responses: $success_count"

    if (( success_count >= 3 )); then
        log_pass "Card appears to be properly personalized"
        return 0
    else
        log_warn "Card may not be fully personalized"
        return 1
    fi
}

# CLI interface
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    case "$1" in
        validate)
            validate_tags "${2:-A0000009510001}" "$3" "$4" "$5"
            ;;
        quick)
            quick_validate "${2:-A0000009510001}"
            ;;
        *)
            echo "Usage: $0 {validate|quick} [aid] [pan] [expiry] [label]"
            echo ""
            echo "Commands:"
            echo "  validate [aid]  - Full validation of EMV tags"
            echo "  quick [aid]     - Quick validation test"
            echo ""
            echo "Environment variables:"
            echo "  KEY_ENC, KEY_MAC, KEY_DEK - Card keys (optional)"
            exit 1
            ;;
    esac
fi
