#!/bin/bash
#
# STORE DATA Personalization Script
# Personalizes EMV applets using GP STORE DATA (INS 0xE2) instead of custom 80xx commands.
# Works with both dev and production builds.
#
# Usage:
#   ./scripts/personalize_store_data.sh [--mode dev|production] [--dry-run]
#
# In dev mode:    sends STORE DATA APDUs directly via gp.jar -a (no secure channel)
# In production:  sends via gp.jar --store-data (over SCP03 secure channel)
#

set -e
set -o pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"
KEYS_DIR="${ROOT_DIR}/keys"
GP_JAR="${ROOT_DIR}/gp.jar"

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
RED='\033[0;31m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_step() { echo -e "${CYAN}[STEP]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# Defaults
MODE="dev"
DRY_RUN=false
VERBOSE=false

# Card configuration
RID="A000000951"
AID_SUFFIX="0001"
CONTACTLESS_AID_SUFFIX="1010"
BIN="66907500"
PAN=""
DEFAULT_EXPIRY="271231"
APP_LABEL="COLOSSUS"

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --mode) MODE="$2"; shift 2 ;;
        --dry-run) DRY_RUN=true; shift ;;
        --verbose|-v) VERBOSE=true; shift ;;
        --pan) PAN="$2"; shift 2 ;;
        --help|-h)
            echo "Usage: $0 [--mode dev|production] [--dry-run] [--pan PAN] [--verbose]"
            echo ""
            echo "Personalizes EMV applets via GP STORE DATA (INS 0xE2)."
            echo ""
            echo "Options:"
            echo "  --mode dev|production   Transport mode (default: dev)"
            echo "  --dry-run               Print commands without executing"
            echo "  --pan PAN               Card PAN (auto-generated if not set)"
            echo "  --verbose, -v           Show APDU details"
            exit 0
            ;;
        *) log_error "Unknown option: $1"; exit 1 ;;
    esac
done

# Generate PAN if not provided
if [[ -z "$PAN" ]]; then
    # Generate random PAN with BIN prefix
    PAN_SUFFIX=$(printf '%07d' $((RANDOM * RANDOM % 10000000)))
    PAN="${BIN}${PAN_SUFFIX}0"  # Last digit is Luhn placeholder
    log_info "Generated PAN: ${PAN}"
fi

FULL_AID="${RID}${AID_SUFFIX}"
FULL_CONTACTLESS_AID="${RID}${CONTACTLESS_AID_SUFFIX}"

# Helper: build a STORE DATA APDU from DGI + data
# Format: 00 E2 P1 P2 LC [DGI(2)] [LEN(1)] [DATA...]
build_store_data() {
    local dgi="$1"    # 4 hex chars (2 bytes)
    local data="$2"   # hex string
    local data_len=$((${#data} / 2))
    local data_len_hex=$(printf '%02X' $data_len)
    local payload="${dgi}${data_len_hex}${data}"
    local lc=$((${#payload} / 2))
    local lc_hex=$(printf '%02X' $lc)
    echo "00E20000${lc_hex}${payload}"
}

# Helper: send APDU
send_apdu() {
    local apdu="$1"
    local desc="$2"

    if $VERBOSE; then
        log_info "  ${desc}: ${apdu}"
    fi

    if $DRY_RUN; then
        echo "  gp -a ${apdu}"
        return
    fi

    # In both modes, we send as raw APDUs for now
    # Production mode would use: java -jar gp.jar --store-data <DGI payload>
    # But gp.jar's --store-data wraps in SCP, which requires card keys
    APDUS+=("-a" "${apdu}")
}

# Collect all APDUs
APDUS=()

# ============================================================
log_step "1. PSE Personalization (1PAY.SYS.DDF01)"
# ============================================================

PSE_AID="315041592E5359532E4444463031"

# Select PSE
APDUS+=("-a" "00A404000E${PSE_AID}")

# Set AID tag (8E) via STORE DATA DGI=008E
send_apdu "$(build_store_data '008E' "0E${PSE_AID}")" "AID (8E)"

# Set AID tag (84) via STORE DATA DGI=0084
send_apdu "$(build_store_data '0084' "0E${PSE_AID}")" "DF Name (84)"

# Set SFI (88) = 01
send_apdu "$(build_store_data '0088' '0101')" "SFI (88)"

# Set language (5F2D) = en
send_apdu "$(build_store_data '5F2D' '656E')" "Language (5F2D)"

# Tag templates for FCI
# Template 05 (tagA5Fci): 00 88 00
send_apdu "$(build_store_data 'B005' '008800')" "FCI A5 template"
# Template 04 (tag6fFci): 00 84 00 A5
send_apdu "$(build_store_data 'B004' '008400A5')" "FCI 6F template"

# Directory entry (tag 61) — points to the payment app
dir_entry_content="4F07${FULL_AID}50${APP_LABEL_LEN:-08}${APP_LABEL_HEX:-434F4C4F53535553}870101"
send_apdu "$(build_store_data '0061' "${dir_entry_content}")" "Directory entry (61)"

# Read record template for SFI1/REC1 (record 010C)
full_dir_entry="6F$(printf '%02X' $((${#dir_entry_content} / 2)))${dir_entry_content}"
send_apdu "$(build_store_data 'C10C' "${full_dir_entry}")" "Read record SFI1/REC1"

# ============================================================
log_step "2. PPSE Personalization (2PAY.SYS.DDF01)"
# ============================================================

PPSE_AID="325041592E5359532E4444463031"

# Select PPSE
APDUS+=("-a" "00A404000E${PPSE_AID}")

# Directory entry via STORE DATA DGI=D001
contactless_label_hex=$(echo -n "${APP_LABEL} CREDIT" | xxd -p | tr -d '\n')
contactless_label_len=$(printf '%02X' $((${#contactless_label_hex} / 2)))
contactless_dir="4F$(printf '%02X' $((${#FULL_CONTACTLESS_AID} / 2)))${FULL_CONTACTLESS_AID}50${contactless_label_len}${contactless_label_hex}870101"
send_apdu "$(build_store_data 'D001' "${contactless_dir}")" "PPSE directory entry"

# ============================================================
log_step "3. Payment Application Personalization"
# ============================================================

# Select payment app
APDUS+=("-a" "00A40400$(printf '%02X' $((${#FULL_AID} / 2)))${FULL_AID}")

# Flags: enable randomness
send_apdu "$(build_store_data 'A003' '0001')" "Flags (randomness)"

# RSA key (if available)
if [[ -f "${KEYS_DIR}/icc/icc_modulus.bin" ]]; then
    icc_mod_hex=$(xxd -p "${KEYS_DIR}/icc/icc_modulus.bin" | tr -d '\n')
    send_apdu "$(build_store_data 'A004' "${icc_mod_hex}")" "RSA modulus"

    icc_priv_hex=$(xxd -p "${KEYS_DIR}/icc/icc_private.pem" | tr -d '\n' 2>/dev/null || true)
    if [[ -n "$icc_priv_hex" ]]; then
        send_apdu "$(build_store_data 'A005' "${icc_priv_hex}")" "RSA exponent"
    fi
fi

# EC private key (if available)
if [[ -f "${KEYS_DIR}/icc/icc_ec_private.bin" ]]; then
    icc_ec_hex=$(xxd -p "${KEYS_DIR}/icc/icc_ec_private.bin" | tr -d '\n')
    send_apdu "$(build_store_data 'A00B' "${icc_ec_hex}")" "EC private key"
fi

# Certificates
if [[ -f "${KEYS_DIR}/issuer/issuer_certificate.bin" ]]; then
    issuer_cert_hex=$(xxd -p "${KEYS_DIR}/issuer/issuer_certificate.bin" | tr -d '\n')
    send_apdu "$(build_store_data '0090' "${issuer_cert_hex}")" "Issuer PK cert (90)"

    issuer_rem_hex=$(xxd -p "${KEYS_DIR}/issuer/issuer_remainder.bin" | tr -d '\n' 2>/dev/null || true)
    if [[ -n "$issuer_rem_hex" ]]; then
        send_apdu "$(build_store_data '0092' "${issuer_rem_hex}")" "Issuer PK remainder (92)"
    fi
fi

if [[ -f "${KEYS_DIR}/icc/icc_certificate.bin" ]]; then
    icc_cert_hex=$(xxd -p "${KEYS_DIR}/icc/icc_certificate.bin" | tr -d '\n')
    send_apdu "$(build_store_data '9F46' "${icc_cert_hex}")" "ICC PK cert (9F46)"

    icc_rem_hex=$(xxd -p "${KEYS_DIR}/icc/icc_remainder.bin" | tr -d '\n' 2>/dev/null || true)
    if [[ -n "$icc_rem_hex" ]]; then
        send_apdu "$(build_store_data '9F48' "${icc_rem_hex}")" "ICC PK remainder (9F48)"
    fi
fi

# CAPK/Issuer/ICC public key exponents
send_apdu "$(build_store_data '008F' '0192')" "CA PK index (8F)"
send_apdu "$(build_store_data '9F32' '0103')" "Issuer PK exponent (9F32)"
send_apdu "$(build_store_data '9F47' '0103')" "ICC PK exponent (9F47)"

# PIN
send_apdu "$(build_store_data 'A001' '123400')" "PIN code"

# Response template tag
send_apdu "$(build_store_data 'A002' '0077')" "Response template (tag 77)"

# GPO response template: AIP (82), AFL (94)
send_apdu "$(build_store_data 'B001' '00820094')" "GPO template"
# DDA response template: 9F4B
send_apdu "$(build_store_data 'B002' '9F4B')" "DDA template"
# GenAC response template: 9F27, 9F36, 9F26, 9F10
send_apdu "$(build_store_data 'B003' '9F279F369F269F10')" "GenAC template"
# FCI template: 50 (label), 87 (priority)
send_apdu "$(build_store_data 'B005' '00500087')" "FCI A5 template"
# FCI 6F: 84, A5
send_apdu "$(build_store_data 'B004' '008400A5')" "FCI 6F template"

# Read record templates
# SFI2/REC1: 8F, 92, 9F32, 9F47
send_apdu "$(build_store_data 'C114' '008F00929F329F47')" "SFI2/REC1 template"
# SFI2/REC2: 90
send_apdu "$(build_store_data 'C214' '0090')" "SFI2/REC2 template"
# SFI1/REC2: 57, 5F20
send_apdu "$(build_store_data 'C20C' '00575F20')" "SFI1/REC2 template"
# SFI3/REC1: 5A, 5F24, 5F25, 5F28, 5F34, 9F07, 9F0D, 9F0E, 9F0F, 9F4A, 8C, 8D
send_apdu "$(build_store_data 'C11C' '005A5F245F255F285F349F079F0D9F0E9F0F9F4A008C008D')" "SFI3/REC1 template"
# SFI3/REC2: 8E
send_apdu "$(build_store_data 'C21C' '008E')" "SFI3/REC2 template"

# Card data tags
send_apdu "$(build_store_data '9F36' '0001')" "ATC (9F36)"
send_apdu "$(build_store_data '0084' "07${FULL_AID}")" "AID (84)"

pan_hex=$(echo -n "$PAN" | sed 's/\(.\)/\1/g' | xxd -r -p 2>/dev/null | xxd -p | tr -d '\n' 2>/dev/null || echo "$PAN")
pan_len=$(printf '%02X' $((${#PAN} / 2)))
send_apdu "$(build_store_data '005A' "${pan_len}${pan_hex}")" "PAN (5A)"

send_apdu "$(build_store_data '5F24' "03${DEFAULT_EXPIRY}")" "Expiry (5F24)"
send_apdu "$(build_store_data '5F34' '0101')" "PAN seq (5F34)"

# AIP: 3C01 (DDA, CVM, issuer auth, terminal risk mgmt)
send_apdu "$(build_store_data '0082' '023C01')" "AIP (82)"
# AFL
send_apdu "$(build_store_data '0094' '0C080202001001020218010500')" "AFL (94)"
# 9F4A = SDA tag list: 82 (AIP)
send_apdu "$(build_store_data '9F4A' '0182')" "SDA tag list (9F4A)"

# Application label
app_label_hex=$(echo -n "$APP_LABEL" | xxd -p | tr -d '\n')
app_label_len=$(printf '%02X' ${#APP_LABEL})
send_apdu "$(build_store_data '0050' "${app_label_len}${app_label_hex}")" "App label (50)"
send_apdu "$(build_store_data '0087' '0101')" "Priority (87)"

# ============================================================
log_step "4. Executing"
# ============================================================

if $DRY_RUN; then
    echo ""
    log_info "Dry run complete. Commands above would be sent to the card."
    exit 0
fi

log_info "Sending ${#APDUS[@]} APDUs via gp.jar..."
if $VERBOSE; then
    java -jar "$GP_JAR" "${APDUS[@]}" -v
else
    java -jar "$GP_JAR" "${APDUS[@]}"
fi

log_info "Personalization complete via STORE DATA."
