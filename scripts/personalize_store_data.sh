#!/bin/bash
#
# STORE DATA Personalization Script
# Personalizes EMV applets using GP STORE DATA (INS 0xE2) instead of custom 80xx commands.
# Mirrors personalize.sh but uses standard GP STORE DATA for all data loading.
#
# Usage:
#   ./scripts/personalize_store_data.sh [--dry-run] [--pan PAN] [--verbose]
#

set -e
set -o pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"
KEYS_DIR="${ROOT_DIR}/keys"
GP_JAR="${ROOT_DIR}/gp.jar"

# Use Homebrew JDK if system Java not available
if ! command -v java &>/dev/null; then
    for jdk in /opt/homebrew/opt/openjdk@17 /opt/homebrew/opt/openjdk@21 /opt/homebrew/opt/openjdk; do
        if [[ -d "$jdk" ]]; then
            export JAVA_HOME="$jdk"
            export PATH="$jdk/bin:$PATH"
            break
        fi
    done
fi

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
DRY_RUN=false
VERBOSE=false

# Card configuration — temporarily using Mastercard AID for C-2 kernel testing
RID="A000000004"
AID_SUFFIX="1010"
CONTACTLESS_AID_SUFFIX="1010"
DEFAULT_BIN="54000000"
DEFAULT_APP_LABEL="MASTERCARD"
DEFAULT_EXPIRY="271231"
PAN=""

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --dry-run) DRY_RUN=true; shift ;;
        --verbose|-v) VERBOSE=true; shift ;;
        --pan) PAN="$2"; shift 2 ;;
        --keys) KEYS_DIR="$2"; shift 2 ;;
        --help|-h)
            echo "Usage: $0 [--dry-run] [--pan PAN] [--keys KEYS_DIR] [--verbose]"
            exit 0
            ;;
        *) log_error "Unknown option: $1"; exit 1 ;;
    esac
done

# Validate keys directory
if [[ ! -d "$KEYS_DIR" ]]; then
    log_error "Keys directory not found: $KEYS_DIR"
    log_error "Run key generation first or specify --keys <path>"
    exit 1
fi

# Generate PAN if not provided (matches personalize.sh)
if [[ -z "$PAN" ]]; then
    PAN_SUFFIX=$(printf '%07d' $((RANDOM * RANDOM % 10000000)))
    PAN="${DEFAULT_BIN}${PAN_SUFFIX}0"
    log_info "Generated PAN: ${PAN}"
fi

FULL_AID="${RID}${AID_SUFFIX}"
FULL_CONTACTLESS_AID="${RID}${CONTACTLESS_AID_SUFFIX}"

# ============================================================
# Key extraction (matches personalize.sh exactly)
# ============================================================

ICC_MODULUS="${KEYS_DIR}/icc/icc_modulus.bin"
ICC_PRIVKEY="${KEYS_DIR}/icc/icc_private.pem"
ICC_CERT="${KEYS_DIR}/icc/icc_certificate.bin"
ICC_REM="${KEYS_DIR}/icc/icc_remainder.bin"
ISSUER_CERT="${KEYS_DIR}/issuer/issuer_certificate.bin"
ISSUER_REM="${KEYS_DIR}/issuer/issuer_remainder.bin"

# ICC modulus
icc_mod_hex=""
icc_mod_size=0
if [[ -f "$ICC_MODULUS" ]]; then
    icc_mod_hex=$(xxd -p "$ICC_MODULUS" | tr -d '\n')
    icc_mod_size=$(wc -c < "$ICC_MODULUS" | tr -d ' ')
    log_info "ICC modulus: ${icc_mod_size} bytes"
fi

# ICC private exponent (extract raw exponent from PEM, not the whole PEM)
icc_priv_exp=""
icc_priv_size=0
if [[ -f "$ICC_PRIVKEY" ]]; then
    icc_priv_exp=$(openssl rsa -in "$ICC_PRIVKEY" -noout -text 2>/dev/null | \
        awk '/^privateExponent:/{flag=1; next} /^[a-zA-Z]/{flag=0} flag' | \
        tr -d ' :\n' | sed 's/^0*//')
    # Ensure even hex chars
    if (( ${#icc_priv_exp} % 2 == 1 )); then
        icc_priv_exp="0${icc_priv_exp}"
    fi
    # Pad to modulus size
    local_mod_size_hex=$(( icc_mod_size * 2 ))
    while (( ${#icc_priv_exp} < local_mod_size_hex )); do
        icc_priv_exp="0${icc_priv_exp}"
    done
    icc_priv_size=$((${#icc_priv_exp} / 2))
    log_info "ICC private exponent: ${icc_priv_size} bytes"
fi

# Certificates
icc_cert_hex=""
icc_cert_size=0
if [[ -f "$ICC_CERT" ]]; then
    icc_cert_hex=$(xxd -p "$ICC_CERT" | tr -d '\n')
    icc_cert_size=$(wc -c < "$ICC_CERT" | tr -d ' ')
fi

icc_rem_hex=""
if [[ -f "$ICC_REM" ]]; then
    icc_rem_hex=$(xxd -p "$ICC_REM" | tr -d '\n')
fi

issuer_cert_hex=""
issuer_cert_size=0
if [[ -f "$ISSUER_CERT" ]]; then
    issuer_cert_hex=$(xxd -p "$ISSUER_CERT" | tr -d '\n')
    issuer_cert_size=$(wc -c < "$ISSUER_CERT" | tr -d ' ')
fi

issuer_rem_hex=""
if [[ -f "$ISSUER_REM" ]]; then
    issuer_rem_hex=$(xxd -p "$ISSUER_REM" | tr -d '\n')
fi

# EC private key
icc_ec_priv_hex=""
if [[ -f "${KEYS_DIR}/icc/icc_ec_private.bin" ]]; then
    icc_ec_priv_hex=$(xxd -p "${KEYS_DIR}/icc/icc_ec_private.bin" | tr -d '\n')
fi

# ============================================================
# Formatting (matches personalize.sh)
# ============================================================

app_label_hex=$(echo -n "$DEFAULT_APP_LABEL" | xxd -p | tr -d '\n')
app_label_len=$(printf '%02X' ${#DEFAULT_APP_LABEL})

cardholder_name="COLOSSUS/CARD"
cardholder_hex=$(echo -n "$cardholder_name" | xxd -p | tr -d '\n')
cardholder_len=$(printf '%02X' ${#cardholder_name})

# PAN formatting
pan_hex="$PAN"
if (( ${#PAN} % 2 == 1 )); then
    pan_hex="${PAN}F"
fi
pan_bytes=$((${#pan_hex} / 2))
pan_len_hex=$(printf '%02X' $pan_bytes)

# Track 2
track2="${pan_hex}D${DEFAULT_EXPIRY:0:4}2201000000000000F"
track2="${track2:0:38}"
track2_len=$(printf '%02X' $((${#track2} / 2)))

# Directory entries
full_aid_len=$(printf '%02X' $((${#FULL_AID} / 2)))
dir_entry="4F${full_aid_len}${FULL_AID}50${app_label_len}${app_label_hex}870101"
dir_entry_len=$(printf '%02X' $((${#dir_entry} / 2)))
full_dir_entry="61${dir_entry_len}${dir_entry}"
full_dir_entry_len=$(printf '%02X' $((${#full_dir_entry} / 2)))

# PPSE directory
preferred_name="${DEFAULT_APP_LABEL} CREDIT"
preferred_name_hex=$(echo -n "$preferred_name" | xxd -p | tr -d '\n')
preferred_name_len=$(printf '%02X' ${#preferred_name})
full_contactless_aid_len=$(printf '%02X' $((${#FULL_CONTACTLESS_AID} / 2)))
# Mastercard AID auto-maps to C-2 kernel, no explicit 9F2A needed
contactless_dir="4F${full_contactless_aid_len}${FULL_CONTACTLESS_AID}50${preferred_name_len}${preferred_name_hex}9F12${preferred_name_len}${preferred_name_hex}870101"
contactless_dir_len=$(printf '%02X' $((${#contactless_dir} / 2)))

# ============================================================
# STORE DATA APDU builder
# Format: 00 E2 P1 P2 LC [DGI(2)] [BER_LEN] [DATA...]
# For data > 200 bytes, we chunk into multiple STORE DATA commands
# ============================================================

build_store_data_apdus() {
    local dgi="$1"      # 4 hex chars
    local data="$2"     # hex string
    local data_bytes=$((${#data} / 2))
    local chunk_size=200  # max data bytes per APDU (leaves room for DGI+len header)

    if (( data_bytes <= chunk_size )); then
        # Single APDU
        local ber_len
        if (( data_bytes > 127 )); then
            ber_len=$(printf '81%02X' $data_bytes)
        else
            ber_len=$(printf '%02X' $data_bytes)
        fi
        local payload="${dgi}${ber_len}${data}"
        local lc=$(printf '%02X' $((${#payload} / 2)))
        echo "-a 00E20000${lc}${payload}"
    else
        # Multiple APDUs — chunk the data, keep same DGI in each
        local offset=0
        local seq=0
        while (( offset * 2 < ${#data} )); do
            local remaining=$(( (${#data} - offset * 2) / 2 ))
            local this_size=$chunk_size
            if (( this_size > remaining )); then
                this_size=$remaining
            fi
            local chunk="${data:$((offset * 2)):$((this_size * 2))}"

            if (( offset == 0 )); then
                # First chunk includes DGI + BER total length
                local ber_len
                if (( data_bytes > 127 )); then
                    ber_len=$(printf '81%02X' $data_bytes)
                else
                    ber_len=$(printf '%02X' $data_bytes)
                fi
                local payload="${dgi}${ber_len}${chunk}"
                local lc=$(printf '%02X' $((${#payload} / 2)))
                # P1=01 means more blocks coming
                echo "-a 00E20100${lc}${payload}"
            else
                # Continuation — just raw data, no DGI header
                local lc=$(printf '%02X' $this_size)
                local is_last=$(( (offset + this_size) * 2 >= ${#data} ))
                if (( is_last )); then
                    # P1=00 = last block
                    echo "-a 00E20000${lc}${chunk}"
                else
                    # P1=01 = more coming
                    echo "-a 00E20100${lc}${chunk}"
                fi
            fi

            offset=$(( offset + this_size ))
            seq=$(( seq + 1 ))
        done
    fi
}

# Collect all APDUs
APDUS=()

add_store_data() {
    local dgi="$1"
    local data="$2"
    local desc="$3"

    local apdu_args
    apdu_args=$(build_store_data_apdus "$dgi" "$data")

    if $VERBOSE; then
        log_info "  ${desc}: DGI=${dgi} (${#data} hex chars = $(( ${#data} / 2 )) bytes)"
    fi

    while IFS= read -r line; do
        APDUS+=($line)
    done <<< "$apdu_args"
}

# ============================================================
log_step "1. PSE Personalization (1PAY.SYS.DDF01)"
# ============================================================

PSE_AID="315041592E5359532E4444463031"

# Select PSE
APDUS+=("-a" "00A404000E${PSE_AID}")
# Factory reset (dev only — harmless if production build ignores it)
APDUS+=("-a" "8005000000")

add_store_data "008E" "0E${PSE_AID}" "AID (8E)"
add_store_data "0084" "0E${PSE_AID}" "DF Name (84)"
add_store_data "0088" "0101" "SFI (88)"
add_store_data "5F2D" "656E" "Language (5F2D)"
add_store_data "B005" "008800" "FCI A5 template"
add_store_data "B004" "008400A5" "FCI 6F template"
add_store_data "0061" "${dir_entry}" "Directory entry (61)"
add_store_data "C10C" "${full_dir_entry}" "Read record SFI1/REC1"

# ============================================================
log_step "2. PPSE Personalization (2PAY.SYS.DDF01)"
# ============================================================

PPSE_AID="325041592E5359532E4444463031"

APDUS+=("-a" "00A404000E${PPSE_AID}")
APDUS+=("-a" "8005000000")

add_store_data "D001" "${contactless_dir}" "PPSE directory entry"

# ============================================================
log_step "3. Payment Application Personalization"
# ============================================================

APDUS+=("-a" "00A40400$(printf '%02X' $((${#FULL_AID} / 2)))${FULL_AID}")
APDUS+=("-a" "8005000000")

# Flags
add_store_data "A003" "0001" "Flags (randomness)"

# RSA key (modulus + exponent)
if [[ -n "$icc_mod_hex" ]]; then
    add_store_data "A004" "$icc_mod_hex" "RSA modulus (${icc_mod_size}B)"
fi
if [[ -n "$icc_priv_exp" ]]; then
    add_store_data "A005" "$icc_priv_exp" "RSA exponent (${icc_priv_size}B)"
fi

# EC private key
if [[ -n "$icc_ec_priv_hex" ]]; then
    add_store_data "A00B" "$icc_ec_priv_hex" "EC private key (32B)"
fi

# Certificates
add_store_data "008F" "0192" "CA PK index (8F)"
add_store_data "9F32" "0103" "Issuer PK exponent (9F32)"
if [[ -n "$issuer_cert_hex" ]]; then
    add_store_data "0090" "$issuer_cert_hex" "Issuer PK cert (90)"
fi
if [[ -n "$issuer_rem_hex" ]]; then
    add_store_data "0092" "$issuer_rem_hex" "Issuer PK remainder (92)"
fi
add_store_data "9F47" "0103" "ICC PK exponent (9F47)"
if [[ -n "$icc_cert_hex" ]]; then
    add_store_data "9F46" "$icc_cert_hex" "ICC PK cert (9F46)"
fi
if [[ -n "$icc_rem_hex" ]]; then
    add_store_data "9F48" "$icc_rem_hex" "ICC PK remainder (9F48)"
fi

# PIN
add_store_data "A001" "123400" "PIN code (1234)"

# Response template
add_store_data "A002" "0077" "Response template (tag 77)"

# Tag templates (matches personalize.sh exactly)
add_store_data "B001" "00820094" "GPO template (AIP+AFL)"
add_store_data "B002" "9F4B" "DDA template (9F4B)"
add_store_data "B003" "9F279F369F269F10" "GenAC template"
add_store_data "B005" "00500087" "FCI A5 template"
add_store_data "B004" "008400A5" "FCI 6F template"

# Read record templates (matches personalize.sh record layout)
add_store_data "C20C" "00575F20" "SFI1/REC2 (Track2, Name)"
add_store_data "C114" "008F00929F329F47" "SFI2/REC1 (CA/Issuer/ICC PK info)"
add_store_data "C214" "0090" "SFI2/REC2 (Issuer cert)"
add_store_data "C11C" "005A5F245F255F285F349F079F0D9F0E9F0F9F4A008C008D" "SFI3/REC1 (card data)"
add_store_data "C21C" "008E" "SFI3/REC2 (CVM list)"
add_store_data "C31C" "5F309F089F429F449F49" "SFI3/REC3 (issuer country, versions)"
add_store_data "C41C" "9F46" "SFI3/REC4 (ICC PK cert)"
add_store_data "C51C" "9F48" "SFI3/REC5 (ICC PK remainder)"

# Card data tags
add_store_data "9F36" "0001" "ATC (9F36)"
add_store_data "0084" "07${FULL_AID}" "AID (84)"
add_store_data "005A" "${pan_hex}" "PAN (5A)"
add_store_data "5F24" "03${DEFAULT_EXPIRY}" "Expiry (5F24)"
add_store_data "5F34" "0101" "PAN seq (5F34)"
add_store_data "0057" "${track2}" "Track 2 (57)"
add_store_data "0050" "${app_label_hex}" "App label (50)"
add_store_data "0087" "0101" "Priority (87)"
add_store_data "5F20" "${cardholder_hex}" "Cardholder name (5F20)"
add_store_data "9F08" "0001" "App version (9F08)"
add_store_data "5F25" "240101" "App effective date (5F25)"
add_store_data "5F28" "0840" "Issuer country (5F28)"
add_store_data "9F07" "FF0000" "AUC (9F07)"

# AIP: 3C01 (DDA, CVM, Issuer Auth, Terminal Risk, CDA)
add_store_data "0082" "3C01" "AIP (82)"
# AFL: SFI1 rec2 (0 ODA), SFI2 rec1-2 (2 ODA), SFI3 rec1-5 (0 ODA)
add_store_data "0094" "080202001001020218010500" "AFL (94)"
# SDA tag list: 82 (AIP)
add_store_data "9F4A" "0182" "SDA tag list (9F4A)"

# CDOL1: Amount(6)+AmountOther(6)+Country(2)+TVR(5)+Currency(2)+Date(3)+Type(1)+UN(4)+TermID(8)+MerchID(15)+AcqID(6)
add_store_data "008C" "9F02069F03069F1A0295055F2A029A039C019F37049F1C089F160F9F0106" "CDOL1 (8C)"
# CDOL2: same as CDOL1
add_store_data "008D" "9F02069F03069F1A0295055F2A029A039C019F37049F1C089F160F9F0106" "CDOL2 (8D)"
# CVM list: online PIN, signature, no CVM
add_store_data "008E" "000000000000000042031E031F00" "CVM list (8E)"

# ============================================================
log_step "4. Executing"
# ============================================================

log_info "Total APDUs: $((${#APDUS[@]} / 2))"

if $DRY_RUN; then
    echo ""
    log_info "Dry run — commands that would be sent:"
    echo "java -jar $GP_JAR ${APDUS[*]}"
    exit 0
fi

log_info "Sending to card via gp.jar..."
if $VERBOSE; then
    java -jar "$GP_JAR" "${APDUS[@]}" -v
else
    java -jar "$GP_JAR" "${APDUS[@]}"
fi

log_info "Personalization complete via STORE DATA."
log_info "PAN: ${PAN}"
