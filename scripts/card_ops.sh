#!/bin/bash
# Card operations: query, remove, load, personalize

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Default GP.jar location
GP_JAR="${PROJECT_ROOT}/gp.jar"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }
log_cmd() { echo -e "${CYAN}[CMD]${NC} $1"; }

# Build GP command with optional keys
build_gp_cmd() {
    local cmd="java -jar ${GP_JAR}"

    if [[ -n "$KEY_ENC" && -n "$KEY_MAC" && -n "$KEY_DEK" ]]; then
        cmd+=" --key-enc $KEY_ENC --key-mac $KEY_MAC --key-dek $KEY_DEK"
    fi

    echo "$cmd"
}

# Query card for installed applications
card_query() {
    log_info "Querying card for installed applications..."
    local gp_cmd=$(build_gp_cmd)
    log_cmd "$gp_cmd -l"

    $gp_cmd -l 2>&1 | grep -v "^WARNING:" | grep -v "^Warning:"
}

# Query card info
card_info() {
    log_info "Getting card information..."
    local gp_cmd=$(build_gp_cmd)
    log_cmd "$gp_cmd -i"

    $gp_cmd -i 2>&1 | grep -v "^WARNING:" | grep -v "^Warning:"
}

# Remove all applications (except ISD)
card_remove_all() {
    log_info "Removing all applications from card..."
    local gp_cmd=$(build_gp_cmd)

    # Get list of packages
    local packages=$($gp_cmd -l 2>&1 | grep "^PKG:" | awk '{print $2}' | grep -v "^A000000151" || true)

    if [[ -z "$packages" ]]; then
        log_info "No removable packages found"
        return 0
    fi

    for pkg in $packages; do
        log_info "Removing package: $pkg"
        $gp_cmd --delete "$pkg" --force 2>&1 | grep -v "^WARNING:" | grep -v "^Warning:" || true
    done

    log_info "Removal complete"
}

# Remove specific application
card_remove() {
    local aid="$1"

    if [[ -z "$aid" ]]; then
        log_error "AID required"
        return 1
    fi

    log_info "Removing application: $aid"
    local gp_cmd=$(build_gp_cmd)
    log_cmd "$gp_cmd --delete $aid --force"

    $gp_cmd --delete "$aid" --force 2>&1 | grep -v "^WARNING:" | grep -v "^Warning:"
}

# Load CAP file
card_load() {
    local cap_file="$1"

    if [[ -z "$cap_file" ]]; then
        log_error "CAP file path required"
        return 1
    fi

    if [[ ! -f "$cap_file" ]]; then
        log_error "CAP file not found: $cap_file"
        return 1
    fi

    log_info "Loading CAP file: $cap_file"
    local gp_cmd=$(build_gp_cmd)
    log_cmd "$gp_cmd --force --install $cap_file"

    $gp_cmd --force --install "$cap_file" 2>&1 | grep -v "^WARNING:" | grep -v "^Warning:"
}

# Send APDU commands
card_apdu() {
    local apdu="$1"

    if [[ -z "$apdu" ]]; then
        log_error "APDU required"
        return 1
    fi

    local gp_cmd=$(build_gp_cmd)
    $gp_cmd -a "$apdu" 2>&1 | grep -v "^WARNING:" | grep -v "^Warning:"
}

# Send multiple APDUs (for personalization)
card_apdu_batch() {
    local apdus=("$@")

    if [[ ${#apdus[@]} -eq 0 ]]; then
        log_error "APDUs required"
        return 1
    fi

    local gp_cmd=$(build_gp_cmd)
    gp_cmd+=" -d"  # Debug mode

    for apdu in "${apdus[@]}"; do
        gp_cmd+=" -a $apdu"
    done

    log_cmd "Sending ${#apdus[@]} APDUs..."
    eval "$gp_cmd" 2>&1 | grep -v "^WARNING:" | grep -v "^Warning:"
}

# Personalize PSE
personalize_pse() {
    local rid="$1"
    local aid="$2"
    local app_label="$3"

    log_info "Personalizing PSE..."

    # PSE AID: 1PAY.SYS.DDF01 = 315041592E5359532E4444463031
    local pse_aid="315041592E5359532E4444463031"

    # Full AID for payment app directory entry
    local full_aid="${rid}${aid}"

    # Convert app label to hex
    local app_label_hex=$(echo -n "$app_label" | xxd -p | tr -d '\n')
    local app_label_len=$(printf '%02X' ${#app_label})

    # Build directory entry: 61 len 4F len AID 50 len label 87 01 01
    local aid_len=$(printf '%02X' $((${#full_aid} / 2)))
    local dir_entry="4F${aid_len}${full_aid}50${app_label_len}${app_label_hex}870101"
    local dir_entry_len=$(printf '%02X' $((${#dir_entry} / 2)))
    local full_dir_entry="61${dir_entry_len}${dir_entry}"
    local full_dir_entry_len=$(printf '%02X' $((${#full_dir_entry} / 2)))

    local apdus=(
        # Select PSE
        "00A404000E${pse_aid}"
        # Factory reset
        "8005000000"
        # Set DF Name (tag 8E)
        "8001008E0E${pse_aid}"
        # Set DF Name for FCI (tag 84)
        "800100840E${pse_aid}"
        # Set SFI (tag 88)
        "800100880101"
        # Set Language Preference (tag 5F2D)
        "80015F2D02656E"
        # Set tag template for FCI
        "8002000502008800"
        "8002000404008400A5"
        # Set directory entry (tag 61)
        "80010061${dir_entry_len}${dir_entry}"
        # Set read record template
        "8003010C${full_dir_entry_len}${full_dir_entry}"
    )

    card_apdu_batch "${apdus[@]}"
}

# Personalize Payment App (without certificates - those come separately)
personalize_payapp_base() {
    local rid="$1"
    local aid="$2"
    local pan="$3"
    local expiry="$4"  # YYMMDD
    local app_label="$5"

    log_info "Personalizing Payment App base data..."

    local full_aid="${rid}${aid}"

    # Convert values
    local app_label_hex=$(echo -n "$app_label" | xxd -p | tr -d '\n')
    local app_label_len=$(printf '%02X' ${#app_label})
    local cardholder_name="${app_label}/CARDHOLDER "
    local cardholder_hex=$(echo -n "$cardholder_name" | xxd -p | tr -d '\n')
    local cardholder_len=$(printf '%02X' ${#cardholder_name})

    # PAN formatting
    local pan_hex=""
    local pan_len=$((${#pan}))
    if (( pan_len % 2 == 1 )); then
        pan_hex="${pan}F"
    else
        pan_hex="$pan"
    fi
    local pan_bytes=$((${#pan_hex} / 2))
    local pan_len_hex=$(printf '%02X' $pan_bytes)

    # Track 2: PAN=EXPIRY01000000000000F (service code 201, discretionary data zeros)
    local track2="${pan_hex}D${expiry:0:4}2201000000000000F"
    # Ensure track2 is proper length (max 19 bytes = 38 hex chars)
    track2="${track2:0:38}"
    local track2_len=$(printf '%02X' $((${#track2} / 2)))

    # Expiry YYMMDD -> YYMMDD format for tag 5F24
    local exp_5f24="${expiry}"
    # Effective date (tag 5F25) - use 240101 as default
    local eff_date="240101"

    local apdus=(
        # Select Payment App
        "00A4040007${full_aid}"
        # Factory reset
        "8005000000"
        # Set AID (tag 84)
        "8001008407${full_aid}"
        # Set PAN (tag 5A)
        "8001005A${pan_len_hex}${pan_hex}"
        # Set Expiry (tag 5F24)
        "80015F2403${exp_5f24}"
        # Set PAN Sequence (tag 5F34)
        "80015F340101"
        # Set Track 2 (tag 57)
        "80010057${track2_len}${track2}"
        # Set Application Label (tag 50)
        "80010050${app_label_len}${app_label_hex}"
        # Set Application Priority (tag 87)
        "800100870101"
        # Set Cardholder Name (tag 5F20)
        "80015F20${cardholder_len}${cardholder_hex}"
        # Set Application Version (tag 9F08)
        "80019F08020001"
        # Set Effective Date (tag 5F25)
        "80015F2503${eff_date}"
        # Set Issuer Country Code (tag 5F28) - US = 0840
        "80015F28020840"
        # Set AUC (tag 9F07)
        "80019F070200FF00"
        # Set AIP (tag 82) - DDA + CDA supported
        "80010082023D01"
        # Set AFL (tag 94)
        "800100940C080202001001050118010300"
        # Set SDA Tag List (tag 9F4A)
        "80019F4A0182"
        # Set CDOL1 (tag 8C)
        "8001008C1E9F02069F03069F1A0295055F2A029A039C019F37049F1C089F160F9F0106"
        # Set CDOL2 (tag 8D)
        "8001008D208A029F02069F03069F1A0295055F2A029A039C019F37049F1C089F160F9F0106"
        # Set CVM List (tag 8E) - No CVM
        "8001008E0A00000000000000001F00"
        # Set IAC Default (tag 9F0D)
        "80019F0D05FC688C9800"
        # Set IAC Denial (tag 9F0E)
        "80019F0E050010000000"
        # Set IAC Online (tag 9F0F)
        "80019F0F05FC688CF800"
        # Set IAD (tag 9F10)
        "80019F100706010A03A4A002"
        # Set ATC (tag 9F36)
        "80019F36020001"
    )

    card_apdu_batch "${apdus[@]}"
}

# Personalize Payment App certificates
personalize_payapp_certs() {
    local rid="$1"
    local aid="$2"
    local icc_cert="$3"       # Path to ICC certificate
    local icc_remainder="$4"  # Path to ICC remainder
    local icc_exponent="$5"   # Path to ICC exponent
    local icc_modulus="$6"    # Path to ICC modulus
    local icc_privkey="$7"    # Path to ICC private key
    local issuer_cert="$8"    # Path to Issuer certificate
    local issuer_remainder="$9"  # Path to Issuer remainder
    local issuer_exponent="${10}" # Path to Issuer exponent
    local capk_index="${11:-92}"  # CAPK index

    log_info "Personalizing Payment App certificates..."

    local full_aid="${rid}${aid}"

    # Read certificate files and convert to hex
    local icc_cert_hex=$(xxd -p "$icc_cert" | tr -d '\n')
    local icc_cert_size=$(stat -f%z "$icc_cert" 2>/dev/null || stat -c%s "$icc_cert")
    # For lengths >= 128, use 81XX encoding
    local icc_cert_len
    if (( icc_cert_size >= 128 )); then
        icc_cert_len=$(printf '81%02X' $icc_cert_size)
    else
        icc_cert_len=$(printf '%02X' $icc_cert_size)
    fi
    log_info "ICC cert size: ${icc_cert_size} bytes, length encoding: ${icc_cert_len}"

    local icc_rem_hex=$(xxd -p "$icc_remainder" | tr -d '\n')
    local icc_rem_size=$(stat -f%z "$icc_remainder" 2>/dev/null || stat -c%s "$icc_remainder")
    local icc_rem_len=$(printf '%02X' $icc_rem_size)
    log_info "ICC remainder size: ${icc_rem_size} bytes"

    local icc_exp_hex=$(xxd -p "$icc_exponent" | tr -d '\n')

    local icc_mod_hex=$(xxd -p "$icc_modulus" | tr -d '\n')
    local icc_mod_size=$(stat -f%z "$icc_modulus" 2>/dev/null || stat -c%s "$icc_modulus")
    # For extended APDU (256 bytes), use 00 01 00 format
    local icc_mod_len
    if (( icc_mod_size >= 256 )); then
        icc_mod_len=$(printf '00%04X' $icc_mod_size)
    else
        icc_mod_len=$(printf '%02X' $icc_mod_size)
    fi
    log_info "ICC modulus size: ${icc_mod_size} bytes, length encoding: ${icc_mod_len}"

    # Extract ICC private exponent
    local icc_priv_exp=$(openssl rsa -in "$icc_privkey" -noout -text 2>/dev/null | grep -A 100 "privateExponent:" | head -50 | grep -v "privateExponent:" | tr -d ' :\n' | sed 's/^0*//')
    # Pad to match modulus size
    local mod_size=$(( $(stat -f%z "$icc_modulus" 2>/dev/null || stat -c%s "$icc_modulus") * 2 ))
    while (( ${#icc_priv_exp} < mod_size )); do
        icc_priv_exp="0${icc_priv_exp}"
    done
    local icc_priv_size=$((${#icc_priv_exp} / 2))
    # For extended APDU (256 bytes), use 00 01 00 format
    local icc_priv_len
    if (( icc_priv_size >= 256 )); then
        icc_priv_len=$(printf '00%04X' $icc_priv_size)
    else
        icc_priv_len=$(printf '%02X' $icc_priv_size)
    fi
    log_info "ICC private exponent size: ${icc_priv_size} bytes, length encoding: ${icc_priv_len}"

    local issuer_cert_hex=$(xxd -p "$issuer_cert" | tr -d '\n')
    local issuer_cert_size=$(stat -f%z "$issuer_cert" 2>/dev/null || stat -c%s "$issuer_cert")
    # For lengths >= 128, use 81XX encoding
    local issuer_cert_len
    if (( issuer_cert_size >= 128 )); then
        issuer_cert_len=$(printf '81%02X' $issuer_cert_size)
    else
        issuer_cert_len=$(printf '%02X' $issuer_cert_size)
    fi
    log_info "Issuer cert size: ${issuer_cert_size} bytes, length encoding: ${issuer_cert_len}"

    local issuer_rem_hex=$(xxd -p "$issuer_remainder" | tr -d '\n')
    local issuer_rem_size=$(stat -f%z "$issuer_remainder" 2>/dev/null || stat -c%s "$issuer_remainder")
    local issuer_rem_len=$(printf '%02X' $issuer_rem_size)
    log_info "Issuer remainder size: ${issuer_rem_size} bytes"

    local issuer_exp_hex=$(xxd -p "$issuer_exponent" | tr -d '\n')

    local apdus=(
        # Select Payment App
        "00A4040007${full_aid}"
        # Set RSA key length setting (setting 0x0003)
        "80040003020001"
        # Set ICC modulus (setting 0x0004)
        "80040004${icc_mod_len}${icc_mod_hex}"
        # Set ICC private exponent (setting 0x0005)
        "80040005${icc_priv_len}${icc_priv_exp}"
        # Set CAPK Index (tag 8F)
        "8001008F01${capk_index}"
        # Set Issuer PK Exponent (tag 9F32)
        "80019F320103"
        # Set Issuer PK Certificate (tag 90)
        "80010090${issuer_cert_len}${issuer_cert_hex}"
        # Set Issuer PK Remainder (tag 92)
        "80010092${issuer_rem_len}${issuer_rem_hex}"
        # Set ICC PK Exponent (tag 9F47)
        "80019F470103"
        # Set ICC PK Certificate (tag 9F46)
        "80019F46${icc_cert_len}${icc_cert_hex}"
        # Set ICC PK Remainder (tag 9F48)
        "80019F48${icc_rem_len}${icc_rem_hex}"
    )

    # Set response templates
    apdus+=(
        # Template settings for response formats
        "8004000102123400"
        "8004000202007700"
        "800200010400820094"
        "80020002029F4B"
        "800200030A9F279F369F269F109F4B"
        "800200050400500087"
        "8002000404008400A5"
        "8003020C0400575F20"
        "8003011406008F9F329F4A"
        "80030214020090"
        "80030314020092"
        "80030414029F46"
        "80030514049F479F48"
        "8003011C14005A5F245F255F285F349F079F0D9F0E9F0F9F08"
        "8003021C06008C008D008E"
        "8003031C049F369F10"
    )

    card_apdu_batch "${apdus[@]}"
}

# CLI interface
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    case "$1" in
        query)
            card_query
            ;;
        info)
            card_info
            ;;
        remove-all)
            card_remove_all
            ;;
        remove)
            card_remove "$2"
            ;;
        load)
            card_load "$2"
            ;;
        apdu)
            shift
            card_apdu "$@"
            ;;
        *)
            echo "Usage: $0 {query|info|remove-all|remove|load|apdu} [args]"
            echo ""
            echo "Commands:"
            echo "  query              - List installed applications"
            echo "  info               - Get card information"
            echo "  remove-all         - Remove all applications (except ISD)"
            echo "  remove <aid>       - Remove specific application"
            echo "  load <cap>         - Load CAP file"
            echo "  apdu <apdu>        - Send APDU command"
            echo ""
            echo "Environment variables:"
            echo "  KEY_ENC, KEY_MAC, KEY_DEK - Card keys (optional, uses defaults if not set)"
            exit 1
            ;;
    esac
fi
