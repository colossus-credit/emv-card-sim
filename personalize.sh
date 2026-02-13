#!/bin/bash
#
# EMV Card Personalization Script
# Comprehensive tool for deploying and personalizing EMV JavaCard applets
#

set -e
set -o pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPTS_DIR="${SCRIPT_DIR}/scripts"
KEYS_DIR="${SCRIPT_DIR}/keys"
BUILD_DIR="${SCRIPT_DIR}/build"

# Source helper scripts
source "${SCRIPTS_DIR}/luhn.sh"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# Logging functions
log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }
log_step() { echo -e "${CYAN}[STEP]${NC} $1"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }

# Default values
DEFAULT_RID="A000000951"
DEFAULT_AID="0001"
DEFAULT_CONTACTLESS_AID="1010"
DEFAULT_BIN="66907500"
DEFAULT_APP_LABEL="COLOSSUS"
DEFAULT_EXPIRY="271231"

# Configuration variables
RID=""
AID=""
CONTACTLESS_AID=""
KEY_ENC=""
KEY_MAC=""
KEY_DEK=""
PAN=""
BIN=""
ICC_CERT=""
ICC_REM=""
ICC_EXP=""
ICC_PRIVKEY=""
ICC_MODULUS=""
ISSUER_CERT=""
ISSUER_REM=""
ISSUER_EXP=""
PSE_CAP=""
PPSE_CAP=""
PAYAPP_CAP=""
PAYAPP_CONTACTLESS_CAP=""
GEN_KEYS=false
VERBOSE=false
T0_MODE=false

# GP.jar location
GP_JAR="${SCRIPT_DIR}/gp.jar"

show_help() {
    cat << EOF
${BOLD}EMV Card Personalization Tool${NC}

${BOLD}USAGE:${NC}
    $0 [OPTIONS]

${BOLD}OPTIONS:${NC}
    ${CYAN}Card Identity:${NC}
    --rid <RID>              RID (Registered Application Provider ID)
                             Default: ${DEFAULT_RID}
    --aid <AID>              AID suffix (appended to RID)
                             Default: ${DEFAULT_AID}

    ${CYAN}Card Keys (optional):${NC}
    --key-enc <KEY>          Encryption key (hex)
    --key-mac <KEY>          MAC key (hex)
    --key-dek <KEY>          DEK key (hex)
                             If not provided, uses card default keys

    ${CYAN}PAN Configuration:${NC}
    --pan <PAN>              Primary Account Number (16 digits)
                             Must pass Luhn check
    --bin <BIN>              Bank Identification Number (8 digits)
                             Default: ${DEFAULT_BIN}
                             Used to generate PAN if --pan not specified
                             Cannot conflict with --pan

    ${CYAN}Certificate Paths:${NC}
    --icc-cert <PATH>        ICC certificate file
    --icc-rem <PATH>         ICC remainder file
    --icc-exp <PATH>         ICC exponent file
    --icc-privkey <PATH>     ICC private key file (PEM)
    --issuer-cert <PATH>     Issuer certificate file
    --issuer-rem <PATH>      Issuer remainder file
    --issuer-exp <PATH>      Issuer exponent file
                             If any --icc or --issuer provided, all must be provided
                             If none provided, uses files from keys/ directory

    ${CYAN}CAP Files:${NC}
    --pse <PATH>             PSE CAP file path
    --pay-app <PATH>         Payment App CAP file path
                             If not provided, looks in build/card/
                             If not found, offers to run build

    ${CYAN}Other Options:${NC}
    --gen-keys               Auto-generate keys without prompting
    --label <NAME>           Application label (default: ${DEFAULT_APP_LABEL})
    --expiry <YYMMDD>        Card expiry date (default: ${DEFAULT_EXPIRY})
    --t0                     T=0 protocol mode (prompts for card removal/reinsertion
                             between each gp.jar call)
    -v, --verbose            Verbose output
    -h, --help               Show this help message

${BOLD}EXAMPLES:${NC}
    # Basic personalization with defaults
    $0

    # Custom RID/AID with specific PAN
    $0 --rid A000000951 --aid 0001 --pan 6690750012345678

    # With custom keys
    $0 --key-enc 404142... --key-mac 404142... --key-dek 404142...

    # Generate fresh keys
    $0 --gen-keys

    # Specify CAP files
    $0 --pse /path/to/pse.cap --pay-app /path/to/paymentapp.cap

EOF
}

# Parse command line arguments
parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --rid)
                RID="$2"
                shift 2
                ;;
            --aid)
                AID="$2"
                shift 2
                ;;
            --key-enc)
                KEY_ENC="$2"
                shift 2
                ;;
            --key-mac)
                KEY_MAC="$2"
                shift 2
                ;;
            --key-dek)
                KEY_DEK="$2"
                shift 2
                ;;
            --pan)
                PAN="$2"
                shift 2
                ;;
            --bin)
                BIN="$2"
                shift 2
                ;;
            --icc-cert)
                ICC_CERT="$2"
                shift 2
                ;;
            --icc-rem)
                ICC_REM="$2"
                shift 2
                ;;
            --icc-exp)
                ICC_EXP="$2"
                shift 2
                ;;
            --icc-privkey)
                ICC_PRIVKEY="$2"
                shift 2
                ;;
            --issuer-cert)
                ISSUER_CERT="$2"
                shift 2
                ;;
            --issuer-rem)
                ISSUER_REM="$2"
                shift 2
                ;;
            --issuer-exp)
                ISSUER_EXP="$2"
                shift 2
                ;;
            --pse)
                PSE_CAP="$2"
                shift 2
                ;;
            --pay-app)
                PAYAPP_CAP="$2"
                shift 2
                ;;
            --gen-keys)
                GEN_KEYS=true
                shift
                ;;
            --label)
                DEFAULT_APP_LABEL="$2"
                shift 2
                ;;
            --expiry)
                DEFAULT_EXPIRY="$2"
                shift 2
                ;;
            -v|--verbose)
                VERBOSE=true
                shift
                ;;
            --t0)
                T0_MODE=true
                shift
                ;;
            -h|--help)
                show_help
                exit 0
                ;;
            *)
                log_error "Unknown option: $1"
                show_help
                exit 1
                ;;
        esac
    done
}

# Apply defaults
apply_defaults() {
    [[ -z "$RID" ]] && RID="$DEFAULT_RID"
    [[ -z "$AID" ]] && AID="$DEFAULT_AID"
    [[ -z "$CONTACTLESS_AID" ]] && CONTACTLESS_AID="$DEFAULT_CONTACTLESS_AID"
    [[ -z "$BIN" ]] && BIN="$DEFAULT_BIN"
}

# Validate PAN/BIN
validate_pan_bin() {
    log_step "Validating PAN/BIN configuration..."

    # If PAN is provided, validate it
    if [[ -n "$PAN" ]]; then
        # Check Luhn
        if ! luhn_validate "$PAN"; then
            log_error "PAN $PAN fails Luhn check"
            exit 1
        fi
        log_info "PAN passes Luhn check"

        # If BIN is also provided, check for conflict
        if [[ -n "$BIN" ]]; then
            if ! validate_bin_pan "$BIN" "$PAN"; then
                log_error "PAN $PAN does not start with BIN $BIN - conflict!"
                exit 1
            fi
            log_info "PAN matches BIN"
        fi
    else
        # Generate PAN from BIN
        log_info "Generating PAN from BIN: $BIN"
        PAN=$(generate_pan "$BIN" 16)
        log_info "Generated PAN: $PAN"

        # Verify it passes Luhn
        if ! luhn_validate "$PAN"; then
            log_error "Generated PAN fails Luhn check - this should not happen"
            exit 1
        fi
    fi

    log_success "PAN validation complete: $PAN"
}

# Check and locate CAP files
locate_cap_files() {
    log_step "Locating CAP files..."

    # PSE CAP (Contact)
    if [[ -z "$PSE_CAP" ]]; then
        if [[ -f "${BUILD_DIR}/card/pse.cap" ]]; then
            PSE_CAP="${BUILD_DIR}/card/pse.cap"
            log_info "Found PSE CAP: $PSE_CAP"
        fi
    fi

    # PPSE CAP (Contactless)
    if [[ -z "$PPSE_CAP" ]]; then
        if [[ -f "${BUILD_DIR}/card/ppse.cap" ]]; then
            PPSE_CAP="${BUILD_DIR}/card/ppse.cap"
            log_info "Found PPSE CAP: $PPSE_CAP"
        fi
    fi

    # Payment App CAP (Contact)
    if [[ -z "$PAYAPP_CAP" ]]; then
        if [[ -f "${BUILD_DIR}/card/paymentapp.cap" ]]; then
            PAYAPP_CAP="${BUILD_DIR}/card/paymentapp.cap"
            log_info "Found Payment App CAP: $PAYAPP_CAP"
        fi
    fi

    # Payment App Contactless CAP
    if [[ -z "$PAYAPP_CONTACTLESS_CAP" ]]; then
        if [[ -f "${BUILD_DIR}/card/paymentapp_contactless.cap" ]]; then
            PAYAPP_CONTACTLESS_CAP="${BUILD_DIR}/card/paymentapp_contactless.cap"
            log_info "Found Contactless Payment App CAP: $PAYAPP_CONTACTLESS_CAP"
        fi
    fi

    # If any is missing, offer to build
    if [[ -z "$PSE_CAP" || -z "$PPSE_CAP" || -z "$PAYAPP_CAP" || -z "$PAYAPP_CONTACTLESS_CAP" ]]; then
        log_warn "CAP files not found in build/card/"

        read -p "Would you like to build the CAP files? (y/n) " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            log_step "Building CAP files..."
            cd "$SCRIPT_DIR"

            # Detect Java version and use appropriate JDK
            if command -v /Library/Java/JavaVirtualMachines/jdk1.8.0_251.jdk/Contents/Home/bin/javac &> /dev/null; then
                JAVA_HOME=/Library/Java/JavaVirtualMachines/jdk1.8.0_251.jdk/Contents/Home \
                gradle cap -Pjc_version=2.2.2 \
                    -Pcompile_javac_path=/Library/Java/JavaVirtualMachines/jdk1.8.0_251.jdk/Contents/Home/bin/javac \
                    -x checkstyleMain -x checkstyleTest -x test
            else
                gradle cap -x checkstyleMain -x checkstyleTest -x test
            fi

            # Verify files were created
            if [[ -f "${BUILD_DIR}/card/pse.cap" ]]; then
                PSE_CAP="${BUILD_DIR}/card/pse.cap"
            fi
            if [[ -f "${BUILD_DIR}/card/ppse.cap" ]]; then
                PPSE_CAP="${BUILD_DIR}/card/ppse.cap"
            fi
            if [[ -f "${BUILD_DIR}/card/paymentapp.cap" ]]; then
                PAYAPP_CAP="${BUILD_DIR}/card/paymentapp.cap"
            fi
            if [[ -f "${BUILD_DIR}/card/paymentapp_contactless.cap" ]]; then
                PAYAPP_CONTACTLESS_CAP="${BUILD_DIR}/card/paymentapp_contactless.cap"
            fi
        fi
    fi

    # Final check
    if [[ -z "$PSE_CAP" || ! -f "$PSE_CAP" ]]; then
        log_error "PSE CAP file not found"
        exit 1
    fi
    if [[ -z "$PAYAPP_CAP" || ! -f "$PAYAPP_CAP" ]]; then
        log_error "Payment App CAP file not found"
        exit 1
    fi
    if [[ -z "$PAYAPP_CONTACTLESS_CAP" || ! -f "$PAYAPP_CONTACTLESS_CAP" ]]; then
        log_error "Contactless Payment App CAP file not found"
        exit 1
    fi

    log_success "CAP files located"
}

# Check and locate certificate files
locate_cert_files() {
    log_step "Locating certificate files..."

    # Check if any ICC or Issuer cert options were provided
    local icc_provided=false
    local issuer_provided=false

    [[ -n "$ICC_CERT" || -n "$ICC_REM" || -n "$ICC_EXP" || -n "$ICC_PRIVKEY" ]] && icc_provided=true
    [[ -n "$ISSUER_CERT" || -n "$ISSUER_REM" || -n "$ISSUER_EXP" ]] && issuer_provided=true

    # If any cert option provided, all must be provided
    if $icc_provided; then
        if [[ -z "$ICC_CERT" || -z "$ICC_REM" || -z "$ICC_EXP" || -z "$ICC_PRIVKEY" ]]; then
            log_error "If any --icc-* option is provided, all must be provided:"
            log_error "  --icc-cert, --icc-rem, --icc-exp, --icc-privkey"
            exit 1
        fi
    fi

    if $issuer_provided; then
        if [[ -z "$ISSUER_CERT" || -z "$ISSUER_REM" || -z "$ISSUER_EXP" ]]; then
            log_error "If any --issuer-* option is provided, all must be provided:"
            log_error "  --issuer-cert, --issuer-rem, --issuer-exp"
            exit 1
        fi
    fi

    # If neither provided, use default locations
    if ! $icc_provided && ! $issuer_provided; then
        ICC_CERT="${KEYS_DIR}/icc/icc_certificate.bin"
        ICC_REM="${KEYS_DIR}/icc/icc_remainder.bin"
        ICC_EXP="${KEYS_DIR}/icc/icc_exponent.bin"
        ICC_PRIVKEY="${KEYS_DIR}/icc/icc_private.pem"
        ICC_MODULUS="${KEYS_DIR}/icc/icc_modulus.bin"
        ISSUER_CERT="${KEYS_DIR}/issuer/issuer_certificate.bin"
        ISSUER_REM="${KEYS_DIR}/issuer/issuer_remainder.bin"
        ISSUER_EXP="${KEYS_DIR}/issuer/issuer_exponent.bin"

        # Check if default files exist
        local all_exist=true
        for f in "$ICC_CERT" "$ICC_REM" "$ICC_EXP" "$ICC_PRIVKEY" "$ISSUER_CERT" "$ISSUER_REM" "$ISSUER_EXP"; do
            if [[ ! -f "$f" ]]; then
                all_exist=false
                break
            fi
        done

        if ! $all_exist; then
            log_warn "Certificate files not found in keys/ directory"

            if $GEN_KEYS; then
                log_info "Auto-generating keys (--gen-keys specified)"
                generate_keys
            else
                read -p "Would you like to generate new keys? (y/n) " -n 1 -r
                echo
                if [[ $REPLY =~ ^[Yy]$ ]]; then
                    generate_keys
                else
                    log_error "Certificate files required but not found"
                    exit 1
                fi
            fi
        fi
    fi

    # Set ICC modulus if using default path
    [[ -z "$ICC_MODULUS" ]] && ICC_MODULUS="${KEYS_DIR}/icc/icc_modulus.bin"

    # Verify all files exist
    for f in "$ICC_CERT" "$ICC_REM" "$ICC_EXP" "$ICC_PRIVKEY" "$ISSUER_CERT" "$ISSUER_REM" "$ISSUER_EXP"; do
        if [[ ! -f "$f" ]]; then
            log_error "Certificate file not found: $f"
            exit 1
        fi
    done

    log_success "Certificate files located"
}

# Generate keys
generate_keys() {
    log_step "Generating certificate hierarchy..."

    # Save expiry before sourcing generate_keys.sh (it has its own DEFAULT_EXPIRY)
    local saved_expiry="$DEFAULT_EXPIRY"
    source "${SCRIPTS_DIR}/generate_keys.sh"
    generate_all "$PAN" "$saved_expiry"
    # Restore expiry
    DEFAULT_EXPIRY="$saved_expiry"

    log_success "Key generation complete"
}

# Regenerate just the ICC certificate with the current PAN
# This is needed because the ICC cert contains the PAN and must match
regenerate_icc_cert() {
    log_step "Regenerating ICC certificate for PAN: $PAN..."

    # Save expiry before sourcing generate_keys.sh (it has its own DEFAULT_EXPIRY)
    local saved_expiry="$DEFAULT_EXPIRY"
    source "${SCRIPTS_DIR}/generate_keys.sh"
    generate_icc "$PAN" "$saved_expiry"
    # Restore expiry
    DEFAULT_EXPIRY="$saved_expiry"

    log_success "ICC certificate regenerated"
}

# Build GP command
build_gp_cmd() {
    local cmd="java -jar ${GP_JAR}"

    if [[ -n "$KEY_ENC" && -n "$KEY_MAC" && -n "$KEY_DEK" ]]; then
        cmd+=" --key-enc $KEY_ENC --key-mac $KEY_MAC --key-dek $KEY_DEK"
    fi

    echo "$cmd"
}

# Prompt for card removal and reinsertion (T=0 mode only)
prompt_card_cycle() {
    if ! $T0_MODE; then
        return
    fi
    local phase="$1"
    echo ""
    echo -e "${BOLD}========================================${NC}"
    echo -e "${YELLOW}  T=0 Card Cycle Required${NC}"
    echo -e "${BOLD}========================================${NC}"
    echo ""
    echo -e "  ${CYAN}Completed:${NC} $phase"
    echo ""
    echo -e "  1. ${RED}REMOVE${NC} the card from the reader"
    echo -e "  2. Wait 2 seconds"
    echo -e "  3. ${GREEN}REINSERT${NC} the card into the reader"
    echo ""
    read -p "  Press ENTER when card has been reinserted..." -r
    echo ""
    log_info "Continuing..."
}

# Query card for apps
query_card() {
    log_step "Querying card for installed applications..."
    local gp_cmd=$(build_gp_cmd)

    $gp_cmd -l 2>&1 | grep -v "^WARNING:" | grep -v "^Warning:" || true
}

# Remove all apps
remove_all_apps() {
    log_step "Removing all applications from card..."
    local gp_cmd=$(build_gp_cmd)

    # Get list of packages (excluding system packages)
    local packages=$($gp_cmd -l 2>&1 | grep "^PKG:" | awk '{print $2}' | grep -v "^A000000151" || true)

    if [[ -z "$packages" ]]; then
        log_info "No removable packages found"
        return 0
    fi

    for pkg in $packages; do
        log_info "Removing package: $pkg"
        $gp_cmd --delete "$pkg" --force 2>&1 | grep -v "^WARNING:" | grep -v "^Warning:" || true
    done

    log_success "Removal complete"
}

# Load CAP files
load_cap_files() {
    log_step "Loading CAP files to card..."
    local gp_cmd=$(build_gp_cmd)

    log_info "Loading PSE (Contact): $PSE_CAP"
    $gp_cmd --force --install "$PSE_CAP" 2>&1 | grep -v "^WARNING:" | grep -v "^Warning:"

    prompt_card_cycle "Installed PSE CAP"

    if [[ -n "$PPSE_CAP" && -f "$PPSE_CAP" ]]; then
        log_info "Loading PPSE (Contactless): $PPSE_CAP"
        $gp_cmd --force --install "$PPSE_CAP" 2>&1 | grep -v "^WARNING:" | grep -v "^Warning:"

        prompt_card_cycle "Installed PPSE CAP"
    fi

    log_info "Loading Payment App (Contact): $PAYAPP_CAP"
    $gp_cmd --force --install "$PAYAPP_CAP" 2>&1 | grep -v "^WARNING:" | grep -v "^Warning:"

    prompt_card_cycle "Installed Payment App CAP"

    if [[ -n "$PAYAPP_CONTACTLESS_CAP" && -f "$PAYAPP_CONTACTLESS_CAP" ]]; then
        log_info "Loading Payment App (Contactless): $PAYAPP_CONTACTLESS_CAP"
        $gp_cmd --force --install "$PAYAPP_CONTACTLESS_CAP" 2>&1 | grep -v "^WARNING:" | grep -v "^Warning:"
    fi

    log_success "CAP files loaded"
}

# Personalize the card
personalize_card() {
    log_step "Personalizing card..."

    local full_aid="${RID}${AID}"
    local gp_cmd=$(build_gp_cmd)
    gp_cmd+=" -d"

    # Build all APDUs
    local pse_aid="315041592E5359532E4444463031"

    # Convert values to hex
    local app_label_hex=$(echo -n "$DEFAULT_APP_LABEL" | xxd -p | tr -d '\n')
    local app_label_len=$(printf '%02X' ${#DEFAULT_APP_LABEL})
    local cardholder_name="${DEFAULT_APP_LABEL}/CARDHOLDER "
    local cardholder_hex=$(echo -n "$cardholder_name" | xxd -p | tr -d '\n')
    local cardholder_len=$(printf '%02X' ${#cardholder_name})

    # Preferred name for 9F12 (e.g., "COLOSSUS CREDIT")
    local preferred_name="${DEFAULT_APP_LABEL} CREDIT"
    local preferred_name_hex=$(echo -n "$preferred_name" | xxd -p | tr -d '\n')
    local preferred_name_len=$(printf '%02X' ${#preferred_name})

    # PAN formatting
    local pan_hex="$PAN"
    if (( ${#PAN} % 2 == 1 )); then
        pan_hex="${PAN}F"
    fi
    local pan_bytes=$((${#pan_hex} / 2))
    local pan_len_hex=$(printf '%02X' $pan_bytes)

    # Track 2
    local track2="${pan_hex}D${DEFAULT_EXPIRY:0:4}2201000000000000F"
    track2="${track2:0:38}"
    local track2_len=$(printf '%02X' $((${#track2} / 2)))

    # Directory entry for PSE
    local full_aid_len=$(printf '%02X' $((${#full_aid} / 2)))
    local dir_entry="4F${full_aid_len}${full_aid}50${app_label_len}${app_label_hex}870101"
    local dir_entry_len=$(printf '%02X' $((${#dir_entry} / 2)))
    local full_dir_entry="61${dir_entry_len}${dir_entry}"
    local full_dir_entry_len=$(printf '%02X' $((${#full_dir_entry} / 2)))

    # Certificate data - with extended TLV length encoding for RSA-2048
    local icc_cert_hex=$(xxd -p "$ICC_CERT" | tr -d '\n')
    local icc_cert_size=$(wc -c < "$ICC_CERT" | tr -d ' ')
    # APDU LC for raw certificate (no TLV encoding - card adds TLV when returning)
    local icc_cert_lc
    if (( icc_cert_size > 255 )); then
        icc_cert_lc=$(printf '00%04X' $icc_cert_size)
    else
        icc_cert_lc=$(printf '%02X' $icc_cert_size)
    fi

    local icc_rem_hex=$(xxd -p "$ICC_REM" | tr -d '\n')
    local icc_rem_size=$(wc -c < "$ICC_REM" | tr -d ' ')
    local icc_rem_len=$(printf '%02X' $icc_rem_size)

    local icc_mod_hex=$(xxd -p "$ICC_MODULUS" | tr -d '\n')
    local icc_mod_size=$(wc -c < "$ICC_MODULUS" | tr -d ' ')
    # For APDU LC: use extended length format (00 HH LL) for 256+ bytes
    local icc_mod_len
    if (( icc_mod_size >= 256 )); then
        icc_mod_len=$(printf '00%04X' $icc_mod_size)
    else
        icc_mod_len=$(printf '%02X' $icc_mod_size)
    fi

    # Extract ICC private exponent (only the privateExponent field, not prime1, prime2, etc.)
    local icc_priv_exp=$(openssl rsa -in "$ICC_PRIVKEY" -noout -text 2>/dev/null | awk '/^privateExponent:/{flag=1; next} /^[a-zA-Z]/{flag=0} flag' | tr -d ' :\n' | sed 's/^0*//')
    # Ensure even number of hex characters (pad with leading zero if odd)
    if (( ${#icc_priv_exp} % 2 == 1 )); then
        icc_priv_exp="0${icc_priv_exp}"
    fi
    local mod_size_hex=$(( icc_mod_size * 2 ))
    while (( ${#icc_priv_exp} < mod_size_hex )); do
        icc_priv_exp="0${icc_priv_exp}"
    done
    local icc_priv_size=$((${#icc_priv_exp} / 2))
    local icc_priv_len
    if (( icc_priv_size >= 256 )); then
        icc_priv_len=$(printf '00%04X' $icc_priv_size)
    else
        icc_priv_len=$(printf '%02X' $icc_priv_size)
    fi

    local issuer_cert_hex=$(xxd -p "$ISSUER_CERT" | tr -d '\n')
    local issuer_cert_size=$(wc -c < "$ISSUER_CERT" | tr -d ' ')
    # APDU LC for raw certificate (no TLV encoding - card adds TLV when returning)
    local issuer_cert_lc
    if (( issuer_cert_size > 255 )); then
        issuer_cert_lc=$(printf '00%04X' $issuer_cert_size)
    else
        issuer_cert_lc=$(printf '%02X' $issuer_cert_size)
    fi

    local issuer_rem_hex=$(xxd -p "$ISSUER_REM" | tr -d '\n')
    local issuer_rem_size=$(wc -c < "$ISSUER_REM" | tr -d ' ')
    local issuer_rem_len=$(printf '%02X' $issuer_rem_size)

    # EC private key (P-256, 32 bytes)
    local icc_ec_priv_hex=""
    if [[ -f "${KEYS_DIR}/icc/icc_ec_private.bin" ]]; then
        icc_ec_priv_hex=$(xxd -p "${KEYS_DIR}/icc/icc_ec_private.bin" | tr -d '\n')
    fi

    # Build APDU list
    gp_cmd+=" -a 00A404000E${pse_aid}"
    gp_cmd+=" -a 8005000000"
    gp_cmd+=" -a 8001008E0E${pse_aid}"
    gp_cmd+=" -a 800100840E${pse_aid}"
    gp_cmd+=" -a 800100880101"
    gp_cmd+=" -a 80015F2D02656E"
    gp_cmd+=" -a 8002000502008800"
    gp_cmd+=" -a 8002000404008400A5"
    gp_cmd+=" -a 80010061${dir_entry_len}${dir_entry}"
    gp_cmd+=" -a 8003010C${full_dir_entry_len}${full_dir_entry}"

    # PPSE personalization (Contactless) - points to contactless payment app
    # FCI structure: 6F -> 84 (PPSE AID), A5 -> BF0C -> 61 (directory entry)
    local ppse_aid="325041592E5359532E4444463031"
    local full_contactless_aid="${RID}${CONTACTLESS_AID}"
    local full_contactless_aid_len=$(printf '%02X' $((${#full_contactless_aid} / 2)))
    # Application label and preferred name both use "VISA CREDIT" to match working Visa response
    local ppse_label="${DEFAULT_APP_LABEL} CREDIT"
    local ppse_label_hex=$(echo -n "$ppse_label" | xxd -p | tr -d '\n')
    local ppse_label_len=$(printf '%02X' ${#ppse_label})
    # Directory entry: 4F(AID) + 50(label="VISA CREDIT") + 9F12(preferred name="VISA CREDIT") + 87(priority)
    local contactless_dir_entry="4F${full_contactless_aid_len}${full_contactless_aid}50${ppse_label_len}${ppse_label_hex}9F12${ppse_label_len}${ppse_label_hex}870101"
    local contactless_dir_entry_len=$(printf '%02X' $((${#contactless_dir_entry} / 2)))
    gp_cmd+=" -a 00A404000E${ppse_aid}"
    gp_cmd+=" -a 8005000000"
    # Set directory entry content pointing to contactless AID
    gp_cmd+=" -a 80010061${contactless_dir_entry_len}${contactless_dir_entry}"

    # Contact Payment app selection and base personalization
    gp_cmd+=" -a 00A4040007${full_aid}"
    gp_cmd+=" -a 8005000000"
    gp_cmd+=" -a 80040003020001"
    gp_cmd+=" -a 80040004${icc_mod_len}${icc_mod_hex}"
    gp_cmd+=" -a 80040005${icc_priv_len}${icc_priv_exp}"
    # EC private key (setting 0x000B, 32 bytes)
    if [[ -n "$icc_ec_priv_hex" ]]; then
        gp_cmd+=" -a 8004000B20${icc_ec_priv_hex}"
    fi
    gp_cmd+=" -a 8001008F0192"
    gp_cmd+=" -a 80019F320103"
    gp_cmd+=" -a 80010090${issuer_cert_lc}${issuer_cert_hex}"
    gp_cmd+=" -a 80010092${issuer_rem_len}${issuer_rem_hex}"
    gp_cmd+=" -a 80019F470103"
    gp_cmd+=" -a 80019F46${icc_cert_lc}${icc_cert_hex}"
    gp_cmd+=" -a 80019F48${icc_rem_len}${icc_rem_hex}"
    gp_cmd+=" -a 8004000102123400"
    gp_cmd+=" -a 8004000202008000"
    # GPO response template: AIP (82), CTQ (9F6C), AFL (94) - CTQ required for contactless
    gp_cmd+=" -a 800200010400820094"
    gp_cmd+=" -a 80020002029F4B"
    gp_cmd+=" -a 80020003089F279F369F269F10"
    # FCI template: 50 (label), 87 (priority) - NO 9F38 (PDOL) so card accepts empty GPO
    gp_cmd+=" -a 800200050400500087"
    gp_cmd+=" -a 8002000404008400A5"
    # PDOL removed from FCI - card accepts empty GPO (83 00)
    # gp_cmd+=" -a 80019F38189F66049F02069F03069F1A0295055F2A029A039C019F3704"
    # SFI1/REC2: 57, 5F20, 9F1F (len=06: 00 + 1+2+2)
    gp_cmd+=" -a 8003020C0400575F20"
    # SFI2/REC1: 8F, 92, 9F32, 9F47 (len=08: 008F + 0092 + 9F32 + 9F47)
    gp_cmd+=" -a 8003011408008F00929F329F47"
    # SFI2/REC2: 90 only (len=02: 00 + 1)
    gp_cmd+=" -a 80030214020090"
    # SFI2/REC3-5 removed (Visa uses only 2 records on SFI2)
    # SFI3/REC1: 5A,5F24,5F25,5F28,5F34,9F07,9F0D,9F0E,9F0F,9F4A,8C,8D (len=18: 005A + 9x2byte + 008C + 008D)
    gp_cmd+=" -a 8003011C18005A5F245F255F285F349F079F0D9F0E9F0F9F4A008C008D"
    # SFI3/REC2: 8E only (len=02: 00 + 1)
    gp_cmd+=" -a 8003021C02008E"
    # SFI3/REC3: 5F30,9F08,9F42,9F44,9F49 (all 2-byte tags, len=0A)
    gp_cmd+=" -a 8003031C0A5F309F089F429F449F49"
    # SFI3/REC4: 9F46 (ICC PK Cert, len=02)
    gp_cmd+=" -a 8003041C029F46"
    # SFI3/REC5: 9F48 (ICC PK Remainder, len=02) - must be in non-ODA SFI to avoid ICC cert hash mismatch
    gp_cmd+=" -a 8003051C029F48"

    # Continue with remaining tags (single batch for proper data storage)
    gp_cmd+=" -a 80019F36020001"
    gp_cmd+=" -a 8001008407${full_aid}"
    gp_cmd+=" -a 8001005A${pan_len_hex}${pan_hex}"
    gp_cmd+=" -a 80015F2403${DEFAULT_EXPIRY}"
    gp_cmd+=" -a 80015F340101"
    gp_cmd+=" -a 80010057${track2_len}${track2}"
    gp_cmd+=" -a 80010050${app_label_len}${app_label_hex}"
    gp_cmd+=" -a 800100870101"
    gp_cmd+=" -a 80015F20${cardholder_len}${cardholder_hex}"
    gp_cmd+=" -a 80019F08020001"
    gp_cmd+=" -a 80015F2503240101"
    gp_cmd+=" -a 80015F28020840"
    gp_cmd+=" -a 80019F0702FF0000"
    # AIP: 3C01 (DDA supported, cardholder verification, issuer auth, terminal risk management)
    gp_cmd+=" -a 80010082023C01"
    # AFL: SFI1 rec2 (0 ODA), SFI2 rec1-2 (2 ODA), SFI3 rec1-5 (0 ODA)
    gp_cmd+=" -a 800100940C080202001001020218010500"
    # 9F4A = Static Data Auth Tag List: 82 (AIP) - Visa style single byte
    gp_cmd+=" -a 80019F4A0182"
    # 9F1F = Track 1 Discretionary Data (19 bytes of zeros)
    gp_cmd+=" -a 80019F1F1300000000000000000000000000000000000000"
    # 5F30 = Service Code
    gp_cmd+=" -a 80015F30020201"
    # 9F42 = Application Currency Code (USD = 0840)
    gp_cmd+=" -a 80019F42020840"
    # 9F44 = Application Currency Exponent
    gp_cmd+=" -a 80019F440102"
    # 9F49 = DDOL (matches CDOL1: Amount, Amount Other, Country, TVR, Currency, Date, Txn Type, UN, Terminal ID, Merchant ID, Acquirer ID)
    gp_cmd+=" -a 80019F491E9F02069F03069F1A0295055F2A029A039C019F37049F1C089F160F9F0106"
    gp_cmd+=" -a 8001008C1E9F02069F03069F1A0295055F2A029A039C019F37049F1C089F160F9F0106"
    gp_cmd+=" -a 8001008D208A029F02069F03069F1A0295055F2A029A039C019F37049F1C089F160F9F0106"
    # CVM List (20 bytes - Visa format)
    gp_cmd+=" -a 8001008E0A00000000000000001F00"
    # IAC-Default: conditions that default to online
    gp_cmd+=" -a 80019F0D05FC688C9800"
    # IAC-Denial: set to zeros so nothing triggers offline decline
    gp_cmd+=" -a 80019F0E050000000000"
    # IAC-Online: conditions that require online
    gp_cmd+=" -a 80019F0F05FC68FC9800"
    gp_cmd+=" -a 80019F100706010A03A4A002"
    # CTQ (Card Transaction Qualifiers) - required for contactless
    # Byte 1: 80 = Online cryptogram required (typical for ARQC transactions)
    # Byte 2: 00 = No special processing flags
    gp_cmd+=" -a 80019F6C02A000"

    # Contactless Payment app personalization (same data, different AID)
    gp_cmd+=" -a 00A4040007${full_contactless_aid}"
    gp_cmd+=" -a 8005000000"
    gp_cmd+=" -a 80040003020001"
    gp_cmd+=" -a 80040004${icc_mod_len}${icc_mod_hex}"
    gp_cmd+=" -a 80040005${icc_priv_len}${icc_priv_exp}"
    # EC private key (setting 0x000B, 32 bytes)
    if [[ -n "$icc_ec_priv_hex" ]]; then
        gp_cmd+=" -a 8004000B20${icc_ec_priv_hex}"
    fi
    gp_cmd+=" -a 8001008F0192"
    gp_cmd+=" -a 80019F320103"
    gp_cmd+=" -a 80010090${issuer_cert_lc}${issuer_cert_hex}"
    gp_cmd+=" -a 80010092${issuer_rem_len}${issuer_rem_hex}"
    gp_cmd+=" -a 80019F470103"
    gp_cmd+=" -a 80019F46${icc_cert_lc}${icc_cert_hex}"
    gp_cmd+=" -a 80019F48${icc_rem_len}${icc_rem_hex}"
    gp_cmd+=" -a 8004000102123400"
    gp_cmd+=" -a 8004000202008000"
    # GPO template: Format 1 = AIP (82) + AFL (94) only, no CTQ for Format 1
    gp_cmd+=" -a 800200010400820094"
    gp_cmd+=" -a 80020002029F4B"
    gp_cmd+=" -a 80020003089F279F369F269F10"
    # FCI template: 50 (label), 87 (priority), 9F12 (preferred name), 9F38 (PDOL)
    gp_cmd+=" -a 8002000508005000879F129F38"
    gp_cmd+=" -a 8002000404008400A5"
    gp_cmd+=" -a 8003020C0400575F20"
    gp_cmd+=" -a 8003011408008F00929F329F47"
    gp_cmd+=" -a 80030214020090"
    gp_cmd+=" -a 8003011C18005A5F245F255F285F349F079F0D9F0E9F0F9F4A008C008D"
    gp_cmd+=" -a 8003021C02008E"
    gp_cmd+=" -a 8003031C0A5F309F089F429F449F49"
    gp_cmd+=" -a 8003041C029F46"
    gp_cmd+=" -a 8003051C029F48"
    gp_cmd+=" -a 80019F36020001"
    gp_cmd+=" -a 8001008407${full_contactless_aid}"
    # 9F12 Application Preferred Name (reuse preferred_name from PPSE section)
    gp_cmd+=" -a 80019F12${preferred_name_len}${preferred_name_hex}"
    # PDOL: TTQ(4), Amount(6), AmountOther(6), Country(2), TVR(5), Currency(2), Date(3), Type(1), UN(4)
    gp_cmd+=" -a 80019F38189F66049F02069F03069F1A0295055F2A029A039C019F3704"
    gp_cmd+=" -a 8001005A${pan_len_hex}${pan_hex}"
    gp_cmd+=" -a 80015F2403${DEFAULT_EXPIRY}"
    gp_cmd+=" -a 80015F340101"
    gp_cmd+=" -a 80010057${track2_len}${track2}"
    gp_cmd+=" -a 80010050${app_label_len}${app_label_hex}"
    gp_cmd+=" -a 800100870101"
    gp_cmd+=" -a 80015F20${cardholder_len}${cardholder_hex}"
    gp_cmd+=" -a 80019F08020001"
    gp_cmd+=" -a 80015F2503240101"
    gp_cmd+=" -a 80015F28020840"
    gp_cmd+=" -a 80019F0702FF0000"
    # AIP: 2000 for qVSDC with fDDA (byte 1 bit 6 = DDA supported)
    gp_cmd+=" -a 80010082022000"
    gp_cmd+=" -a 800100940C080202001001020218010500"
    gp_cmd+=" -a 80019F4A0182"
    gp_cmd+=" -a 80019F1F1300000000000000000000000000000000000000"
    gp_cmd+=" -a 80015F30020201"
    gp_cmd+=" -a 80019F42020840"
    gp_cmd+=" -a 80019F440102"
    # 9F49 = DDOL (matches CDOL1: Amount, Amount Other, Country, TVR, Currency, Date, Txn Type, UN, Terminal ID, Merchant ID, Acquirer ID)
    gp_cmd+=" -a 80019F491E9F02069F03069F1A0295055F2A029A039C019F37049F1C089F160F9F0106"
    gp_cmd+=" -a 8001008C1E9F02069F03069F1A0295055F2A029A039C019F37049F1C089F160F9F0106"
    gp_cmd+=" -a 8001008D208A029F02069F03069F1A0295055F2A029A039C019F37049F1C089F160F9F0106"
    gp_cmd+=" -a 8001008E0A00000000000000001F00"
    gp_cmd+=" -a 80019F0D05FC688C9800"
    gp_cmd+=" -a 80019F0E050000000000"
    gp_cmd+=" -a 80019F0F05FC68FC9800"
    gp_cmd+=" -a 80019F100706010A03A4A002"
    gp_cmd+=" -a 80019F6C02A000"

    log_info "Sending personalization APDUs..."

    # Debug: dump gp_cmd to file for inspection
    echo "$gp_cmd" > /tmp/gp_cmd_debug.txt
    log_info "APDU command saved to /tmp/gp_cmd_debug.txt"

    eval "$gp_cmd" 2>&1 | grep -v "^WARNING:" | grep -v "^Warning:"

    log_success "Personalization complete"
}

# Personalize PSE only (for T=0 mode)
personalize_pse() {
    log_step "Personalizing PSE..."

    local full_aid="${RID}${AID}"
    local gp_cmd=$(build_gp_cmd)
    gp_cmd+=" -d"

    local pse_aid="315041592E5359532E4444463031"

    # Convert values to hex
    local app_label_hex=$(echo -n "$DEFAULT_APP_LABEL" | xxd -p | tr -d '\n')
    local app_label_len=$(printf '%02X' ${#DEFAULT_APP_LABEL})

    # Directory entry for PSE
    local full_aid_len=$(printf '%02X' $((${#full_aid} / 2)))
    local dir_entry="4F${full_aid_len}${full_aid}50${app_label_len}${app_label_hex}870101"
    local dir_entry_len=$(printf '%02X' $((${#dir_entry} / 2)))
    local full_dir_entry="61${dir_entry_len}${dir_entry}"
    local full_dir_entry_len=$(printf '%02X' $((${#full_dir_entry} / 2)))

    # PSE personalization APDUs
    gp_cmd+=" -a 00A404000E${pse_aid}"
    gp_cmd+=" -a 8005000000"
    gp_cmd+=" -a 8001008E0E${pse_aid}"
    gp_cmd+=" -a 800100840E${pse_aid}"
    gp_cmd+=" -a 800100880101"
    gp_cmd+=" -a 80015F2D02656E"
    gp_cmd+=" -a 8002000502008800"
    gp_cmd+=" -a 8002000404008400A5"
    gp_cmd+=" -a 80010061${dir_entry_len}${dir_entry}"
    gp_cmd+=" -a 8003010C${full_dir_entry_len}${full_dir_entry}"

    log_info "Sending PSE personalization APDUs..."
    eval "$gp_cmd" 2>&1 | grep -v "^WARNING:" | grep -v "^Warning:"

    log_success "PSE personalization complete"
}

# Personalize PPSE only (for contactless support)
personalize_ppse() {
    log_step "Personalizing PPSE (Contactless)..."

    # Use contactless AID for PPSE directory
    local full_contactless_aid="${RID}${CONTACTLESS_AID}"
    local gp_cmd=$(build_gp_cmd)
    gp_cmd+=" -d"

    local ppse_aid="325041592E5359532E4444463031"

    # Application label and preferred name both use "VISA CREDIT" to match working Visa response
    local ppse_label="${DEFAULT_APP_LABEL} CREDIT"
    local ppse_label_hex=$(echo -n "$ppse_label" | xxd -p | tr -d '\n')
    local ppse_label_len=$(printf '%02X' ${#ppse_label})

    # Directory entry content: 4F <AID>, 50 <label="VISA CREDIT">, 9F12 <preferred name="VISA CREDIT">, 87 <priority>
    local full_aid_len=$(printf '%02X' $((${#full_contactless_aid} / 2)))
    local dir_entry_content="4F${full_aid_len}${full_contactless_aid}50${ppse_label_len}${ppse_label_hex}9F12${ppse_label_len}${ppse_label_hex}870101"
    local dir_entry_content_len=$(printf '%02X' $((${#dir_entry_content} / 2)))

    # PPSE personalization APDUs (new simplified applet)
    # Select PPSE
    gp_cmd+=" -a 00A404000E${ppse_aid}"
    # Factory reset
    gp_cmd+=" -a 8005000000"
    # Set directory entry content (command 80 01 00 61)
    # The applet will build FCI with BF0C containing 61 wrapper around this content
    gp_cmd+=" -a 80010061${dir_entry_content_len}${dir_entry_content}"

    log_info "Sending PPSE personalization APDUs..."
    eval "$gp_cmd" 2>&1 | grep -v "^WARNING:" | grep -v "^Warning:"

    log_success "PPSE personalization complete"
}

# Personalize Payment Application - small APDUs only (templates, tags, AIP, AFL)
# This is called first to ensure basic card functionality works
personalize_payapp_small() {
    log_step "Personalizing Payment Application (basic tags)..."

    local full_aid="${RID}${AID}"
    local gp_cmd=$(build_gp_cmd)
    gp_cmd+=" -d"

    # Convert values to hex
    local app_label_hex=$(echo -n "$DEFAULT_APP_LABEL" | xxd -p | tr -d '\n')
    local app_label_len=$(printf '%02X' ${#DEFAULT_APP_LABEL})
    local cardholder_name="${DEFAULT_APP_LABEL}/CARDHOLDER "
    local cardholder_hex=$(echo -n "$cardholder_name" | xxd -p | tr -d '\n')
    local cardholder_len=$(printf '%02X' ${#cardholder_name})

    # PAN formatting
    local pan_hex="$PAN"
    if (( ${#PAN} % 2 == 1 )); then
        pan_hex="${PAN}F"
    fi
    local pan_bytes=$((${#pan_hex} / 2))
    local pan_len_hex=$(printf '%02X' $pan_bytes)

    # Track 2
    local track2="${pan_hex}D${DEFAULT_EXPIRY:0:4}2201000000000000F"
    track2="${track2:0:38}"
    local track2_len=$(printf '%02X' $((${#track2} / 2)))

    # ICC remainder (small - usually <42 bytes)
    local icc_rem_hex=$(xxd -p "$ICC_REM" | tr -d '\n')
    local icc_rem_size=$(wc -c < "$ICC_REM" | tr -d ' ')
    local icc_rem_len=$(printf '%02X' $icc_rem_size)

    # Issuer remainder (small)
    local issuer_rem_hex=$(xxd -p "$ISSUER_REM" | tr -d '\n')
    local issuer_rem_size=$(wc -c < "$ISSUER_REM" | tr -d ' ')
    local issuer_rem_len=$(printf '%02X' $issuer_rem_size)

    # Payment app selection and factory reset
    gp_cmd+=" -a 00A4040007${full_aid}"
    gp_cmd+=" -a 8005000000"

    # Settings (small)
    gp_cmd+=" -a 80040003020001"
    gp_cmd+=" -a 8004000102123400"
    gp_cmd+=" -a 8004000202008000"

    # Templates - only non-certificate related ones
    # GPO response template: AIP (82), CTQ (9F6C), AFL (94) - CTQ required for contactless
    gp_cmd+=" -a 800200010400820094"
    gp_cmd+=" -a 80020002029F4B"
    gp_cmd+=" -a 80020003089F279F369F269F10"
    gp_cmd+=" -a 800200050400500087"
    gp_cmd+=" -a 8002000404008400A5"
    # SFI 1 Record 2: 57, 5F20, 9F1F (no certs)
    gp_cmd+=" -a 8003020C0400575F20"
    # SFI 3 Record 1: non-cert tags only
    gp_cmd+=" -a 8003011C18005A5F245F255F285F349F079F0D9F0E9F0F9F4A008C008D"
    # SFI 3 Record 2: 8E (CVM list, no certs)
    gp_cmd+=" -a 8003021C02008E"
    # SFI 3 Record 3: 5F30,9F08,9F42,9F44,9F49 (no certs)
    gp_cmd+=" -a 8003031C0A5F309F089F429F449F49"
    # NOTE: SFI 2 (cert records) and SFI 3 Record 4 (ICC cert) templates moved to personalize_payapp_large

    # Small EMV tags - CRITICAL: AIP and AFL
    gp_cmd+=" -a 80010082023C01"
    gp_cmd+=" -a 800100940C080202001001020218010500"

    # Other small tags
    gp_cmd+=" -a 80019F36020001"
    gp_cmd+=" -a 8001008407${full_aid}"
    gp_cmd+=" -a 8001005A${pan_len_hex}${pan_hex}"
    gp_cmd+=" -a 80015F2403${DEFAULT_EXPIRY}"
    gp_cmd+=" -a 80015F340101"
    gp_cmd+=" -a 80010057${track2_len}${track2}"
    gp_cmd+=" -a 80010050${app_label_len}${app_label_hex}"
    gp_cmd+=" -a 800100870101"
    gp_cmd+=" -a 80015F20${cardholder_len}${cardholder_hex}"
    gp_cmd+=" -a 80019F08020001"
    gp_cmd+=" -a 80015F2503240101"
    gp_cmd+=" -a 80015F28020840"
    gp_cmd+=" -a 80019F0702FF0000"
    gp_cmd+=" -a 80019F4A0182"
    gp_cmd+=" -a 80019F1F1300000000000000000000000000000000000000"
    gp_cmd+=" -a 80015F30020201"
    gp_cmd+=" -a 80019F42020840"
    gp_cmd+=" -a 80019F440102"
    # 9F49 = DDOL (matches CDOL1: Amount, Amount Other, Country, TVR, Currency, Date, Txn Type, UN, Terminal ID, Merchant ID, Acquirer ID)
    gp_cmd+=" -a 80019F491E9F02069F03069F1A0295055F2A029A039C019F37049F1C089F160F9F0106"
    gp_cmd+=" -a 8001008C1E9F02069F03069F1A0295055F2A029A039C019F37049F1C089F160F9F0106"
    gp_cmd+=" -a 8001008D208A029F02069F03069F1A0295055F2A029A039C019F37049F1C089F160F9F0106"
    gp_cmd+=" -a 8001008E0A00000000000000001F00"
    gp_cmd+=" -a 80019F0D05FC688C9800"
    gp_cmd+=" -a 80019F0E050000000000"
    gp_cmd+=" -a 80019F0F05FC68FC9800"
    gp_cmd+=" -a 80019F100706010A03A4A002"
    # CTQ (Card Transaction Qualifiers) - required for contactless
    # Byte 1: 80 = Online cryptogram required (typical for ARQC transactions)
    # Byte 2: 00 = No special processing flags
    gp_cmd+=" -a 80019F6C02A000"

    # Small certificate-related tags
    gp_cmd+=" -a 8001008F0192"
    gp_cmd+=" -a 80019F320103"
    gp_cmd+=" -a 80019F470103"
    gp_cmd+=" -a 80010092${issuer_rem_len}${issuer_rem_hex}"
    gp_cmd+=" -a 80019F48${icc_rem_len}${icc_rem_hex}"

    log_info "Sending basic Payment App APDUs..."
    eval "$gp_cmd" 2>&1 | grep -v "^WARNING:" | grep -v "^Warning:"

    log_success "Payment Application basic personalization complete"
}

# Generate chunked APDU commands for large tag data
# Usage: generate_chunked_apdus TAG_HEX DATA_HEX
# Returns: space-separated list of -a APDU arguments
# Protocol: 80 09 P1 P2 LC data
#   First chunk: [total_len_hi][total_len_lo][chunk_data...]
#   Subsequent chunks: [chunk_data...]
generate_chunked_apdus() {
    local tag_hex="$1"
    local data_hex="$2"
    local chunk_size=200  # Max bytes per chunk (leaves room for headers)

    local data_len=$((${#data_hex} / 2))
    local total_len_hex=$(printf '%04X' $data_len)

    local result=""
    local offset=0
    local is_first=true

    while (( offset * 2 < ${#data_hex} )); do
        local remaining=$(( (${#data_hex} - offset * 2) / 2 ))
        local this_chunk_data_size

        if $is_first; then
            # First chunk: 2 bytes for length header + data
            this_chunk_data_size=$(( chunk_size - 2 ))
            if (( this_chunk_data_size > remaining )); then
                this_chunk_data_size=$remaining
            fi
            local chunk_data="${data_hex:$((offset * 2)):$((this_chunk_data_size * 2))}"
            local apdu_data="${total_len_hex}${chunk_data}"
            local lc=$(printf '%02X' $(( 2 + this_chunk_data_size )))
            result+=" -a 8009${tag_hex}${lc}${apdu_data}"
            is_first=false
        else
            # Subsequent chunks: just data
            this_chunk_data_size=$chunk_size
            if (( this_chunk_data_size > remaining )); then
                this_chunk_data_size=$remaining
            fi
            local chunk_data="${data_hex:$((offset * 2)):$((this_chunk_data_size * 2))}"
            local lc=$(printf '%02X' $this_chunk_data_size)
            result+=" -a 8009${tag_hex}${lc}${chunk_data}"
        fi

        offset=$(( offset + this_chunk_data_size ))
    done

    echo "$result"
}

# Generate chunked APDU commands for large settings data (RSA key)
# Usage: generate_chunked_settings_apdus SETTING_ID_HEX DATA_HEX
# Protocol: 80 0A P1 P2 LC data (similar to chunked tags)
generate_chunked_settings_apdus() {
    local setting_id_hex="$1"
    local data_hex="$2"
    local chunk_size=200

    local data_len=$((${#data_hex} / 2))
    local total_len_hex=$(printf '%04X' $data_len)

    local result=""
    local offset=0
    local is_first=true

    while (( offset * 2 < ${#data_hex} )); do
        local remaining=$(( (${#data_hex} - offset * 2) / 2 ))
        local this_chunk_data_size

        if $is_first; then
            this_chunk_data_size=$(( chunk_size - 2 ))
            if (( this_chunk_data_size > remaining )); then
                this_chunk_data_size=$remaining
            fi
            local chunk_data="${data_hex:$((offset * 2)):$((this_chunk_data_size * 2))}"
            local apdu_data="${total_len_hex}${chunk_data}"
            local lc=$(printf '%02X' $(( 2 + this_chunk_data_size )))
            result+=" -a 800A${setting_id_hex}${lc}${apdu_data}"
            is_first=false
        else
            this_chunk_data_size=$chunk_size
            if (( this_chunk_data_size > remaining )); then
                this_chunk_data_size=$remaining
            fi
            local chunk_data="${data_hex:$((offset * 2)):$((this_chunk_data_size * 2))}"
            local lc=$(printf '%02X' $this_chunk_data_size)
            result+=" -a 800A${setting_id_hex}${lc}${chunk_data}"
        fi

        offset=$(( offset + this_chunk_data_size ))
    done

    echo "$result"
}

# Personalize Payment Application - large APDUs (RSA keys, certificates)
# This is called after small APDUs, requires extended APDU support or chunked transfer
personalize_payapp_large() {
    log_step "Personalizing Payment Application (certificates/keys)..."

    local full_aid="${RID}${AID}"
    local gp_cmd=$(build_gp_cmd)
    gp_cmd+=" -d"

    # Certificate data
    local icc_cert_hex=$(xxd -p "$ICC_CERT" | tr -d '\n')
    local icc_cert_size=$(wc -c < "$ICC_CERT" | tr -d ' ')

    local icc_mod_hex=$(xxd -p "$ICC_MODULUS" | tr -d '\n')
    local icc_mod_size=$(wc -c < "$ICC_MODULUS" | tr -d ' ')

    local icc_priv_exp=$(openssl rsa -in "$ICC_PRIVKEY" -noout -text 2>/dev/null | awk '/^privateExponent:/{flag=1; next} /^[a-zA-Z]/{flag=0} flag' | tr -d ' :\n' | sed 's/^0*//')
    if (( ${#icc_priv_exp} % 2 == 1 )); then
        icc_priv_exp="0${icc_priv_exp}"
    fi
    local mod_size_hex=$(( icc_mod_size * 2 ))
    while (( ${#icc_priv_exp} < mod_size_hex )); do
        icc_priv_exp="0${icc_priv_exp}"
    done
    local icc_priv_size=$((${#icc_priv_exp} / 2))

    local issuer_cert_hex=$(xxd -p "$ISSUER_CERT" | tr -d '\n')
    local issuer_cert_size=$(wc -c < "$ISSUER_CERT" | tr -d ' ')

    # EC private key (P-256, 32 bytes)
    local icc_ec_priv_hex=""
    if [[ -f "${KEYS_DIR}/icc/icc_ec_private.bin" ]]; then
        icc_ec_priv_hex=$(xxd -p "${KEYS_DIR}/icc/icc_ec_private.bin" | tr -d '\n')
    fi

    # Select payment app
    gp_cmd+=" -a 00A4040007${full_aid}"

    # Certificate-related templates FIRST (small APDUs - will succeed on T=0)
    # SFI 2 Record 1: 8F, 92, 9F32, 9F47 (cert-related)
    gp_cmd+=" -a 8003011408008F00929F329F47"
    # SFI 2 Record 2: 90 (Issuer PK Cert)
    gp_cmd+=" -a 80030214020090"
    # SFI 3 Record 4: 9F46 (ICC PK Cert)
    gp_cmd+=" -a 8003041C029F46"
    # SFI 3 Record 5: 9F48 (ICC PK Remainder) - non-ODA to avoid ICC cert hash mismatch
    gp_cmd+=" -a 8003051C029F48"

    if $T0_MODE; then
        # T=0 mode: use chunked transfer for ALL large data (no extended APDUs)
        log_info "Using chunked transfer for T=0 protocol..."

        # RSA modulus - use chunked settings (80 0A 00 04)
        local mod_apdus=$(generate_chunked_settings_apdus "0004" "$icc_mod_hex")
        gp_cmd+="$mod_apdus"

        # RSA private exponent - use chunked settings (80 0A 00 05)
        local exp_apdus=$(generate_chunked_settings_apdus "0005" "$icc_priv_exp")
        gp_cmd+="$exp_apdus"

        # EC private key (setting 0x000B, 32 bytes - fits in single short APDU)
        if [[ -n "$icc_ec_priv_hex" ]]; then
            gp_cmd+=" -a 8004000B20${icc_ec_priv_hex}"
        fi

        # Issuer certificate (tag 90) - use chunked EMV tag (80 09)
        local issuer_apdus=$(generate_chunked_apdus "0090" "$issuer_cert_hex")
        gp_cmd+="$issuer_apdus"

        # ICC certificate (tag 9F46) - use chunked EMV tag (80 09)
        local icc_apdus=$(generate_chunked_apdus "9F46" "$icc_cert_hex")
        gp_cmd+="$icc_apdus"
    else
        # T=1 mode: use extended APDUs (original approach)
        local icc_cert_lc
        if (( icc_cert_size > 255 )); then
            icc_cert_lc=$(printf '00%04X' $icc_cert_size)
        else
            icc_cert_lc=$(printf '%02X' $icc_cert_size)
        fi

        local icc_mod_len
        if (( icc_mod_size >= 256 )); then
            icc_mod_len=$(printf '00%04X' $icc_mod_size)
        else
            icc_mod_len=$(printf '%02X' $icc_mod_size)
        fi

        local icc_priv_len
        if (( icc_priv_size >= 256 )); then
            icc_priv_len=$(printf '00%04X' $icc_priv_size)
        else
            icc_priv_len=$(printf '%02X' $icc_priv_size)
        fi

        local issuer_cert_lc
        if (( issuer_cert_size > 255 )); then
            issuer_cert_lc=$(printf '00%04X' $issuer_cert_size)
        else
            issuer_cert_lc=$(printf '%02X' $issuer_cert_size)
        fi

        # Large APDUs: RSA key and certificates
        gp_cmd+=" -a 80040004${icc_mod_len}${icc_mod_hex}"
        gp_cmd+=" -a 80040005${icc_priv_len}${icc_priv_exp}"
        # EC private key (setting 0x000B, 32 bytes)
        if [[ -n "$icc_ec_priv_hex" ]]; then
            gp_cmd+=" -a 8004000B20${icc_ec_priv_hex}"
        fi
        gp_cmd+=" -a 80010090${issuer_cert_lc}${issuer_cert_hex}"
        gp_cmd+=" -a 80019F46${icc_cert_lc}${icc_cert_hex}"
    fi

    log_info "Sending certificate/key APDUs..."
    eval "$gp_cmd" 2>&1 | grep -v "^WARNING:" | grep -v "^Warning:"

    log_success "Payment Application certificate personalization complete"
}

# Personalize Payment Application - combined (for T=1 mode)
personalize_payapp() {
    personalize_payapp_small
    personalize_payapp_large
}

# Personalize Contactless Payment Application - small APDUs
personalize_payapp_contactless_small() {
    log_step "Personalizing Contactless Payment Application (basic tags)..."

    local full_aid="${RID}${CONTACTLESS_AID}"
    local gp_cmd=$(build_gp_cmd)
    gp_cmd+=" -d"

    # Convert values to hex
    local app_label_hex=$(echo -n "$DEFAULT_APP_LABEL" | xxd -p | tr -d '\n')
    local app_label_len=$(printf '%02X' ${#DEFAULT_APP_LABEL})
    local cardholder_name="${DEFAULT_APP_LABEL}/CARDHOLDER "
    local cardholder_hex=$(echo -n "$cardholder_name" | xxd -p | tr -d '\n')
    local cardholder_len=$(printf '%02X' ${#cardholder_name})

    # Preferred name for 9F12 (e.g., "VISA CREDIT")
    local preferred_name="${DEFAULT_APP_LABEL} CREDIT"
    local preferred_name_hex=$(echo -n "$preferred_name" | xxd -p | tr -d '\n')
    local preferred_name_len=$(printf '%02X' ${#preferred_name})

    # PAN formatting
    local pan_hex="$PAN"
    if (( ${#PAN} % 2 == 1 )); then
        pan_hex="${PAN}F"
    fi
    local pan_bytes=$((${#pan_hex} / 2))
    local pan_len_hex=$(printf '%02X' $pan_bytes)

    # Track 2
    local track2="${pan_hex}D${DEFAULT_EXPIRY:0:4}2201000000000000F"
    track2="${track2:0:38}"
    local track2_len=$(printf '%02X' $((${#track2} / 2)))

    # ICC remainder (small - usually <42 bytes)
    local icc_rem_hex=$(xxd -p "$ICC_REM" | tr -d '\n')
    local icc_rem_size=$(wc -c < "$ICC_REM" | tr -d ' ')
    local icc_rem_len=$(printf '%02X' $icc_rem_size)

    # Issuer remainder (small)
    local issuer_rem_hex=$(xxd -p "$ISSUER_REM" | tr -d '\n')
    local issuer_rem_size=$(wc -c < "$ISSUER_REM" | tr -d ' ')
    local issuer_rem_len=$(printf '%02X' $issuer_rem_size)

    # Payment app selection and factory reset
    gp_cmd+=" -a 00A4040007${full_aid}"
    gp_cmd+=" -a 8005000000"

    # Settings (small)
    gp_cmd+=" -a 80040003020001"
    gp_cmd+=" -a 8004000102123400"
    gp_cmd+=" -a 8004000202008000"

    # Templates
    # GPO template: Format 1 = AIP (82) + AFL (94) only, no CTQ for Format 1
    gp_cmd+=" -a 800200010400820094"
    gp_cmd+=" -a 80020002029F4B"
    gp_cmd+=" -a 80020003089F279F369F269F10"
    # FCI template: 50 (label), 87 (priority), 9F12 (preferred name), 9F38 (PDOL)
    gp_cmd+=" -a 8002000508005000879F129F38"
    gp_cmd+=" -a 8002000404008400A5"
    # READ RECORD templates - must match AFL entries
    # SFI1/REC2: 57, 5F20, 9F1F (Track2, Cardholder, DiscData)
    gp_cmd+=" -a 8003020C0400575F20"
    # SFI2/REC1: 8F, 92, 9F32, 9F47 (CAPublicKeyIndex, IssuerCert, etc.)
    gp_cmd+=" -a 8003011408008F00929F329F47"
    # SFI2/REC2: 90 (IssuerPubKey)
    gp_cmd+=" -a 80030214020090"
    # SFI3/REC1: 5A,5F24,5F25,5F28,5F34,9F07,9F0D,9F0E,9F0F,9F4A,8C,8D
    gp_cmd+=" -a 8003011C18005A5F245F255F285F349F079F0D9F0E9F0F9F4A008C008D"
    # SFI3/REC2: 8E (CVM)
    gp_cmd+=" -a 8003021C02008E"
    # SFI3/REC3: 5F30,9F08,9F42,9F44,9F49
    gp_cmd+=" -a 8003031C0A5F309F089F429F449F49"
    # SFI3/REC4: 9F46 (ICC PublicKey Cert)
    gp_cmd+=" -a 8003041C029F46"

    # Small EMV tags - CRITICAL: AIP and AFL
    # AIP: 2000 for qVSDC with fDDA (byte 1 bit 6 = DDA supported)
    gp_cmd+=" -a 80010082022000"
    gp_cmd+=" -a 800100940C080202001001020218010500"

    # Other small tags
    gp_cmd+=" -a 80019F36020001"
    gp_cmd+=" -a 8001008407${full_aid}"
    # 9F12 Application Preferred Name
    gp_cmd+=" -a 80019F12${preferred_name_len}${preferred_name_hex}"
    # PDOL: TTQ(4), Amount(6), AmountOther(6), Country(2), TVR(5), Currency(2), Date(3), Type(1), UN(4)
    gp_cmd+=" -a 80019F38189F66049F02069F03069F1A0295055F2A029A039C019F3704"
    gp_cmd+=" -a 8001005A${pan_len_hex}${pan_hex}"
    gp_cmd+=" -a 80015F2403${DEFAULT_EXPIRY}"
    gp_cmd+=" -a 80015F340101"
    gp_cmd+=" -a 80010057${track2_len}${track2}"
    gp_cmd+=" -a 80010050${app_label_len}${app_label_hex}"
    gp_cmd+=" -a 800100870101"
    gp_cmd+=" -a 80015F20${cardholder_len}${cardholder_hex}"
    gp_cmd+=" -a 80019F08020001"
    gp_cmd+=" -a 80015F2503240101"
    gp_cmd+=" -a 80015F28020840"
    gp_cmd+=" -a 80019F0702FF0000"
    gp_cmd+=" -a 80019F4A0182"
    gp_cmd+=" -a 80019F1F1300000000000000000000000000000000000000"
    gp_cmd+=" -a 80015F30020201"
    gp_cmd+=" -a 80019F42020840"
    gp_cmd+=" -a 80019F440102"
    # 9F49 = DDOL (matches CDOL1: Amount, Amount Other, Country, TVR, Currency, Date, Txn Type, UN, Terminal ID, Merchant ID, Acquirer ID)
    gp_cmd+=" -a 80019F491E9F02069F03069F1A0295055F2A029A039C019F37049F1C089F160F9F0106"
    gp_cmd+=" -a 8001008C1E9F02069F03069F1A0295055F2A029A039C019F37049F1C089F160F9F0106"
    gp_cmd+=" -a 8001008D208A029F02069F03069F1A0295055F2A029A039C019F37049F1C089F160F9F0106"
    gp_cmd+=" -a 8001008E0A00000000000000001F00"
    gp_cmd+=" -a 80019F0D05FC688C9800"
    gp_cmd+=" -a 80019F0E050000000000"
    gp_cmd+=" -a 80019F0F05FC68FC9800"
    gp_cmd+=" -a 80019F100706010A03A4A002"
    gp_cmd+=" -a 80019F6C02A000"

    # Small certificate-related tags
    gp_cmd+=" -a 8001008F0192"
    gp_cmd+=" -a 80019F320103"
    gp_cmd+=" -a 80019F470103"
    gp_cmd+=" -a 80010092${issuer_rem_len}${issuer_rem_hex}"
    gp_cmd+=" -a 80019F48${icc_rem_len}${icc_rem_hex}"

    log_info "Sending basic Contactless Payment App APDUs..."
    eval "$gp_cmd" 2>&1 | grep -v "^WARNING:" | grep -v "^Warning:"

    log_success "Contactless Payment Application basic personalization complete"
}

# Personalize Contactless Payment Application - large APDUs (RSA keys, certificates)
personalize_payapp_contactless_large() {
    log_step "Personalizing Contactless Payment Application (certificates/keys)..."

    local full_aid="${RID}${CONTACTLESS_AID}"
    local gp_cmd=$(build_gp_cmd)
    gp_cmd+=" -d"

    # Certificate data
    local icc_cert_hex=$(xxd -p "$ICC_CERT" | tr -d '\n')
    local icc_cert_size=$(wc -c < "$ICC_CERT" | tr -d ' ')

    local icc_mod_hex=$(xxd -p "$ICC_MODULUS" | tr -d '\n')
    local icc_mod_size=$(wc -c < "$ICC_MODULUS" | tr -d ' ')

    local icc_priv_exp=$(openssl rsa -in "$ICC_PRIVKEY" -noout -text 2>/dev/null | awk '/^privateExponent:/{flag=1; next} /^[a-zA-Z]/{flag=0} flag' | tr -d ' :\n' | sed 's/^0*//')
    if (( ${#icc_priv_exp} % 2 == 1 )); then
        icc_priv_exp="0${icc_priv_exp}"
    fi
    local mod_size_hex=$(( icc_mod_size * 2 ))
    while (( ${#icc_priv_exp} < mod_size_hex )); do
        icc_priv_exp="0${icc_priv_exp}"
    done
    local icc_priv_size=$((${#icc_priv_exp} / 2))

    local issuer_cert_hex=$(xxd -p "$ISSUER_CERT" | tr -d '\n')
    local issuer_cert_size=$(wc -c < "$ISSUER_CERT" | tr -d ' ')

    # EC private key (P-256, 32 bytes)
    local icc_ec_priv_hex=""
    if [[ -f "${KEYS_DIR}/icc/icc_ec_private.bin" ]]; then
        icc_ec_priv_hex=$(xxd -p "${KEYS_DIR}/icc/icc_ec_private.bin" | tr -d '\n')
    fi

    # Select payment app
    gp_cmd+=" -a 00A4040007${full_aid}"

    # Certificate-related templates
    gp_cmd+=" -a 8003011408008F00929F329F47"
    gp_cmd+=" -a 80030214020090"
    gp_cmd+=" -a 8003041C029F46"
    gp_cmd+=" -a 8003051C029F48"

    if $T0_MODE; then
        # T=0 mode: use chunked transfer
        log_info "Using chunked transfer for T=0 protocol..."

        local mod_apdus=$(generate_chunked_settings_apdus "0004" "$icc_mod_hex")
        gp_cmd+="$mod_apdus"

        local exp_apdus=$(generate_chunked_settings_apdus "0005" "$icc_priv_exp")
        gp_cmd+="$exp_apdus"

        # EC private key (setting 0x000B, 32 bytes - fits in single short APDU)
        if [[ -n "$icc_ec_priv_hex" ]]; then
            gp_cmd+=" -a 8004000B20${icc_ec_priv_hex}"
        fi

        local issuer_apdus=$(generate_chunked_apdus "0090" "$issuer_cert_hex")
        gp_cmd+="$issuer_apdus"

        local icc_apdus=$(generate_chunked_apdus "9F46" "$icc_cert_hex")
        gp_cmd+="$icc_apdus"
    else
        # T=1 mode: use extended APDUs
        local icc_cert_lc
        if (( icc_cert_size > 255 )); then
            icc_cert_lc=$(printf '00%04X' $icc_cert_size)
        else
            icc_cert_lc=$(printf '%02X' $icc_cert_size)
        fi

        local icc_mod_len
        if (( icc_mod_size >= 256 )); then
            icc_mod_len=$(printf '00%04X' $icc_mod_size)
        else
            icc_mod_len=$(printf '%02X' $icc_mod_size)
        fi

        local icc_priv_len
        if (( icc_priv_size >= 256 )); then
            icc_priv_len=$(printf '00%04X' $icc_priv_size)
        else
            icc_priv_len=$(printf '%02X' $icc_priv_size)
        fi

        local issuer_cert_lc
        if (( issuer_cert_size > 255 )); then
            issuer_cert_lc=$(printf '00%04X' $issuer_cert_size)
        else
            issuer_cert_lc=$(printf '%02X' $issuer_cert_size)
        fi

        gp_cmd+=" -a 80040004${icc_mod_len}${icc_mod_hex}"
        gp_cmd+=" -a 80040005${icc_priv_len}${icc_priv_exp}"
        # EC private key (setting 0x000B, 32 bytes)
        if [[ -n "$icc_ec_priv_hex" ]]; then
            gp_cmd+=" -a 8004000B20${icc_ec_priv_hex}"
        fi
        gp_cmd+=" -a 80010090${issuer_cert_lc}${issuer_cert_hex}"
        gp_cmd+=" -a 80019F46${icc_cert_lc}${icc_cert_hex}"
    fi

    log_info "Sending certificate/key APDUs..."
    eval "$gp_cmd" 2>&1 | grep -v "^WARNING:" | grep -v "^Warning:"

    log_success "Contactless Payment Application certificate personalization complete"
}

# Personalize Contactless Payment Application - combined
personalize_payapp_contactless() {
    personalize_payapp_contactless_small
    personalize_payapp_contactless_large
}

# Validate certificates
validate_certificates() {
    log_step "Validating certificate chain..."

    source "${SCRIPTS_DIR}/validate_certs.sh"

    if validate_chain; then
        log_success "Certificate chain validation passed"
    else
        log_error "Certificate chain validation failed"
        exit 1
    fi
}

# Generate config files
generate_configs() {
    log_step "Generating terminal configuration files..."

    source "${SCRIPTS_DIR}/gen_config.sh"

    gen_verifone_all "${BUILD_DIR}/config/verifone" "$RID" "$AID" "$DEFAULT_APP_LABEL"
    gen_emvpt_all "${BUILD_DIR}/config/emvpt" "$RID" "$DEFAULT_APP_LABEL"

    log_success "Configuration files generated"
    log_info "  Verifone: ${BUILD_DIR}/config/verifone/"
    log_info "  emvpt:    ${BUILD_DIR}/config/emvpt/"
}

# Print summary
print_summary() {
    echo ""
    echo -e "${BOLD}========================================${NC}"
    echo -e "${BOLD}       Personalization Summary          ${NC}"
    echo -e "${BOLD}========================================${NC}"
    echo ""
    echo -e "  ${CYAN}RID:${NC}              $RID"
    echo -e "  ${CYAN}Contact AID:${NC}      ${RID}${AID}"
    echo -e "  ${CYAN}Contactless AID:${NC}  ${RID}${CONTACTLESS_AID}"
    echo -e "  ${CYAN}PAN:${NC}              $PAN"
    echo -e "  ${CYAN}Expiry:${NC}           ${DEFAULT_EXPIRY:0:2}/${DEFAULT_EXPIRY:2:2}/${DEFAULT_EXPIRY:4:2}"
    echo -e "  ${CYAN}Label:${NC}            $DEFAULT_APP_LABEL"
    echo ""
    echo -e "  ${CYAN}Config files:${NC}"
    echo -e "    Verifone: ${BUILD_DIR}/config/verifone/"
    echo -e "    emvpt:    ${BUILD_DIR}/config/emvpt/"
    echo ""
    echo -e "${GREEN}Card personalization complete!${NC}"
    echo ""
}

# Main execution
main() {
    echo ""
    echo -e "${BOLD}EMV Card Personalization Tool${NC}"
    echo -e "${BOLD}==============================${NC}"
    echo ""

    parse_args "$@"
    apply_defaults

    if $T0_MODE; then
        echo -e "${YELLOW}T=0 mode enabled - will prompt for card removal/reinsertion between steps${NC}"
        echo ""
    fi

    # Validate PAN/BIN
    validate_pan_bin

    # Locate CAP files
    locate_cap_files

    # Locate certificate files
    locate_cert_files

    # Regenerate ICC certificate to match the current PAN
    # (ICC cert contains PAN and must be regenerated each time)
    regenerate_icc_cert

    # Validate certificates
    validate_certificates

    if $T0_MODE; then
        # T=0 mode: separate gp.jar calls with card cycles between each
        # Skip query/remove - use --force on install instead

        # Load CAP files (has internal prompt between PSE and PaymentApp)
        load_cap_files

        prompt_card_cycle "Installed Payment App CAP"

        # Personalize PSE (Contact)
        personalize_pse

        prompt_card_cycle "Personalized PSE"

        # Personalize PPSE (Contactless)
        personalize_ppse

        prompt_card_cycle "Personalized PPSE"

        # Personalize Contact Payment Application - small APDUs first (AIP, AFL, templates)
        personalize_payapp_small

        prompt_card_cycle "Personalized Contact Payment App (basic tags)"

        # Personalize Contact Payment Application - large APDUs (certificates, RSA keys)
        personalize_payapp_large

        prompt_card_cycle "Personalized Contact Payment App (certificates)"

        # Personalize Contactless Payment Application - small APDUs
        personalize_payapp_contactless_small

        prompt_card_cycle "Personalized Contactless Payment App (basic tags)"

        # Personalize Contactless Payment Application - large APDUs
        personalize_payapp_contactless_large
    else
        # T=1 mode: original flow with multiple gp.jar calls in sequence

        # Query card
        query_card

        # Remove existing apps
        remove_all_apps

        # Load CAP files
        load_cap_files

        # Personalize card (both PSE and PaymentApp in one session)
        personalize_card
    fi

    # Generate config files
    generate_configs

    # Print summary
    print_summary
}

# Run main
main "$@"
