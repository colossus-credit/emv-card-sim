#!/bin/bash
# Generate configuration files for Verifone and emvpt terminals

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

# Compute CAPK checksum per EMV spec: SHA-1(RID + Index + Modulus + Exponent)
compute_capk_checksum() {
    local rid="$1"
    local index="$2"
    local modulus_file="$3"
    local exponent="$4"

    # Create temp file with concatenated data
    local tmp_file=$(mktemp)
    printf '%s' "$rid" | xxd -r -p >> "$tmp_file"
    printf '%s' "$index" | xxd -r -p >> "$tmp_file"
    cat "$modulus_file" >> "$tmp_file"
    printf '%s' "$exponent" | xxd -r -p >> "$tmp_file"

    # Compute SHA-1 and clean up
    local checksum=$(openssl dgst -sha1 -binary "$tmp_file" | xxd -p | tr -d '\n' | tr '[:lower:]' '[:upper:]')
    rm -f "$tmp_file"

    echo "$checksum"
}

# Generate Verifone emvct.json
gen_verifone_emvct() {
    local output_dir="$1"
    local rid="$2"
    local aid="$3"
    local app_label="$4"

    local full_aid="${rid}${aid}"
    local capk_checksum=$(compute_capk_checksum "$rid" "92" "${KEYS_DIR}/capk/capk_modulus.bin" "03")

    mkdir -p "$output_dir"

    cat > "${output_dir}/emvct.json" << EOF
{
  "terminal": {
    "terminalType": "22",
    "terminalCountryCode": "0840",
    "terminalCapabilities": "E028C8",
    "additionalTerminalCapabilities": "F000F0A001",
    "transactionCurrency": "USD",
    "transactionCurrencyExp": "2"
  },
  "applications": [
    {
      "aid": "${full_aid}",
      "appVersionNumber": "0001",
      "defaultAppName": "${app_label}",
      "asi": "01",
      "merchantCategoryCode": "5999",
      "termIdent": "3132333435363738",
      "floorLimit": "000007D0",
      "securityLimit": "00000000",
      "belowLimitTerminalCapabilities": "E008C8",
      "threshold": "000001F4",
      "targetPercentage": "00",
      "maxTargetPercentage": "00",
      "tacDenial": "0000000000",
      "tacDefault": "FC688C9800",
      "tacOnline": "FC688CF800",
      "defaultDDOL": "9F3704",
      "merchantIdent": "202020202020202020202020202020",
      "cdaProcessing": "01",
      "acBeforeAfter": "00",
      "aipCvmNotSupported": "00",
      "posEntryMode": "05",
      "additionalVersionNumbers": "010102020303040405050606070708080096FFFF",
      "appFlowCap": "3F1F170000",
      "appTermCap": "E028C8",
      "countryCode": "0840",
      "appTermAddCap": "F000F0A001",
      "appTerminalType": "22"
    }
  ],
  "capKeys": [
    {
      "rid": "${rid}",
      "index": "92",
      "exponent": "03",
      "modulus": "$(xxd -p "${KEYS_DIR}/capk/capk_modulus.bin" | tr -d '\n' | tr '[:lower:]' '[:upper:]')",
      "checksum": "${capk_checksum}"
    }
  ]
}
EOF

    log_info "Generated ${output_dir}/emvct.json"
}

# Generate Verifone tlvemvct.json
gen_verifone_tlvemvct() {
    local output_dir="$1"
    local rid="$2"
    local aid="$3"
    local app_label="$4"

    local full_aid="${rid}${aid}"
    local capk_checksum=$(compute_capk_checksum "$rid" "92" "${KEYS_DIR}/capk/capk_modulus.bin" "03")

    mkdir -p "$output_dir"

    cat > "${output_dir}/tlvemvct.json" << EOF
{
  "terminal": {
    "fields": [
      {"tag": "9F35", "value": "22", "name": "Terminal Type"},
      {"tag": "9F1A", "value": "0840", "name": "Terminal Country Code"},
      {"tag": "9F33", "value": "E028C8", "name": "Terminal Capabilities"},
      {"tag": "9F40", "value": "F000F0A001", "name": "Terminal Additional Capabilities"},
      {"tag": "5F2A", "value": "0840", "name": "Transaction Currency"},
      {"tag": "5F36", "value": "2", "name": "Transaction Currency Exponent"}
    ]
  },
  "applications": [
    {
      "fields": [
        {"tag": "4F", "value": "${full_aid}", "name": "Aid"},
        {"tag": "9F09", "value": "0001", "name": "Application Version Number"},
        {"tag": "50", "value": "${app_label}", "name": "Application Label"},
        {"tag": "DF20", "value": "01", "name": "Application selection indicator"},
        {"tag": "9F15", "value": "5999", "name": "Merchant Category Code"},
        {"tag": "9F1C", "value": "3132333435363738", "name": "Terminal Identifier"},
        {"tag": "9F1B", "value": "000007D0", "name": "Terminal Floor Limit"},
        {"tag": "DF49", "value": "00000000", "name": "Security Limit"},
        {"tag": "DF4A", "value": "E008C8", "name": "Terminal Capabilities Below Limit"},
        {"tag": "DF24", "value": "000001F4", "name": "Threshold"},
        {"tag": "DFAB47", "value": "00", "name": "Target Percentage"},
        {"tag": "DFAB48", "value": "00", "name": "Max Target Percentage"},
        {"tag": "DF21", "value": "0000000000", "name": "TAC Denial"},
        {"tag": "DF22", "value": "FC688C9800", "name": "TAC Default"},
        {"tag": "DF23", "value": "FC688CF800", "name": "TAC Online"},
        {"tag": "DF25", "value": "9F3704", "name": "Default DDOL"},
        {"tag": "9F16", "value": "202020202020202020202020202020", "name": "Merchant Identifier"},
        {"tag": "DF4B", "value": "01", "name": "CDA Processing"},
        {"tag": "DF27", "value": "00", "name": "AC Before After"},
        {"tag": "DF28", "value": "00", "name": "AIP CVM Not Supported"},
        {"tag": "9F39", "value": "05", "name": "POS Entry Mode"},
        {"tag": "DF4C", "value": "010102020303040405050606070708080096FFFF", "name": "Additional Version Numbers"},
        {"tag": "DF29", "value": "3F1F170000", "name": "App Flow Cap"},
        {"tag": "DF30", "value": "E028C8", "name": "App Term Cap"},
        {"tag": "DF31", "value": "0840", "name": "Country Code"},
        {"tag": "DF32", "value": "F000F0A001", "name": "App Term Add Cap"},
        {"tag": "DF33", "value": "22", "name": "App Terminal Type"}
      ]
    }
  ],
  "capKeys": [
    {
      "fields": [
        {"tag": "9F06", "value": "${rid}", "name": "RID"},
        {"tag": "9F22", "value": "92", "name": "CA Public Key Index"},
        {"tag": "DF04", "value": "03", "name": "CA Public Key Exponent"},
        {"tag": "DF02", "value": "$(xxd -p "${KEYS_DIR}/capk/capk_modulus.bin" | tr -d '\n' | tr '[:lower:]' '[:upper:]')", "name": "CA Public Key Modulus"},
        {"tag": "DF03", "value": "${capk_checksum}", "name": "CA Public Key Checksum"}
      ]
    }
  ]
}
EOF

    log_info "Generated ${output_dir}/tlvemvct.json"
}

# Generate Verifone emvctls.json (contactless)
gen_verifone_emvctls() {
    local output_dir="$1"
    local rid="$2"
    local aid="$3"
    local app_label="$4"

    local full_aid="${rid}${aid}"

    mkdir -p "$output_dir"

    cat > "${output_dir}/emvctls.json" << EOF
{
  "terminal": {
    "terminalType": "22",
    "terminalCountryCode": "0840",
    "terminalCapabilities": "E06008",
    "additionalTerminalCapabilities": "F000F0A001",
    "transactionCurrency": "USD",
    "transactionCurrencyExp": "2"
  },
  "applications": [
    {
      "aid": "${full_aid}",
      "appVersionNumber": "0001",
      "defaultAppName": "${app_label}",
      "kernelId": "04",
      "ttq": "36000000",
      "tacDenial": "0000000000",
      "tacDefault": "FC688C9800",
      "tacOnline": "FC688CF800",
      "floorLimit": "000007D0",
      "ctlsTransactionLimit": "00001388",
      "ctlsCvmLimit": "00000000",
      "ctlsFloorLimit": "000007D0"
    }
  ],
  "capKeys": [
    {
      "rid": "${rid}",
      "index": "92",
      "exponent": "03",
      "modulus": "$(xxd -p "${KEYS_DIR}/capk/capk_modulus.bin" | tr -d '\n' | tr '[:lower:]' '[:upper:]')"
    }
  ]
}
EOF

    log_info "Generated ${output_dir}/emvctls.json"
}

# Generate Verifone tlvemvctls.json
gen_verifone_tlvemvctls() {
    local output_dir="$1"
    local rid="$2"
    local aid="$3"
    local app_label="$4"

    local full_aid="${rid}${aid}"

    mkdir -p "$output_dir"

    cat > "${output_dir}/tlvemvctls.json" << EOF
{
  "terminal": {
    "fields": [
      {"tag": "9F35", "value": "22", "name": "Terminal Type"},
      {"tag": "9F1A", "value": "0840", "name": "Terminal Country Code"},
      {"tag": "9F33", "value": "E06008", "name": "Terminal Capabilities"},
      {"tag": "9F40", "value": "F000F0A001", "name": "Terminal Additional Capabilities"},
      {"tag": "5F2A", "value": "0840", "name": "Transaction Currency"},
      {"tag": "5F36", "value": "2", "name": "Transaction Currency Exponent"}
    ]
  },
  "applications": [
    {
      "fields": [
        {"tag": "4F", "value": "${full_aid}", "name": "Aid"},
        {"tag": "9F09", "value": "0001", "name": "Application Version Number"},
        {"tag": "50", "value": "${app_label}", "name": "Application Label"},
        {"tag": "DF8101", "value": "04", "name": "Kernel ID"},
        {"tag": "9F66", "value": "36000000", "name": "TTQ"},
        {"tag": "DF21", "value": "0000000000", "name": "TAC Denial"},
        {"tag": "DF22", "value": "FC688C9800", "name": "TAC Default"},
        {"tag": "DF23", "value": "FC688CF800", "name": "TAC Online"},
        {"tag": "9F1B", "value": "000007D0", "name": "Floor Limit"},
        {"tag": "DF8124", "value": "00001388", "name": "CTLS Transaction Limit"},
        {"tag": "DF8126", "value": "00000000", "name": "CTLS CVM Limit"},
        {"tag": "DF8123", "value": "000007D0", "name": "CTLS Floor Limit"}
      ]
    }
  ],
  "capKeys": [
    {
      "fields": [
        {"tag": "9F06", "value": "${rid}", "name": "RID"},
        {"tag": "9F22", "value": "92", "name": "CA Public Key Index"},
        {"tag": "DF04", "value": "03", "name": "CA Public Key Exponent"},
        {"tag": "DF02", "value": "$(xxd -p "${KEYS_DIR}/capk/capk_modulus.bin" | tr -d '\n' | tr '[:lower:]' '[:upper:]')", "name": "CA Public Key Modulus"}
      ]
    }
  ]
}
EOF

    log_info "Generated ${output_dir}/tlvemvctls.json"
}

# Generate emvpt settings.yaml
gen_emvpt_settings() {
    local output_dir="$1"

    mkdir -p "$output_dir"

    cat > "${output_dir}/settings.yaml" << 'EOF'
censor_sensitive_fields: false
configuration_files:
  emv_tags: 'config/emv_tags.yaml'
  scheme_ca_public_keys: 'config/scheme_ca_public_keys.yaml'
  constants: 'config/constants.yaml'
terminal:
  use_random: true
  capabilities:
    sda: true
    dda: true
    cda: true
    plaintext_pin: true
    enciphered_pin: true
    terminal_risk_management: true
    issuer_authentication: false
  tvr:
    offline_data_authentication_was_not_performed: false
    sda_failed: false
    icc_data_missing: false
    card_appears_on_terminal_exception_file: false
    dda_failed: false
    cda_failed: false
    icc_and_terminal_have_different_application_versions: false
    expired_application: false
    application_not_yet_effective: false
    requested_service_not_allowed_for_card_product: false
    new_card: false
    cardholder_verification_was_not_successful: false
    unrecognised_cvm: false
    pin_try_limit_exceeded: false
    pin_entry_required_and_pin_pad_not_present_or_not_working: false
    pin_entry_required_pin_pad_present_but_pin_was_not_entered: false
    online_pin_entered: false
    transaction_exceeds_floor_limit: false
    lower_consecutive_offline_limit_exceeded: false
    upper_consecutive_offline_limit_exceeded: false
    transaction_selected_randomly_for_online_processing: false
    merchant_forced_transaction_online: false
    default_tdol_used: false
    issuer_authentication_failed: false
    script_processing_failed_before_final_generate_ac: false
    script_processing_failed_after_final_generate_ac: false
  tsi:
    offline_data_authentication_was_performed: false
    cardholder_verification_was_performed: false
    card_risk_management_was_performed: false
    issuer_authentication_was_performed: false
    terminal_risk_management_was_performed: false
    script_processing_was_performed: false
  terminal_transaction_qualifiers:
    mag_stripe_mode_supported: false
    emv_mode_supported: true
    emv_contact_chip_supported: true
    offline_only_reader: false
    online_pin_supported: false
    signature_supported: true
    offline_data_authentication_for_online_authorizations_supported: true
    online_cryptogram_required: false
    cvm_required: false
    contact_chip_offline_pin_supported: true
    issuer_update_processing_supported: false
    consumer_device_cvm_supported: false
  c4_enhanced_contactless_reader_capabilities:
    contact_mode_supported: true
    contactless_mag_stripe_mode_supported: true
    contactless_emv_full_online_mode_not_supported: false
    contactless_emv_partial_online_mode_supported: false
    contactless_mode_supported: true
    try_another_interface_after_decline: true
    mobile_cvm_supported: true
    online_pin_supported: false
    signature: true
    plaintext_offline_pin: true
    reader_is_offline_only: true
    cvm_required: false
    terminal_exempt_from_no_cvm_checks: false
    delayed_authorisation_terminal: false
    transit_terminal: false
    c4_kernel_version: 3
  cryptogram_type: 'AuthorisationRequestCryptogram'
  cryptogram_type_arqc: 'TransactionCertificate'
default_tags:
  '9F1A': '0840'
  '5F2A': '0840'
  '9C': '00'
  '9F35': '22'
EOF

    log_info "Generated ${output_dir}/settings.yaml"
}

# Generate emvpt scheme_ca_public_keys.yaml
gen_emvpt_capk() {
    local output_dir="$1"
    local rid="$2"
    local app_label="$3"

    mkdir -p "$output_dir"

    local modulus_hex=$(xxd -p "${KEYS_DIR}/capk/capk_modulus.bin" | tr -d '\n' | tr '[:lower:]' '[:upper:]')

    cat > "${output_dir}/scheme_ca_public_keys.yaml" << EOF
${rid}:
  issuer: ${app_label} Network
  certificates:
    '92':
      modulus: ${modulus_hex}
      exponent: '03'
EOF

    log_info "Generated ${output_dir}/scheme_ca_public_keys.yaml"
}

# Copy emvpt static files
copy_emvpt_static() {
    local output_dir="$1"
    local emvpt_config="/Users/dangerousfood/Dev/emvpt/terminalsimulator/config"

    mkdir -p "$output_dir"

    # Copy static config files
    if [[ -f "${emvpt_config}/constants.yaml" ]]; then
        cp "${emvpt_config}/constants.yaml" "${output_dir}/"
        log_info "Copied constants.yaml"
    fi

    if [[ -f "${emvpt_config}/emv_tags.yaml" ]]; then
        cp "${emvpt_config}/emv_tags.yaml" "${output_dir}/"
        log_info "Copied emv_tags.yaml"
    fi

    if [[ -f "${emvpt_config}/log4rs.yaml" ]]; then
        cp "${emvpt_config}/log4rs.yaml" "${output_dir}/"
        log_info "Copied log4rs.yaml"
    fi
}

# Generate all Verifone configs
gen_verifone_all() {
    local output_dir="$1"
    local rid="$2"
    local aid="$3"
    local app_label="$4"

    log_info "Generating Verifone configuration files..."

    gen_verifone_emvct "$output_dir" "$rid" "$aid" "$app_label"
    gen_verifone_tlvemvct "$output_dir" "$rid" "$aid" "$app_label"
    gen_verifone_emvctls "$output_dir" "$rid" "$aid" "$app_label"
    gen_verifone_tlvemvctls "$output_dir" "$rid" "$aid" "$app_label"

    log_info "Verifone configuration complete!"
}

# Generate all emvpt configs
gen_emvpt_all() {
    local output_dir="$1"
    local rid="$2"
    local app_label="$3"

    log_info "Generating emvpt configuration files..."

    gen_emvpt_settings "$output_dir"
    gen_emvpt_capk "$output_dir" "$rid" "$app_label"
    copy_emvpt_static "$output_dir"

    log_info "emvpt configuration complete!"
}

# CLI interface
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    case "$1" in
        verifone)
            gen_verifone_all "${2:-build/config/verifone}" "${3:-A000000951}" "${4:-0001}" "${5:-COLOSSUS}"
            ;;
        emvpt)
            gen_emvpt_all "${2:-build/config/emvpt}" "${3:-A000000951}" "${4:-COLOSSUS}"
            ;;
        all)
            gen_verifone_all "${2:-build/config/verifone}" "${3:-A000000951}" "${4:-0001}" "${5:-COLOSSUS}"
            gen_emvpt_all "${2:-build/config/emvpt}" "${3:-A000000951}" "${5:-COLOSSUS}"
            ;;
        *)
            echo "Usage: $0 {verifone|emvpt|all} [output_dir] [rid] [aid] [app_label]"
            echo ""
            echo "Commands:"
            echo "  verifone [dir] [rid] [aid] [label]  - Generate Verifone config files"
            echo "  emvpt [dir] [rid] [label]           - Generate emvpt config files"
            echo "  all [dir] [rid] [aid] [label]       - Generate all config files"
            echo ""
            echo "Defaults:"
            echo "  dir:   build/config/{verifone,emvpt}"
            echo "  rid:   A000000951"
            echo "  aid:   0001"
            echo "  label: COLOSSUS"
            exit 1
            ;;
    esac
fi
