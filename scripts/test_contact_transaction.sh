#!/bin/bash
#
# EMV Contact Transaction Test Script
# Tests the card using contact interface with standard EMV flow
#

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"
GP_JAR="${ROOT_DIR}/gp.jar"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# Default keys (can be overridden)
KEY_ENC=""
KEY_MAC=""
KEY_DEK=""
T0_MODE=false

# Parse arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        --key-enc) KEY_ENC="$2"; shift 2 ;;
        --key-mac) KEY_MAC="$2"; shift 2 ;;
        --key-dek) KEY_DEK="$2"; shift 2 ;;
        --t0) T0_MODE=true; shift ;;
        -h|--help)
            echo "Usage: $0 [OPTIONS]"
            echo "  --key-enc KEY    Encryption key"
            echo "  --key-mac KEY    MAC key"
            echo "  --key-dek KEY    DEK key"
            echo "  --t0             T=0 mode (separate gp.jar calls)"
            exit 0
            ;;
        *) shift ;;
    esac
done

# Build GP command base
build_gp_cmd() {
    local cmd="java -jar ${GP_JAR}"
    if [[ -n "$KEY_ENC" && -n "$KEY_MAC" && -n "$KEY_DEK" ]]; then
        cmd+=" --key-enc $KEY_ENC --key-mac $KEY_MAC --key-dek $KEY_DEK"
    fi
    echo "$cmd"
}

# Prompt for card cycle in T=0 mode
prompt_card_cycle() {
    if $T0_MODE; then
        local step="$1"
        echo ""
        echo -e "${YELLOW}  T=0: Remove and reinsert card, then press ENTER...${NC}"
        read -r
    fi
}

# Run APDU and show result
run_apdu() {
    local description="$1"
    local apdu="$2"
    local gp_cmd=$(build_gp_cmd)

    echo -e "${CYAN}${description}${NC}"
    echo "    APDU: ${apdu}"
    result=$($gp_cmd -d -a "${apdu}" 2>&1 | grep -E "RESP|<|>")
    echo "$result"
    echo ""
}

# Run multiple APDUs in sequence (for T=1 mode)
run_apdus_t1() {
    local gp_cmd=$(build_gp_cmd)
    gp_cmd+=" -d"

    # Add all APDUs
    for apdu in "$@"; do
        gp_cmd+=" -a ${apdu}"
    done

    $gp_cmd 2>&1 | grep -v "^WARNING" | grep -v "^Warning"
}

echo ""
echo -e "${BOLD}========================================${NC}"
echo -e "${BOLD}   EMV Contact Transaction Test        ${NC}"
echo -e "${BOLD}========================================${NC}"
if $T0_MODE; then
    echo -e "${YELLOW}   T=0 Mode: Separate card sessions    ${NC}"
fi
echo ""

# Test APDUs
PSE_AID="315041592E5359532E4444463031"  # 1PAY.SYS.DDF01
APP_AID="A0000009510001"  # Your payment app AID

# CDOL1 data (58 bytes)
CDOL1_DATA="000000000100000000000000084000000000000840260124001234567800000000000000000000000000000000000000000000000000000000"

if $T0_MODE; then
    # T=0 Mode: Each step is a separate gp.jar call

    echo -e "${CYAN}[1] SELECT PSE${NC}"
    run_apdu "SELECT 1PAY.SYS.DDF01" "00A404000E${PSE_AID}"
    prompt_card_cycle "SELECT PSE"

    echo -e "${CYAN}[2] READ RECORD PSE${NC}"
    run_apdu "READ RECORD SFI 1 Record 1" "00B2010C00"
    prompt_card_cycle "READ RECORD PSE"

    echo -e "${CYAN}[3] SELECT Payment App${NC}"
    run_apdu "SELECT AID ${APP_AID}" "00A4040007${APP_AID}"
    prompt_card_cycle "SELECT AID"

    echo -e "${CYAN}[4] GET PROCESSING OPTIONS${NC}"
    run_apdu "GPO (empty PDOL)" "80A80000028300"
    prompt_card_cycle "GPO"

    echo -e "${CYAN}[5] READ RECORD - SFI 1 Record 2${NC}"
    run_apdu "READ RECORD (Track 2, Cardholder)" "00B2020C00"
    prompt_card_cycle "READ RECORD SFI1R2"

    echo -e "${CYAN}[6] READ RECORD - SFI 2 Record 1${NC}"
    run_apdu "READ RECORD (Cert metadata)" "00B2011400"
    prompt_card_cycle "READ RECORD SFI2R1"

    echo -e "${CYAN}[7] READ RECORD - SFI 2 Record 2${NC}"
    run_apdu "READ RECORD (Issuer cert)" "00B2021400"
    prompt_card_cycle "READ RECORD SFI2R2"

    echo -e "${CYAN}[8] READ RECORD - SFI 3 Record 1${NC}"
    run_apdu "READ RECORD (PAN, Expiry)" "00B2011C00"
    prompt_card_cycle "READ RECORD SFI3R1"

    echo -e "${CYAN}[9] READ RECORD - SFI 3 Record 2${NC}"
    run_apdu "READ RECORD (CVM List)" "00B2021C00"
    prompt_card_cycle "READ RECORD SFI3R2"

    echo -e "${CYAN}[10] READ RECORD - SFI 3 Record 3${NC}"
    run_apdu "READ RECORD (Currency, DDOL)" "00B2031C00"
    prompt_card_cycle "READ RECORD SFI3R3"

    echo -e "${CYAN}[11] READ RECORD - SFI 3 Record 4${NC}"
    run_apdu "READ RECORD (ICC cert)" "00B2041C00"
    prompt_card_cycle "READ RECORD SFI3R4"

    echo -e "${CYAN}[12] GENERATE AC (ARQC)${NC}"
    run_apdu "GENERATE AC" "80AE80003A${CDOL1_DATA}"

else
    # T=1 Mode: All APDUs in one gp.jar call

    echo -e "${YELLOW}Running complete EMV flow in single session...${NC}"
    echo ""

    run_apdus_t1 \
        "00A404000E${PSE_AID}" \
        "00B2010C00" \
        "00A4040007${APP_AID}" \
        "80A80000028300" \
        "00B2020C00" \
        "00B2011400" \
        "00B2021400" \
        "00B2011C00" \
        "00B2021C00" \
        "00B2031C00" \
        "00B2041C00" \
        "80AE80003A${CDOL1_DATA}"
fi

echo ""
echo -e "${GREEN}Test complete!${NC}"
echo ""
echo -e "${BOLD}Expected responses:${NC}"
echo "  - SELECT PSE: 6F with directory entry (61 -> 4F, 50, 87)"
echo "  - SELECT AID: 6F with 84 (AID), A5 (50, 87)"
echo "  - GPO: 77 with 82 (AIP), 9F6C (CTQ), 94 (AFL)"
echo "  - READ RECORD: 70 templates with card data"
echo "  - GENERATE AC: 77 with 9F27, 9F36, 9F26, 9F10, [9F4B if CDA]"
echo ""
echo -e "${BOLD}Key tags to verify:${NC}"
echo "  - 9F6C (CTQ) in GPO response = contactless ready"
echo "  - 57 (Track 2) in SFI 1 Record 2"
echo "  - 5A (PAN) in SFI 3 Record 1"
echo "  - 9F4B (SDAD) in GENERATE AC = CDA working"
echo ""
