#!/bin/bash
#
# AFL/SFI Validator Script - Works with any EMV card
# Sends all commands in a single gp.jar session to avoid card reset issues
#
# Usage:
#   ./afl-sfi-validator.sh           # Contact mode (PSE)
#   ./afl-sfi-validator.sh --ppse    # Contactless mode (PPSE)
#   ./afl-sfi-validator.sh -a AID    # Specify AID directly
#

set -e

# Show help
show_help() {
    echo "AFL/SFI Validator - EMV Card Record Reader"
    echo ""
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  --ppse, -p       Use PPSE (2PAY.SYS.DDF01) for contactless"
    echo "  --aid, -a AID    Specify AID directly (hex string)"
    echo "  --help, -h       Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0                           # Contact (PSE) mode"
    echo "  $0 --ppse                    # Contactless (PPSE) mode"
    echo "  $0 -a A0000009511010         # Direct AID selection"
    echo ""
    exit 0
}

# Check for help flag early
for arg in "$@"; do
    if [[ "$arg" == "--help" || "$arg" == "-h" ]]; then
        show_help
    fi
done

# Function to read lines into an array (compatible with bash 3.x on macOS)
read_lines_into_array() {
    local varname=$1
    local i=0
    eval "$varname=()"
    while IFS= read -r line; do
        eval "${varname}[$i]=\"\$line\""
        i=$((i + 1))
    done
}

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GP_JAR="${SCRIPT_DIR}/gp.jar"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

# Function to get tag name
get_tag_name() {
    local tag="$1"
    case "$tag" in
        "4F") echo "AID" ;;
        "50") echo "Application Label" ;;
        "57") echo "Track 2 Equivalent Data" ;;
        "5A") echo "PAN" ;;
        "5F20") echo "Cardholder Name" ;;
        "5F24") echo "Expiration Date" ;;
        "5F25") echo "Effective Date" ;;
        "5F28") echo "Issuer Country Code" ;;
        "5F2D") echo "Language Preference" ;;
        "5F34") echo "PAN Sequence Number" ;;
        "82") echo "AIP" ;;
        "84") echo "DF Name" ;;
        "87") echo "Application Priority Indicator" ;;
        "8C") echo "CDOL1" ;;
        "8D") echo "CDOL2" ;;
        "8E") echo "CVM List" ;;
        "8F") echo "CA Public Key Index" ;;
        "90") echo "Issuer PK Certificate" ;;
        "92") echo "Issuer PK Remainder" ;;
        "94") echo "AFL" ;;
        "9F07") echo "Application Usage Control" ;;
        "9F08") echo "App Version Number" ;;
        "9F0D") echo "IAC Default" ;;
        "9F0E") echo "IAC Denial" ;;
        "9F0F") echo "IAC Online" ;;
        "9F10") echo "Issuer Application Data" ;;
        "9F11") echo "Issuer Code Table Index" ;;
        "9F12") echo "Application Preferred Name" ;;
        "9F26") echo "Application Cryptogram" ;;
        "9F27") echo "CID" ;;
        "9F32") echo "Issuer PK Exponent" ;;
        "9F36") echo "ATC" ;;
        "9F38") echo "PDOL" ;;
        "9F42") echo "Application Currency Code" ;;
        "9F44") echo "Application Currency Exponent" ;;
        "9F46") echo "ICC PK Certificate" ;;
        "9F47") echo "ICC PK Exponent" ;;
        "9F48") echo "ICC PK Remainder" ;;
        "9F4A") echo "SDA Tag List" ;;
        "9F4B") echo "Signed Dynamic Application Data" ;;
        "A5") echo "FCI Proprietary Template" ;;
        "6F") echo "FCI Template" ;;
        "61") echo "Directory Entry" ;;
        "70") echo "EMV Record Template" ;;
        "77") echo "Response Message Template Format 2" ;;
        "BF0C") echo "FCI Issuer Discretionary Data" ;;
        *) echo "Unknown" ;;
    esac
}

# Extract a TLV tag value from hex data (recursive)
extract_tag() {
    local data="$1"
    local target_tag="$2"
    local pos=0
    local len=${#data}

    target_tag=$(echo "$target_tag" | tr '[:lower:]' '[:upper:]')

    while [ $pos -lt $len ]; do
        # Get tag
        local tag="${data:$pos:2}"
        pos=$((pos + 2))

        if [ $pos -ge $len ]; then break; fi

        # Check for 2-byte tag (5Fxx, 9Fxx, BFxx, etc.)
        local first_byte=$((16#$tag))
        if [ $((first_byte & 0x1F)) -eq 31 ]; then
            tag="${tag}${data:$pos:2}"
            pos=$((pos + 2))
        fi

        if [ $pos -ge $len ]; then break; fi

        # Get length
        local len_byte="${data:$pos:2}"
        pos=$((pos + 2))
        local length

        if [ "$len_byte" == "81" ]; then
            length=$((16#${data:$pos:2}))
            pos=$((pos + 2))
        elif [ "$len_byte" == "82" ]; then
            length=$((16#${data:$pos:4}))
            pos=$((pos + 4))
        else
            length=$((16#$len_byte))
        fi

        # Get value
        local value_len=$((length * 2))
        local value="${data:$pos:$value_len}"
        pos=$((pos + value_len))

        tag=$(echo "$tag" | tr '[:lower:]' '[:upper:]')

        if [ "$tag" == "$target_tag" ]; then
            echo "$value"
            return 0
        fi

        # Recurse into constructed tags (6F, A5, 70, 77, 61, BF0C)
        if [[ "$tag" == "6F" || "$tag" == "A5" || "$tag" == "70" || "$tag" == "77" || "$tag" == "61" || "$tag" == "BF0C" ]]; then
            local nested_result=$(extract_tag "$value" "$target_tag")
            if [ -n "$nested_result" ]; then
                echo "$nested_result"
                return 0
            fi
        fi
    done

    echo ""
    return 1
}

# Parse and display TLV
parse_tlv() {
    local data="$1"
    local indent="$2"
    local pos=0
    local len=${#data}

    while [ $pos -lt $len ]; do
        local tag="${data:$pos:2}"
        pos=$((pos + 2))

        if [ $pos -ge $len ]; then break; fi

        local first_byte=$((16#$tag))
        if [ $((first_byte & 0x1F)) -eq 31 ]; then
            tag="${tag}${data:$pos:2}"
            pos=$((pos + 2))
        fi

        if [ $pos -ge $len ]; then break; fi

        local len_byte="${data:$pos:2}"
        pos=$((pos + 2))
        local length

        if [ "$len_byte" == "81" ]; then
            length=$((16#${data:$pos:2}))
            pos=$((pos + 2))
        elif [ "$len_byte" == "82" ]; then
            length=$((16#${data:$pos:4}))
            pos=$((pos + 4))
        else
            length=$((16#$len_byte))
        fi

        local value_len=$((length * 2))
        local value="${data:$pos:$value_len}"
        pos=$((pos + value_len))

        local tag_upper=$(echo "$tag" | tr '[:lower:]' '[:upper:]')
        local tag_name=$(get_tag_name "$tag_upper")

        printf "${indent}${GREEN}%s${NC} (%s): %d bytes\n" "$tag_upper" "$tag_name" "$length"
        if [ ${#value} -le 80 ]; then
            printf "${indent}  %s\n" "$value"
        else
            printf "${indent}  %s...(%d bytes)\n" "${value:0:64}" "$length"
        fi

        # Recurse into constructed tags
        if [[ "$tag_upper" == "6F" || "$tag_upper" == "A5" || "$tag_upper" == "70" || "$tag_upper" == "77" || "$tag_upper" == "61" || "$tag_upper" == "BF0C" ]]; then
            parse_tlv "$value" "${indent}  "
        fi
    done
}

# Parse gp.jar output line to get data and SW
parse_response() {
    local line="$1"
    # Format: A<< (length+sw) (time) DATA SW
    # Example: A<< (0032+2) (27ms) 6F1E840E315041592E5359532E4444463031A50C8801015F2D02656E9F110101 9000

    # Extract just the hex data and SW (last two fields)
    local hex_part=$(echo "$line" | sed 's/.*) //')
    echo "$hex_part" | tr -d ' '
}

echo "=========================================="
echo "   EMV Card AFL/SFI Validator"
echo "=========================================="
echo ""

if [ ! -f "$GP_JAR" ]; then
    echo -e "${RED}gp.jar not found at $GP_JAR${NC}"
    exit 1
fi

# Parse command line arguments
OVERRIDE_AID=""
USE_PPSE=false

while [[ $# -gt 0 ]]; do
    case "$1" in
        --ppse|-p)
            USE_PPSE=true
            shift
            ;;
        --aid|-a)
            OVERRIDE_AID="$2"
            shift 2
            ;;
        *)
            # Legacy: first positional arg is AID
            if [ -z "$OVERRIDE_AID" ]; then
                OVERRIDE_AID="$1"
            fi
            shift
            ;;
    esac
done

echo "Mode: $(if $USE_PPSE; then echo 'Contactless (PPSE)'; else echo 'Contact (PSE)'; fi)"
echo ""

# ============================================
# PHASE 1: Discover AID from PSE or PPSE
# ============================================
echo -e "${CYAN}Phase 1: Application Discovery${NC}"
echo ""

# PSE AID: 1PAY.SYS.DDF01 (contact)
# PPSE AID: 2PAY.SYS.DDF01 (contactless)
if $USE_PPSE; then
    DIRECTORY_AID="325041592E5359532E4444463031"  # 2PAY.SYS.DDF01
    DIRECTORY_NAME="PPSE"
else
    DIRECTORY_AID="315041592E5359532E4444463031"  # 1PAY.SYS.DDF01
    DIRECTORY_NAME="PSE"
fi

# Send directory select + read record in one session
echo "Selecting $DIRECTORY_NAME and reading directory..."
PHASE1_OUTPUT=$(java -jar "$GP_JAR" -d \
    -a "00A404000E${DIRECTORY_AID}00" \
    -a "00B2010C00" \
    2>&1)

# Parse responses
read_lines_into_array RESPONSES < <(echo "$PHASE1_OUTPUT" | grep "^A<<")

if [ ${#RESPONSES[@]} -lt 1 ]; then
    echo -e "${RED}No response from card. Is card inserted?${NC}"
    exit 1
fi

# Parse directory SELECT response
DIR_LINE="${RESPONSES[0]}"
DIR_FULL=$(parse_response "$DIR_LINE")
DIR_SW="${DIR_FULL: -4}"
DIR_DATA="${DIR_FULL:0:${#DIR_FULL}-4}"

echo "$DIRECTORY_NAME SELECT SW: $DIR_SW"

SELECTED_AID=""

if [ "$DIR_SW" == "9000" ]; then
    echo -e "${GREEN}$DIRECTORY_NAME Selected successfully${NC}"

    # For PPSE, the directory entry is in the SELECT response (FCI), not a separate record
    if $USE_PPSE; then
        echo ""
        echo "$DIRECTORY_NAME FCI contents:"
        parse_tlv "$DIR_DATA" "  "

        # Extract AID from directory entry (tag 4F inside BF0C/61)
        SELECTED_AID=$(extract_tag "$DIR_DATA" "4F")
        if [ -n "$SELECTED_AID" ]; then
            echo ""
            echo -e "${GREEN}Found AID: $SELECTED_AID${NC}"
        fi
    else
        # Parse PSE READ RECORD response
        if [ ${#RESPONSES[@]} -ge 2 ]; then
            REC_LINE="${RESPONSES[1]}"
            REC_FULL=$(parse_response "$REC_LINE")
            REC_SW="${REC_FULL: -4}"
            REC_DATA="${REC_FULL:0:${#REC_FULL}-4}"

            echo "$DIRECTORY_NAME Record SW: $REC_SW"

            if [ "$REC_SW" == "9000" ]; then
                echo ""
                echo "$DIRECTORY_NAME Record contents:"
                parse_tlv "$REC_DATA" "  "

                # Extract AID from directory entry (tag 4F inside 61)
                SELECTED_AID=$(extract_tag "$REC_DATA" "4F")
                if [ -n "$SELECTED_AID" ]; then
                    echo ""
                    echo -e "${GREEN}Found AID: $SELECTED_AID${NC}"
                fi
            fi
        fi
    fi
else
    echo "$DIRECTORY_NAME not available, will try common AIDs"
fi

# If no AID from PSE, try common AIDs
if [ -z "$SELECTED_AID" ]; then
    if [ -n "$OVERRIDE_AID" ]; then
        SELECTED_AID="$OVERRIDE_AID"
        echo "Using provided AID: $SELECTED_AID"
    else
        echo ""
        echo "Trying common AIDs..."

        # Build command to try all common AIDs
        if $USE_PPSE; then
            # Contactless AIDs
            COMMON_AIDS=(
                "A0000009511010"    # COLOSSUS Contactless
                "A0000000031010"    # Visa Credit/Debit
                "A0000000032010"    # Visa Electron
                "A0000000041010"    # Mastercard Credit/Debit
                "A0000000043060"    # Maestro
                "A0000000651010"    # JCB
                "A000000025010104"  # Amex
            )
        else
            # Contact AIDs
            COMMON_AIDS=(
                "A0000009510001"    # COLOSSUS Contact
                "A0000000031010"    # Visa Credit/Debit
                "A0000000032010"    # Visa Electron
                "A0000000041010"    # Mastercard Credit/Debit
                "A0000000043060"    # Maestro
                "A0000000651010"    # JCB
                "A000000025010104"  # Amex
            )
        fi

        GP_ARGS=""
        for aid in "${COMMON_AIDS[@]}"; do
            aid_len=$(printf '%02X' $((${#aid} / 2)))
            GP_ARGS+=" -a 00A40400${aid_len}${aid}00"
        done

        AID_OUTPUT=$(java -jar "$GP_JAR" -d $GP_ARGS 2>&1)
        read_lines_into_array AID_RESPONSES < <(echo "$AID_OUTPUT" | grep "^A<<")

        for i in "${!AID_RESPONSES[@]}"; do
            RESP_FULL=$(parse_response "${AID_RESPONSES[$i]}")
            RESP_SW="${RESP_FULL: -4}"
            if [ "$RESP_SW" == "9000" ]; then
                SELECTED_AID="${COMMON_AIDS[$i]}"
                echo -e "${GREEN}Found working AID: $SELECTED_AID${NC}"
                break
            fi
        done
    fi
fi

if [ -z "$SELECTED_AID" ]; then
    echo -e "${RED}No AID found on card${NC}"
    exit 1
fi

# ============================================
# PHASE 2 & 3: Single session - Select, GPO, and Read Records
# ============================================
echo ""
echo -e "${YELLOW}Please remove and re-insert the card, then press Enter...${NC}"
read -r
echo ""
echo -e "${CYAN}Phase 2 & 3: Full Card Read (single session)${NC}"
echo ""

AID_LEN=$(printf '%02X' $((${#SELECTED_AID} / 2)))

# Build GPO command - use empty PDOL (works for most cards)
# Many cards accept 83 00 (empty PDOL data)
GPO_CMD="80A8000002830000"

# Build a comprehensive READ RECORD command list that covers most cards
# SFI 1-4, records 1-5 each
declare -a READ_COMMANDS=()
declare -a RECORD_NAMES=()

for sfi in 1 2 3 4; do
    P2=$(printf '%02X' $(((sfi << 3) | 4)))
    for rec in 1 2 3 4 5; do
        REC_HEX=$(printf '%02X' $rec)
        READ_COMMANDS+=("00B2${REC_HEX}${P2}00")
        RECORD_NAMES+=("SFI${sfi}-REC${rec}")
    done
done

# Build ALL commands in one gp.jar call: SELECT + GPO + all READ RECORDs
GP_ARGS="-a 00A40400${AID_LEN}${SELECTED_AID}00"
GP_ARGS+=" -a $GPO_CMD"
for cmd in "${READ_COMMANDS[@]}"; do
    GP_ARGS+=" -a $cmd"
done

echo "SELECT AID: $SELECTED_AID"
echo "Sending SELECT + GPO + READ RECORDS in single session..."
echo ""

FULL_OUTPUT=$(java -jar "$GP_JAR" -d $GP_ARGS 2>&1)
read_lines_into_array ALL_RESPONSES < <(echo "$FULL_OUTPUT" | grep "^A<<")

if [ ${#ALL_RESPONSES[@]} -lt 2 ]; then
    echo -e "${RED}No response from card${NC}"
    exit 1
fi

# Parse SELECT response (index 0)
SELECT_FULL=$(parse_response "${ALL_RESPONSES[0]}")
SELECT_SW="${SELECT_FULL: -4}"
SELECT_DATA="${SELECT_FULL:0:${#SELECT_FULL}-4}"

echo "SELECT Response SW: $SELECT_SW"
if [ "$SELECT_SW" != "9000" ]; then
    echo -e "${RED}Failed to select AID${NC}"
    exit 1
fi

echo ""
echo "FCI Template:"
parse_tlv "$SELECT_DATA" "  "

# Parse GPO response (index 1)
GPO_FULL=$(parse_response "${ALL_RESPONSES[1]}")
GPO_SW="${GPO_FULL: -4}"
GPO_DATA="${GPO_FULL:0:${#GPO_FULL}-4}"

echo ""
echo "GPO Response SW: $GPO_SW"

AFL=""
AIP=""

if [ "$GPO_SW" == "9000" ]; then
    echo ""
    echo "GPO Response:"

    # Parse GPO response format
    FIRST_TAG="${GPO_DATA:0:2}"
    if [ "$FIRST_TAG" == "80" ]; then
        # Format 1: 80 len AIP(2) AFL(var)
        LEN=$((16#${GPO_DATA:2:2}))
        AIP="${GPO_DATA:4:4}"
        AFL="${GPO_DATA:8:$((LEN*2-4))}"
        echo "  Format 1 Response"
        echo "  AIP: $AIP"
        echo "  AFL: $AFL"
    elif [ "$FIRST_TAG" == "77" ]; then
        # Format 2: 77 len [TLV...]
        echo "  Format 2 Response"
        parse_tlv "$GPO_DATA" "  "
        AIP=$(extract_tag "$GPO_DATA" "82")
        AFL=$(extract_tag "$GPO_DATA" "94")
        echo ""
        echo "  Extracted AIP: $AIP"
        echo "  Extracted AFL: $AFL"
    else
        echo -e "${YELLOW}Unknown GPO format, continuing with record read${NC}"
    fi
else
    echo -e "${YELLOW}GPO failed (SW=$GPO_SW), continuing with record read${NC}"
fi

# ============================================
# Display Record Contents
# ============================================
echo ""
echo "=========================================="
echo "   Reading Records"
echo "=========================================="
echo ""

if [ -n "$AFL" ]; then
    echo "AFL: $AFL"
    echo ""
fi

TOTAL_RECORDS=${#READ_COMMANDS[@]}
RECORDS_FOUND=0

# READ RECORD responses start at index 2 (after SELECT and GPO)
for i in "${!READ_COMMANDS[@]}"; do
    RESP_IDX=$((i + 2))
    NAME="${RECORD_NAMES[$i]}"

    if [ $RESP_IDX -lt ${#ALL_RESPONSES[@]} ]; then
        RESP_FULL=$(parse_response "${ALL_RESPONSES[$RESP_IDX]}")
        SW="${RESP_FULL: -4}"
        DATA="${RESP_FULL:0:${#RESP_FULL}-4}"

        if [ "$SW" == "9000" ]; then
            RECORDS_FOUND=$((RECORDS_FOUND + 1))
            echo -e "${CYAN}=== $NAME ===${NC}"
            echo "Command: ${READ_COMMANDS[$i]}"
            echo -e "${GREEN}SW: $SW (OK)${NC}"
            echo "Response length: $((${#DATA} / 2)) bytes"

            # Skip 70 template header if present
            if [[ "$DATA" == 70* ]]; then
                len_byte="${DATA:2:2}"
                if [ "$len_byte" == "81" ]; then
                    INNER="${DATA:6}"
                elif [ "$len_byte" == "82" ]; then
                    INNER="${DATA:8}"
                else
                    INNER="${DATA:4}"
                fi
                parse_tlv "$INNER" "  "
            else
                parse_tlv "$DATA" "  "
            fi
            echo ""
        fi
    fi
done

echo "=========================================="
echo "   Validation Complete - Found $RECORDS_FOUND records"
echo "=========================================="
