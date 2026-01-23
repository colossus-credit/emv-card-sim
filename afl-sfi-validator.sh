#!/bin/bash
#
# AFL/SFI Validator Script
# Reads card records based on AFL and validates the data
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GP_JAR="${SCRIPT_DIR}/gp.jar"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Function to get tag name
get_tag_name() {
    local tag="$1"
    case "$tag" in
        "57") echo "Track 2 Equivalent Data" ;;
        "5A") echo "Application Primary Account Number (PAN)" ;;
        "5F20") echo "Cardholder Name" ;;
        "5F24") echo "Application Expiration Date" ;;
        "5F25") echo "Application Effective Date" ;;
        "5F28") echo "Issuer Country Code" ;;
        "5F34") echo "PAN Sequence Number" ;;
        "8C") echo "Card Risk Management DOL 1 (CDOL1)" ;;
        "8D") echo "Card Risk Management DOL 2 (CDOL2)" ;;
        "8E") echo "Cardholder Verification Method (CVM) List" ;;
        "8F") echo "Certification Authority Public Key Index" ;;
        "90") echo "Issuer Public Key Certificate" ;;
        "92") echo "Issuer Public Key Remainder" ;;
        "9F07") echo "Application Usage Control" ;;
        "9F08") echo "Application Version Number" ;;
        "9F0D") echo "Issuer Action Code - Default" ;;
        "9F0E") echo "Issuer Action Code - Denial" ;;
        "9F0F") echo "Issuer Action Code - Online" ;;
        "9F10") echo "Issuer Application Data" ;;
        "9F32") echo "Issuer Public Key Exponent" ;;
        "9F36") echo "Application Transaction Counter (ATC)" ;;
        "9F46") echo "ICC Public Key Certificate" ;;
        "9F47") echo "ICC Public Key Exponent" ;;
        "9F48") echo "ICC Public Key Remainder" ;;
        "9F4A") echo "Static Data Authentication Tag List" ;;
        *) echo "Unknown" ;;
    esac
}

# Parse TLV data and display
parse_tlv() {
    local data="$1"
    local indent="$2"
    local pos=0
    local len=${#data}

    while [ $pos -lt $len ]; do
        # Get tag (1 or 2 bytes)
        local tag="${data:$pos:2}"
        pos=$((pos + 2))

        # Check if tag is 2 bytes (1F, 5F, 9F, DF, etc.)
        local first_nibble="${tag:0:1}"
        if [[ "$first_nibble" == "1" || "$first_nibble" == "5" || "$first_nibble" == "9" || "$first_nibble" == "D" || "$first_nibble" == "B" || "$first_nibble" == "7" ]]; then
            local second_byte="${tag:1:1}"
            if [[ "$second_byte" == "F" || "$second_byte" == "f" ]]; then
                tag="${data:$((pos-2)):4}"
                pos=$((pos + 2))
            fi
        fi

        if [ $pos -ge $len ]; then
            break
        fi

        # Get length
        local length_byte="${data:$pos:2}"
        pos=$((pos + 2))
        local length

        if [ "$length_byte" == "81" ]; then
            length=$((16#${data:$pos:2}))
            pos=$((pos + 2))
        elif [ "$length_byte" == "82" ]; then
            length=$((16#${data:$pos:4}))
            pos=$((pos + 4))
        else
            length=$((16#$length_byte))
        fi

        # Get value
        local value_len=$((length * 2))
        local value="${data:$pos:$value_len}"
        pos=$((pos + value_len))

        # Get tag name
        local tag_upper=$(echo "$tag" | tr '[:lower:]' '[:upper:]')
        local tag_name=$(get_tag_name "$tag_upper")

        # Check if value is all zeros
        local is_zeros=true
        local cleaned_value=$(echo "$value" | tr -d ' ')
        for ((i=0; i<${#cleaned_value}; i++)); do
            if [ "${cleaned_value:$i:1}" != "0" ]; then
                is_zeros=false
                break
            fi
        done

        # Display
        if $is_zeros && [ ${#value} -gt 0 ]; then
            printf "${indent}${RED}Tag %s (%s): %d bytes - ALL ZEROS!${NC}\n" "$tag_upper" "$tag_name" "$length"
            printf "${indent}  ${RED}Value: %s${NC}\n" "$value"
        else
            printf "${indent}${GREEN}Tag %s (%s): %d bytes${NC}\n" "$tag_upper" "$tag_name" "$length"
            if [ ${#value} -le 64 ]; then
                printf "${indent}  Value: %s\n" "$value"
            else
                printf "${indent}  Value: %s...(%d bytes total)\n" "${value:0:64}" "$length"
            fi
        fi
    done
}

echo "=========================================="
echo "   AFL/SFI Validator Script"
echo "=========================================="
echo ""

# Check for gp.jar
if [ ! -f "$GP_JAR" ]; then
    echo -e "${RED}gp.jar not found at $GP_JAR${NC}"
    exit 1
fi

# Build command to send all APDUs
# SELECT application + GPO + READ RECORD for all AFL entries
echo -e "${CYAN}Sending APDUs via GlobalPlatformPro...${NC}"
echo ""

# AFL from personalization: 08 02 02 00 | 10 01 05 03 | 18 01 03 00
# SFI 1, Records 2-2
# SFI 2, Records 1-5
# SFI 3, Records 1-3

GP_CMD="java -jar $GP_JAR -d"
GP_CMD+=" -a 00A4040007A000000951000100"   # SELECT AID
GP_CMD+=" -a 80A80000028300"               # GPO (minimal)
# READ RECORD commands in AFL order: SFI1 -> SFI3 (static data) -> SFI2 (ODA)
GP_CMD+=" -a 00B2020C00"                   # READ RECORD SFI 1, Record 2
GP_CMD+=" -a 00B2011C00"                   # READ RECORD SFI 3, Record 1 (static data)
GP_CMD+=" -a 00B2021C00"                   # READ RECORD SFI 3, Record 2
GP_CMD+=" -a 00B2031C00"                   # READ RECORD SFI 3, Record 3
GP_CMD+=" -a 00B2011400"                   # READ RECORD SFI 2, Record 1 (ODA records)
GP_CMD+=" -a 00B2021400"                   # READ RECORD SFI 2, Record 2
GP_CMD+=" -a 00B2031400"                   # READ RECORD SFI 2, Record 3
GP_CMD+=" -a 00B2041400"                   # READ RECORD SFI 2, Record 4
GP_CMD+=" -a 00B2051400"                   # READ RECORD SFI 2, Record 5

echo "Command: $GP_CMD"
echo ""

# Run the command and capture output
OUTPUT=$($GP_CMD 2>&1)
echo "Raw GP output:"
echo "$OUTPUT"
echo ""

echo "=========================================="
echo "   Parsing APDU Responses"
echo "=========================================="
echo ""

# Parse each response line from debug output (A<< lines)
RESPONSE_NUM=0
# Order matches AFL: SFI1 -> SFI3 (static data) -> SFI2 (ODA records)
COMMANDS=("SELECT AID" "GPO" "SFI1-REC2" "SFI3-REC1" "SFI3-REC2" "SFI3-REC3" "SFI2-REC1" "SFI2-REC2" "SFI2-REC3" "SFI2-REC4" "SFI2-REC5")
EXPECTED_TAGS=("FCI" "AIP+AFL" "57,5F20" "5A,5F24,5F25,5F28,5F34,9F07,9F0D,9F0E,9F0F,9F08" "8C,8D,8E" "9F36,9F10" "8F,9F32,9F4A" "90" "92" "9F46" "9F47,9F48")

while IFS= read -r line; do
    # Look for APDU response lines (A<< format from debug output)
    if [[ "$line" =~ ^A\<\< ]]; then
        # Extract the hex data and status word from debug line
        # Format: A<< (0053+2) (175ms) 6F33...9000
        hex_data=$(echo "$line" | sed 's/^A<< ([^)]*) ([^)]*) //' | tr -d ' ')

        if [ ${#hex_data} -ge 4 ]; then
            # Extract SW (last 4 chars)
            SW="${hex_data: -4}"
            DATA="${hex_data:0:${#hex_data}-4}"

            if [ $RESPONSE_NUM -lt ${#COMMANDS[@]} ]; then
                CMD_NAME="${COMMANDS[$RESPONSE_NUM]}"
                EXPECTED="${EXPECTED_TAGS[$RESPONSE_NUM]}"

                echo -e "${CYAN}=== Response $RESPONSE_NUM: $CMD_NAME ===${NC}"
                echo "Expected tags: $EXPECTED"
                echo "SW: $SW"

                if [ "$SW" == "9000" ]; then
                    echo -e "${GREEN}Status: OK${NC}"

                    if [ ${#DATA} -gt 0 ]; then
                        # Skip template headers (6F, 77, 70, 80)
                        PARSE_DATA="$DATA"
                        if [[ "$PARSE_DATA" == 6F* || "$PARSE_DATA" == 77* || "$PARSE_DATA" == 70* ]]; then
                            len_byte="${PARSE_DATA:2:2}"
                            if [ "$len_byte" == "81" ]; then
                                PARSE_DATA="${PARSE_DATA:6}"
                            elif [ "$len_byte" == "82" ]; then
                                PARSE_DATA="${PARSE_DATA:8}"
                            else
                                PARSE_DATA="${PARSE_DATA:4}"
                            fi
                        elif [[ "$PARSE_DATA" == 80* ]]; then
                            # Format 1 GPO response
                            len=$((16#${PARSE_DATA:2:2}))
                            echo "  AIP: ${PARSE_DATA:4:4}"
                            echo "  AFL: ${PARSE_DATA:8:$((len*2-4))}"
                            PARSE_DATA=""
                        fi

                        if [ ${#PARSE_DATA} -gt 0 ]; then
                            echo "TLV Data:"
                            parse_tlv "$PARSE_DATA" "  "
                        fi
                    fi
                elif [ "$SW" == "6A83" ]; then
                    echo -e "${RED}Status: Record not found${NC}"
                elif [ "$SW" == "6700" ]; then
                    echo -e "${RED}Status: Wrong length${NC}"
                elif [ "$SW" == "6982" ]; then
                    echo -e "${RED}Status: Security status not satisfied${NC}"
                else
                    echo -e "${RED}Status: Error (SW=$SW)${NC}"
                fi
                echo ""
            fi

            RESPONSE_NUM=$((RESPONSE_NUM + 1))
        fi
    fi
done <<< "$OUTPUT"

echo ""
echo "=========================================="
echo "   AFL Structure Analysis"
echo "=========================================="
echo ""
echo "AFL from personalization: 08 02 02 00 | 10 01 05 03 | 18 01 03 00"
echo ""
echo "Entry 1: 08 02 02 00"
echo "  SFI byte: 0x08 = 0000 1000"
echo "  SFI: 08 >> 3 = 1"
echo "  First record: 2"
echo "  Last record: 2"
echo "  ODA records: 0"
echo "  P2 for READ RECORD: (1 << 3) | 0x04 = 0x0C"
echo ""
echo "Entry 2: 10 01 05 03"
echo "  SFI byte: 0x10 = 0001 0000"
echo "  SFI: 10 >> 3 = 2"
echo "  First record: 1"
echo "  Last record: 5"
echo "  ODA records: 3 (records 1-3 used for ODA)"
echo "  P2 for READ RECORD: (2 << 3) | 0x04 = 0x14"
echo ""
echo "Entry 3: 18 01 03 00"
echo "  SFI byte: 0x18 = 0001 1000"
echo "  SFI: 18 >> 3 = 3"
echo "  First record: 1"
echo "  Last record: 3"
echo "  ODA records: 0"
echo "  P2 for READ RECORD: (3 << 3) | 0x04 = 0x1C"
echo ""

echo "=========================================="
echo "   Record Template Configuration (CORRECTED)"
echo "=========================================="
echo ""
echo "Template format: 80 [len?] [record#] [P2] [tag_len] [tag_len_type] [tag-bytes...]"
echo ""
echo -e "${GREEN}SFI 1, Record 2: 80 03 02 0C 04 00 57 5F20${NC}"
echo "  Record 2, P2=0C (SFI 1)"
echo "  Tags: 57(1) + 5F20(2) = 4 bytes [tag_len=04] ✓"
echo ""
echo -e "${GREEN}SFI 2, Record 1: 80 03 01 14 05 00 8F 9F32 9F4A${NC}"
echo "  Record 1, P2=14 (SFI 2)"
echo "  Tags: 8F(1) + 9F32(2) + 9F4A(2) = 5 bytes [tag_len=05] ✓"
echo ""
echo -e "${GREEN}SFI 2, Record 2: 80 03 02 14 01 00 90${NC}"
echo "  Record 2, P2=14 (SFI 2)"
echo "  Tags: 90(1) = 1 byte [tag_len=01] ✓"
echo ""
echo -e "${GREEN}SFI 2, Record 3: 80 03 03 14 01 00 92${NC}"
echo "  Record 3, P2=14 (SFI 2)"
echo "  Tags: 92(1) = 1 byte [tag_len=01] ✓"
echo ""
echo -e "${GREEN}SFI 2, Record 4: 80 03 04 14 02 00 9F46${NC}"
echo "  Record 4, P2=14 (SFI 2)"
echo "  Tags: 9F46(2) = 2 bytes [tag_len=02] ✓"
echo ""
echo -e "${GREEN}SFI 2, Record 5: 80 03 05 14 04 00 9F47 9F48${NC}"
echo "  Record 5, P2=14 (SFI 2)"
echo "  Tags: 9F47(2) + 9F48(2) = 4 bytes [tag_len=04] ✓"
echo ""
echo -e "${GREEN}SFI 3, Record 1: 80 03 01 1C 13 00 5A 5F24 5F25 5F28 5F34 9F07 9F0D 9F0E 9F0F 9F08${NC}"
echo "  Record 1, P2=1C (SFI 3)"
echo "  Tags: 5A(1) + 5F24(2) + 5F25(2) + 5F28(2) + 5F34(2) + 9F07(2) + 9F0D(2) + 9F0E(2) + 9F0F(2) + 9F08(2)"
echo "       = 1 + (9*2) = 19 = 0x13 bytes [tag_len=13] ✓"
echo ""
echo -e "${GREEN}SFI 3, Record 2: 80 03 02 1C 03 00 8C 8D 8E${NC}"
echo "  Record 2, P2=1C (SFI 3)"
echo "  Tags: 8C(1) + 8D(1) + 8E(1) = 3 bytes [tag_len=03] ✓"
echo "  NOTE: No 00 bytes between tags! This is critical for CDOL1/CDOL2/CVM List."
echo ""
echo -e "${GREEN}SFI 3, Record 3: 80 03 03 1C 04 00 9F36 9F10${NC}"
echo "  Record 3, P2=1C (SFI 3)"
echo "  Tags: 9F36(2) + 9F10(2) = 4 bytes [tag_len=04] ✓"
echo ""

echo "=========================================="
echo "   Template Validation (card_ops.sh)"
echo "=========================================="
echo ""

# Expected templates (corrected)
declare -a EXPECTED_TEMPLATES=(
    "8003020C0400575F20"           # SFI 1, Record 2
    "8003011405008F9F329F4A"       # SFI 2, Record 1
    "80030214010090"               # SFI 2, Record 2
    "80030314010092"               # SFI 2, Record 3
    "8003041402009F46"             # SFI 2, Record 4
    "8003051404009F479F48"         # SFI 2, Record 5
    "8003011C13005A5F245F255F285F349F079F0D9F0E9F0F9F08"  # SFI 3, Record 1
    "8003021C03008C8D8E"           # SFI 3, Record 2
    "8003031C04009F369F10"         # SFI 3, Record 3
)

declare -a TEMPLATE_NAMES=(
    "SFI 1, Record 2 (Track2, Cardholder Name)"
    "SFI 2, Record 1 (CA Index, Issuer Exp, SDA Tag List)"
    "SFI 2, Record 2 (Issuer Certificate)"
    "SFI 2, Record 3 (Issuer PK Remainder)"
    "SFI 2, Record 4 (ICC Certificate)"
    "SFI 2, Record 5 (ICC Exp, ICC PK Remainder)"
    "SFI 3, Record 1 (PAN, Expiry, IACs, etc.)"
    "SFI 3, Record 2 (CDOL1, CDOL2, CVM List) - CRITICAL"
    "SFI 3, Record 3 (ATC, IAD)"
)

CARD_OPS_FILE="${SCRIPT_DIR}/scripts/card_ops.sh"
if [ -f "$CARD_OPS_FILE" ]; then
    echo "Checking templates in: $CARD_OPS_FILE"
    echo ""

    ALL_VALID=true
    for i in "${!EXPECTED_TEMPLATES[@]}"; do
        expected="${EXPECTED_TEMPLATES[$i]}"
        name="${TEMPLATE_NAMES[$i]}"

        # Search for the template in card_ops.sh
        if grep -q "$expected" "$CARD_OPS_FILE" 2>/dev/null; then
            echo -e "${GREEN}✓ $name${NC}"
            echo "  Template: $expected"
        else
            echo -e "${RED}✗ $name${NC}"
            echo "  Expected: $expected"
            # Try to find what's actually there
            pattern="${expected:0:8}"
            actual=$(grep -o "${pattern}[^\"]*" "$CARD_OPS_FILE" 2>/dev/null | head -1)
            if [ -n "$actual" ]; then
                echo -e "  ${RED}Found:    $actual${NC}"
            fi
            ALL_VALID=false
        fi
        echo ""
    done

    if $ALL_VALID; then
        echo -e "${GREEN}=========================================="
        echo "   ALL TEMPLATES VALID!"
        echo "==========================================${NC}"
    else
        echo -e "${RED}=========================================="
        echo "   TEMPLATE ERRORS DETECTED!"
        echo "   Run: ./scripts/card_ops.sh personalize"
        echo "   after fixing the templates"
        echo "==========================================${NC}"
    fi
else
    echo -e "${YELLOW}card_ops.sh not found at $CARD_OPS_FILE${NC}"
    echo "Cannot validate templates."
fi

echo ""
echo "=========================================="
echo "   Validation Complete"
echo "=========================================="
