#!/bin/bash
#
# EMV Card Profile Cloner
# Reads PSE and PPSE from a card and builds a complete profile YAML
#
# Usage:
#   ./clone-profile.sh                    # Output to stdout
#   ./clone-profile.sh -o profile.yaml    # Output to file
#   ./clone-profile.sh --contact-only     # Only read contact (PSE)
#   ./clone-profile.sh --contactless-only # Only read contactless (PPSE)
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GP_JAR="${SCRIPT_DIR}/gp.jar"

# Colors for stderr output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

# Output file (empty = stdout)
OUTPUT_FILE=""
CONTACT_ONLY=false
CONTACTLESS_ONLY=false

# Show help
show_help() {
    echo "EMV Card Profile Cloner"
    echo ""
    echo "Reads PSE and PPSE from a card and builds a complete profile YAML"
    echo ""
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  -o, --output FILE      Write YAML to file (default: stdout)"
    echo "  --contact-only         Only read contact interface (PSE)"
    echo "  --contactless-only     Only read contactless interface (PPSE)"
    echo "  -h, --help             Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0                           # Output to stdout"
    echo "  $0 -o card_profile.yaml      # Save to file"
    echo "  $0 --contactless-only        # Only PPSE"
    echo ""
    exit 0
}

# Log to stderr (so YAML goes to stdout cleanly)
log() {
    echo -e "$@" >&2
}

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

# Function to get tag name
get_tag_name() {
    local tag="$1"
    case "$tag" in
        "4F") echo "AID" ;;
        "50") echo "Application Label" ;;
        "56") echo "Track 1 Data" ;;
        "57") echo "Track 2 Equivalent Data" ;;
        "5A") echo "PAN" ;;
        "5F20") echo "Cardholder Name" ;;
        "5F24") echo "Expiration Date" ;;
        "5F25") echo "Effective Date" ;;
        "5F28") echo "Issuer Country Code" ;;
        "5F2D") echo "Language Preference" ;;
        "5F30") echo "Service Code" ;;
        "5F34") echo "PAN Sequence Number" ;;
        "82") echo "AIP" ;;
        "84") echo "DF Name" ;;
        "87") echo "Application Priority Indicator" ;;
        "88") echo "SFI of the Directory Elementary File" ;;
        "8C") echo "CDOL1" ;;
        "8D") echo "CDOL2" ;;
        "8E") echo "CVM List" ;;
        "8F") echo "CA Public Key Index" ;;
        "90") echo "Issuer PK Certificate" ;;
        "92") echo "Issuer PK Remainder" ;;
        "94") echo "AFL" ;;
        "9F06") echo "AID" ;;
        "9F07") echo "Application Usage Control" ;;
        "9F08") echo "App Version Number" ;;
        "9F0D") echo "IAC Default" ;;
        "9F0E") echo "IAC Denial" ;;
        "9F0F") echo "IAC Online" ;;
        "9F10") echo "Issuer Application Data" ;;
        "9F11") echo "Issuer Code Table Index" ;;
        "9F12") echo "Application Preferred Name" ;;
        "9F1F") echo "Track 1 Discretionary Data" ;;
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
        "9F49") echo "DDOL" ;;
        "9F4A") echo "SDA Tag List" ;;
        "9F4B") echo "Signed Dynamic Application Data" ;;
        "9F62") echo "PCVC3 Track1" ;;
        "9F63") echo "PUNATC Track1" ;;
        "9F64") echo "NATC Track1" ;;
        "9F65") echo "PCVC3 Track2" ;;
        "9F66") echo "TTQ" ;;
        "9F67") echo "MSD Offset" ;;
        "9F6B") echo "Track 2 Data" ;;
        "9F6C") echo "Card Transaction Qualifiers" ;;
        "9F6E") echo "Third Party Data" ;;
        "A5") echo "FCI Proprietary Template" ;;
        "6F") echo "FCI Template" ;;
        "61") echo "Directory Entry" ;;
        "70") echo "EMV Record Template" ;;
        "77") echo "Response Message Template Format 2" ;;
        "BF0C") echo "FCI Issuer Discretionary Data" ;;
        *) echo "" ;;
    esac
}

# Parse gp.jar output line to get data and SW
parse_response() {
    local line="$1"
    local hex_part=$(echo "$line" | sed 's/.*) //')
    echo "$hex_part" | tr -d ' '
}

# Extract a TLV tag value from hex data (recursive)
extract_tag() {
    local data="$1"
    local target_tag="$2"
    local pos=0
    local len=${#data}

    target_tag=$(echo "$target_tag" | tr '[:lower:]' '[:upper:]')

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

        tag=$(echo "$tag" | tr '[:lower:]' '[:upper:]')

        if [ "$tag" == "$target_tag" ]; then
            echo "$value"
            return 0
        fi

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

# Parse all TLVs from data and store in associative-array-like format
# Outputs: TAG:VALUE lines
parse_all_tlvs() {
    local data="$1"
    local prefix="$2"
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

        tag=$(echo "$tag" | tr '[:lower:]' '[:upper:]')

        # Output non-constructed tags
        if [[ "$tag" != "6F" && "$tag" != "A5" && "$tag" != "70" && "$tag" != "77" && "$tag" != "61" && "$tag" != "BF0C" ]]; then
            echo "${prefix}${tag}:${value}"
        fi

        # Recurse into constructed tags
        if [[ "$tag" == "6F" || "$tag" == "A5" || "$tag" == "70" || "$tag" == "77" || "$tag" == "61" || "$tag" == "BF0C" ]]; then
            parse_all_tlvs "$value" "$prefix"
        fi
    done
}

# Common AIDs to try as fallback
COMMON_AIDS=(
    "A0000000031010"    # Visa Credit/Debit
    "A0000000032010"    # Visa Electron
    "A0000000041010"    # Mastercard Credit/Debit
    "A0000000043060"    # Maestro
    "A0000000651010"    # JCB
    "A000000025010104"  # Amex
    "A0000009510001"    # COLOSSUS Contact
    "A0000009511010"    # COLOSSUS Contactless
)

# Extract PIX from AID (everything after the 10-char RID)
get_pix() {
    local aid="$1"
    # RID is first 10 hex chars (5 bytes), PIX is the rest
    echo "${aid:10}"
}

# Determine if AID is contact or contactless based on PIX
# PIX == 0001 -> contact, anything else -> contactless
is_contact_aid() {
    local aid="$1"
    local pix=$(get_pix "$aid")
    [ "$pix" == "0001" ]
}

# Try to find a working AID from common list
try_common_aids() {
    log "${YELLOW}Trying common AIDs...${NC}"

    local gp_args=""
    for aid in "${COMMON_AIDS[@]}"; do
        local aid_len=$(printf '%02X' $((${#aid} / 2)))
        gp_args+=" -a 00A40400${aid_len}${aid}00"
    done

    local output=$(java -jar "$GP_JAR" -d $gp_args 2>&1)
    read_lines_into_array responses < <(echo "$output" | grep "^A<<")

    for i in "${!responses[@]}"; do
        local resp_full=$(parse_response "${responses[$i]}")
        local resp_sw="${resp_full: -4}"
        if [ "$resp_sw" == "9000" ]; then
            echo "${COMMON_AIDS[$i]}"
            return 0
        fi
    done

    echo ""
    return 1
}

# Classify an AID as contact or contactless based on PIX
# PIX == 0001 -> contact, anything else -> contactless
classify_aid() {
    local aid="$1"
    local pix=$(get_pix "$aid")

    if [ "$pix" == "0001" ]; then
        if [ -z "$CONTACT_AID" ]; then
            CONTACT_AID="$aid"
            log "  Contact AID (PIX=0001): $aid"
        fi
    else
        if [ -z "$CONTACTLESS_AID" ]; then
            CONTACTLESS_AID="$aid"
            log "  Contactless AID (PIX=$pix): $aid"
        fi
    fi
}

# Discover AIDs from both PSE and PPSE in a single session
discover_aids() {
    log "${CYAN}Discovering applications (PSE + PPSE)...${NC}"

    # PSE: 1PAY.SYS.DDF01, PPSE: 2PAY.SYS.DDF01
    local pse_aid="315041592E5359532E4444463031"
    local ppse_aid="325041592E5359532E4444463031"

    # Send both SELECTs and READ RECORDs in one session
    local output=$(java -jar "$GP_JAR" -d \
        -a "00A404000E${pse_aid}00" \
        -a "00B2010C00" \
        -a "00A404000E${ppse_aid}00" \
        -a "00B2010C00" \
        2>&1)

    read_lines_into_array responses < <(echo "$output" | grep "^A<<")

    CONTACT_AID=""
    CONTACTLESS_AID=""

    # Parse PSE SELECT response (index 0)
    if [ ${#responses[@]} -ge 1 ]; then
        local pse_full=$(parse_response "${responses[0]}")
        local pse_sw="${pse_full: -4}"
        local pse_data="${pse_full:0:${#pse_full}-4}"

        if [ "$pse_sw" == "9000" ]; then
            log "${GREEN}PSE available${NC}"
            # Parse PSE READ RECORD (index 1)
            if [ ${#responses[@]} -ge 2 ]; then
                local rec_full=$(parse_response "${responses[1]}")
                local rec_sw="${rec_full: -4}"
                local rec_data="${rec_full:0:${#rec_full}-4}"
                if [ "$rec_sw" == "9000" ]; then
                    local found_aid=$(extract_tag "$rec_data" "4F")
                    if [ -n "$found_aid" ]; then
                        classify_aid "$found_aid"
                    fi
                fi
            fi
        else
            log "${YELLOW}PSE not available (SW=$pse_sw)${NC}"
        fi
    fi

    # Parse PPSE SELECT response (index 2)
    if [ ${#responses[@]} -ge 3 ]; then
        local ppse_full=$(parse_response "${responses[2]}")
        local ppse_sw="${ppse_full: -4}"
        local ppse_data="${ppse_full:0:${#ppse_full}-4}"

        if [ "$ppse_sw" == "9000" ]; then
            log "${GREEN}PPSE available${NC}"
            # For PPSE, AID is in FCI (BF0C/61/4F)
            local found_aid=$(extract_tag "$ppse_data" "4F")
            if [ -n "$found_aid" ]; then
                classify_aid "$found_aid"
            fi
        else
            log "${YELLOW}PPSE not available (SW=$ppse_sw)${NC}"
        fi
    fi

    # Fallback: try common AIDs if no AID found
    if [ -z "$CONTACT_AID" ] && [ -z "$CONTACTLESS_AID" ]; then
        log ""
        local fallback_aid=$(try_common_aids)
        if [ -n "$fallback_aid" ]; then
            log "${GREEN}Found working AID: $fallback_aid${NC}"
            classify_aid "$fallback_aid"
        fi
    fi
}

# Read full application profile
# Outputs YAML for the application
read_application() {
    local aid="$1"
    local mode="$2"  # "contact" or "contactless"
    local indent="$3"

    local aid_len=$(printf '%02X' $((${#aid} / 2)))

    log "${CYAN}Reading application $aid ($mode)...${NC}"

    # Build GPO command - empty PDOL
    local gpo_cmd="80A8000002830000"

    # Build READ RECORD commands for SFI 1-4, records 1-10
    declare -a read_commands=()
    declare -a record_ids=()

    for sfi in 1 2 3 4; do
        local p2=$(printf '%02X' $(((sfi << 3) | 4)))
        for rec in 1 2 3 4 5 6 7 8 9 10; do
            local rec_hex=$(printf '%02X' $rec)
            read_commands+=("00B2${rec_hex}${p2}00")
            record_ids+=("SFI${sfi}_REC${rec}")
        done
    done

    # Build all commands
    local gp_args="-a 00A40400${aid_len}${aid}00"
    gp_args+=" -a $gpo_cmd"
    for cmd in "${read_commands[@]}"; do
        gp_args+=" -a $cmd"
    done

    local output=$(java -jar "$GP_JAR" -d $gp_args 2>&1)
    read_lines_into_array responses < <(echo "$output" | grep "^A<<")

    if [ ${#responses[@]} -lt 2 ]; then
        log "${RED}No response from card for AID $aid${NC}"
        return 1
    fi

    # Parse SELECT response
    local select_full=$(parse_response "${responses[0]}")
    local select_sw="${select_full: -4}"
    local select_data="${select_full:0:${#select_full}-4}"

    if [ "$select_sw" != "9000" ]; then
        log "${RED}Failed to select AID $aid (SW=$select_sw)${NC}"
        return 1
    fi

    log "${GREEN}Selected AID $aid${NC}"

    # Start YAML output for this application
    echo "${indent}aid: \"$aid\""
    echo "${indent}mode: \"$mode\""

    # FCI tags
    echo "${indent}fci:"
    local fci_tags=$(parse_all_tlvs "$select_data" "")
    echo "$fci_tags" | while IFS=: read -r tag value; do
        if [ -n "$tag" ] && [ -n "$value" ]; then
            local tag_name=$(get_tag_name "$tag")
            if [ -n "$tag_name" ]; then
                echo "${indent}  ${tag}:  # $tag_name"
            else
                echo "${indent}  ${tag}:"
            fi
            echo "${indent}    value: \"$value\""
        fi
    done

    # Parse GPO response
    local gpo_full=$(parse_response "${responses[1]}")
    local gpo_sw="${gpo_full: -4}"
    local gpo_data="${gpo_full:0:${#gpo_full}-4}"

    echo "${indent}gpo:"
    echo "${indent}  sw: \"$gpo_sw\""

    if [ "$gpo_sw" == "9000" ]; then
        local first_tag="${gpo_data:0:2}"
        if [ "$first_tag" == "80" ]; then
            # Format 1
            local len=$((16#${gpo_data:2:2}))
            local aip="${gpo_data:4:4}"
            local afl="${gpo_data:8:$((len*2-4))}"
            echo "${indent}  format: 1"
            echo "${indent}  82:  # AIP"
            echo "${indent}    value: \"$aip\""
            echo "${indent}  94:  # AFL"
            echo "${indent}    value: \"$afl\""
        elif [ "$first_tag" == "77" ]; then
            # Format 2
            echo "${indent}  format: 2"
            local gpo_tags=$(parse_all_tlvs "$gpo_data" "")
            echo "$gpo_tags" | while IFS=: read -r tag value; do
                if [ -n "$tag" ] && [ -n "$value" ]; then
                    local tag_name=$(get_tag_name "$tag")
                    if [ -n "$tag_name" ]; then
                        echo "${indent}  ${tag}:  # $tag_name"
                    else
                        echo "${indent}  ${tag}:"
                    fi
                    echo "${indent}    value: \"$value\""
                fi
            done
        fi
    fi

    # Parse records
    echo "${indent}records:"

    for i in "${!read_commands[@]}"; do
        local resp_idx=$((i + 2))
        local record_id="${record_ids[$i]}"

        if [ $resp_idx -lt ${#responses[@]} ]; then
            local resp_full=$(parse_response "${responses[$resp_idx]}")
            local sw="${resp_full: -4}"
            local data="${resp_full:0:${#resp_full}-4}"

            if [ "$sw" == "9000" ]; then
                echo "${indent}  ${record_id}:"

                # Skip 70 template header if present
                local inner="$data"
                if [[ "$data" == 70* ]]; then
                    local len_byte="${data:2:2}"
                    if [ "$len_byte" == "81" ]; then
                        inner="${data:6}"
                    elif [ "$len_byte" == "82" ]; then
                        inner="${data:8}"
                    else
                        inner="${data:4}"
                    fi
                fi

                # Parse and output tags
                local record_tags=$(parse_all_tlvs "$inner" "")
                echo "$record_tags" | while IFS=: read -r tag value; do
                    if [ -n "$tag" ] && [ -n "$value" ]; then
                        local tag_name=$(get_tag_name "$tag")
                        if [ -n "$tag_name" ]; then
                            echo "${indent}    ${tag}:  # $tag_name"
                        else
                            echo "${indent}    ${tag}:"
                        fi
                        echo "${indent}      value: \"$value\""
                    fi
                done
            fi
        fi
    done

    log "${GREEN}Finished reading $aid${NC}"
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        -o|--output)
            OUTPUT_FILE="$2"
            shift 2
            ;;
        --contact-only)
            CONTACT_ONLY=true
            shift
            ;;
        --contactless-only)
            CONTACTLESS_ONLY=true
            shift
            ;;
        -h|--help)
            show_help
            ;;
        *)
            log "${RED}Unknown option: $1${NC}"
            show_help
            ;;
    esac
done

# Check for gp.jar
if [ ! -f "$GP_JAR" ]; then
    log "${RED}gp.jar not found at $GP_JAR${NC}"
    exit 1
fi

log "=========================================="
log "   EMV Card Profile Cloner"
log "=========================================="
log ""

# Phase 1: Discover all AIDs in one session
CONTACT_AID=""
CONTACTLESS_AID=""
discover_aids

if [ -z "$CONTACT_AID" ] && [ -z "$CONTACTLESS_AID" ]; then
    log "${RED}No applications found on card${NC}"
    exit 1
fi

# Collect YAML output
yaml_output=""

# Add header
yaml_output+="# EMV Card Profile"$'\n'
yaml_output+="# Generated: $(date -u +"%Y-%m-%dT%H:%M:%SZ")"$'\n'
yaml_output+="# Tool: clone-profile.sh"$'\n'
yaml_output+=$'\n'

# Phase 2: Read each application (separate sessions)

# Read contact application
if [ -n "$CONTACT_AID" ] && ! $CONTACTLESS_ONLY; then
    log ""
    log "${YELLOW}Remove and re-insert card to read contact application, then press Enter...${NC}"
    read -r

    yaml_output+="contact:"$'\n'
    app_yaml=$(read_application "$CONTACT_AID" "contact" "  ")
    yaml_output+="$app_yaml"$'\n'
fi

# Read contactless application
if [ -n "$CONTACTLESS_AID" ] && ! $CONTACT_ONLY; then
    # Only prompt if we also read contact
    if [ -n "$CONTACT_AID" ] && ! $CONTACTLESS_ONLY; then
        log ""
        log "${YELLOW}Remove and re-insert card to read contactless application, then press Enter...${NC}"
        read -r
    else
        log ""
        log "${YELLOW}Ensure card is inserted, then press Enter...${NC}"
        read -r
    fi

    yaml_output+=$'\n'"contactless:"$'\n'
    app_yaml=$(read_application "$CONTACTLESS_AID" "contactless" "  ")
    yaml_output+="$app_yaml"$'\n'
fi

# Output YAML
if [ -n "$OUTPUT_FILE" ]; then
    echo -e "$yaml_output" > "$OUTPUT_FILE"
    log ""
    log "${GREEN}Profile saved to: $OUTPUT_FILE${NC}"
else
    echo ""
    echo -e "$yaml_output"
fi

log ""
log "=========================================="
log "   Profile Clone Complete"
log "=========================================="
