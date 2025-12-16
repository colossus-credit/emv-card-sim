#!/bin/bash

# Program Card from YAML Configuration
# Reads colossus_card_setup_apdus.yaml and sends APDUs via gp.jar
#
# Usage:
#   ./program-card-from-yaml.sh [yaml_file] [applet_aid]
#
# Arguments:
#   yaml_file   - Path to YAML configuration (default: src/test/java/config/colossus_card_setup_apdus.yaml)
#   applet_aid  - Applet AID (default: AFFFFFFFFF1234)
#
# Examples:
#   ./program-card-from-yaml.sh
#   ./program-card-from-yaml.sh ./my_config.yaml
#   ./program-card-from-yaml.sh ./my_config.yaml A0000000951
#
# Requirements:
#   - JavaCard with deployed paymentapp.cap
#   - gp.jar (GlobalPlatformPro tool)
#   - Card reader connected
#   - yq or python3 for YAML parsing

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
NC='\033[0m'

print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_header() {
    echo -e "${CYAN}$1${NC}"
}

print_step() {
    echo -e "${MAGENTA}[STEP]${NC} $1"
}

# Show help
if [ "$1" = "-h" ] || [ "$1" = "--help" ]; then
    echo "Program Card from YAML Configuration"
    echo ""
    echo "Usage:"
    echo "  ./program-card-from-yaml.sh [yaml_file] [applet_aid]"
    echo ""
    echo "Arguments:"
    echo "  yaml_file   - YAML config file (default: src/test/java/config/colossus_card_setup_apdus.yaml)"
    echo "  applet_aid  - Applet AID (default: AFFFFFFFFF1234)"
    echo ""
    echo "Examples:"
    echo "  ./program-card-from-yaml.sh"
    echo "  ./program-card-from-yaml.sh ./my_config.yaml"
    echo "  ./program-card-from-yaml.sh ./my_config.yaml A0000000951"
    echo ""
    echo "Requirements:"
    echo "  - Card reader with JavaCard"
    echo "  - gp.jar in current directory"
    echo "  - Python 3 (for YAML parsing)"
    echo ""
    exit 0
fi

# Parse arguments
YAML_FILE="${1:-src/test/java/config/colossus_card_setup_apdus.yaml}"
APPLET_AID="${2:-AFFFFFFFFF1234}"

# Validate files
if [ ! -f "$YAML_FILE" ]; then
    print_error "YAML file not found: $YAML_FILE"
    exit 1
fi

if [ ! -f "gp.jar" ]; then
    print_error "gp.jar not found in current directory"
    print_info "Download from: https://github.com/martinpaljak/GlobalPlatformPro"
    exit 1
fi

# Check for Python
if ! command -v python3 &> /dev/null; then
    print_error "Python 3 not found. Required for YAML parsing."
    exit 1
fi

# Show banner
echo ""
print_header "═══════════════════════════════════════════════════════════"
print_header "  Colossus Card Programming from YAML"
print_header "═══════════════════════════════════════════════════════════"
echo ""

print_info "Configuration:"
echo "  YAML File:  $YAML_FILE"
echo "  Applet AID: $APPLET_AID"
echo ""

# Count total commands
TOTAL_COMMANDS=$(grep -c "^- req:" "$YAML_FILE" || echo "0")
print_info "Total APDUs to send: $TOTAL_COMMANDS"
echo ""

# Confirm with user
print_warning "This will program your JavaCard with the Colossus configuration"
read -p "Continue? (y/N): " confirm
if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
    print_info "Aborted by user"
    exit 0
fi

echo ""
print_header "─────────────────────────────────────────────────────────"
print_header "  Starting Card Programming"
print_header "─────────────────────────────────────────────────────────"
echo ""

# Function to send APDU via gp.jar (with automatic chaining for long APDUs)
send_apdu() {
    local description="$1"
    local apdu="$2"
    
    # Clean up APDU (remove all spaces and quotes - gp.jar expects continuous hex string)
    apdu_clean=$(echo "$apdu" | tr -d "' \n")
    
    # Fix malformed APDUs by recalculating Lc field
    # Extract header (8 chars = 4 bytes: CLA INS P1 P2)
    local header="${apdu_clean:0:8}"
    # Extract Lc (2 chars = 1 byte at position 8-9)
    local lc="${apdu_clean:8:2}"
    # Extract data (everything after position 10)
    local data="${apdu_clean:10}"
    local actual_data_len=$((${#data} / 2))
    local declared_lc=$((16#$lc))
    
    # If Lc doesn't match actual data length, fix it
    if [ $declared_lc -ne $actual_data_len ] && [ "$lc" != "FF" ]; then
        local correct_lc=$(printf "%02X" $actual_data_len)
        apdu_clean="${header}${correct_lc}${data}"
    fi
    
    # Check if this is a long APDU that needs chaining (Lc=FF means extended length)
    # Format: CCIIIPP1PP2FF<data> where FF at position 8-9 indicates extended length
    if [ "${apdu_clean:8:2}" = "FF" ]; then
        # Extract parts: CLA INS P1 P2 are first 8 chars (4 bytes)
        local header="${apdu_clean:0:8}"
        # Skip the FF and next 2 bytes (extended length indicator), get rest as data
        local data="${apdu_clean:12}"
        local data_len=$((${#data} / 2))
        
        echo -ne "  ${description}... "
        
        # Split into chunks of 128 bytes (256 hex chars)
        local chunk_size=256  # hex chars (128 bytes)
        local chunk_num=1
        local offset=0
        
        while [ $offset -lt ${#data} ]; do
            local chunk="${data:offset:chunk_size}"
            local chunk_bytes=$((${#chunk} / 2))
            local chunk_len=$(printf "%02X" $chunk_bytes)
            
            # Use chaining CLA (0x90) for all chunks except the last
            local remaining=$((${#data} - offset - ${#chunk}))
            if [ $remaining -gt 0 ]; then
                # More chunks to come - use chaining CLA
                local cla="9${header:1:1}"
                local chunk_apdu="${cla}${header:2:6}${chunk_len}${chunk}"
            else
                # Last chunk - use original CLA
                local chunk_apdu="${header}${chunk_len}${chunk}"
            fi
            
            # Send this chunk
            if output=$(java -jar gp.jar --applet "$APPLET_AID" --apdu "$chunk_apdu" -d 2>&1); then
                last_response=$(echo "$output" | grep "A<<" | tail -1)
                if ! echo "$last_response" | grep -qE "(9000|90 00)"; then
                    echo -e "${RED}✗${NC}"
                    print_error "Chunk $chunk_num failed:"
                    echo "$output" | grep -E "A>>|A<<" | tail -5
                    return 1
                fi
            else
                echo -e "${RED}✗${NC}"
                print_error "Failed to send chunk $chunk_num"
                echo "$output" | tail -5
                return 1
            fi
            
            offset=$((offset + chunk_size))
            chunk_num=$((chunk_num + 1))
        done
        
        echo -e "${GREEN}✓${NC} ($((chunk_num - 1)) chunks)"
        return 0
    else
        # Normal APDU - send as-is
        echo -ne "  ${description}... "
        
        if output=$(java -jar gp.jar --applet "$APPLET_AID" --apdu "$apdu_clean" -d 2>&1); then
            last_response=$(echo "$output" | grep "A<<" | tail -1)
            if echo "$last_response" | grep -qE "(9000|90 00)"; then
                echo -e "${GREEN}✓${NC}"
                return 0
            else
                echo -e "${RED}✗${NC}"
                print_error "Unexpected response:"
                echo "$output" | grep -E "A>>|A<<" | tail -5
                return 1
            fi
        else
            echo -e "${RED}✗${NC}"
            print_error "Failed to send APDU"
            echo "$output" | tail -5
            return 1
        fi
    fi
}

# Parse YAML and send APDUs
COMMAND_NUM=0
FAILED=0

python3 - "$YAML_FILE" << 'EOF' | while IFS='	' read -r description apdu; do
import sys
import re

yaml_file = sys.argv[1]

with open(yaml_file, 'r') as f:
    lines = f.readlines()

for i, line in enumerate(lines):
    if "- req:" in line:
        # Find the main descriptive comment (first line that's not Function/Behavior/NOTE)
        comment = f"Command {i+1}"
        for j in range(i-1, max(0, i-10), -1):
            stripped = lines[j].strip()
            # Skip empty, section headers, function/behavior lines
            if not stripped or stripped.startswith('#═'):
                continue
            if stripped.startswith('# Function:') or stripped.startswith('# Behavior:'):
                continue
            if stripped.startswith('# NOTE:'):
                continue
            if stripped.startswith('#'):
                # This is the main comment
                comment = stripped.lstrip('# ').strip()
                # Clean up - take first part before any dashes
                if ' - ' in comment:
                    comment = comment.split(' - ')[0]
                break
        
        # Extract APDU
        match = re.search(r"'([^']+)'", line)
        if match:
            apdu = match.group(1)
            print(f"{comment}	{apdu}")
EOF
    
    COMMAND_NUM=$((COMMAND_NUM + 1))
    
    # Show progress
    progress=$((COMMAND_NUM * 100 / TOTAL_COMMANDS))
    
    # Use description or default
    if [ -z "$description" ] || [ "$description" = "APDU" ]; then
        description="Command $COMMAND_NUM"
    fi
    
    # Send APDU
    if ! send_apdu "$description" "$apdu"; then
        FAILED=$((FAILED + 1))
        print_warning "Failed: $description"
        
        # Ask if should continue
        if [ $FAILED -ge 3 ]; then
            print_error "Too many failures ($FAILED)"
            read -p "Continue anyway? (y/N): " cont
            if [[ ! "$cont" =~ ^[Yy]$ ]]; then
                exit 1
            fi
            FAILED=0
        fi
    fi
    
    # Show progress every 10 commands
    if [ $((COMMAND_NUM % 10)) -eq 0 ]; then
        print_info "Progress: $COMMAND_NUM/$TOTAL_COMMANDS ($progress%)"
    fi
done

echo ""
print_header "─────────────────────────────────────────────────────────"
print_header "  Programming Complete"
print_header "─────────────────────────────────────────────────────────"
echo ""

if [ $FAILED -eq 0 ]; then
    print_success "✓ All $COMMAND_NUM APDUs sent successfully!"
else
    print_warning "⚠ Completed with $FAILED failures"
fi

echo ""
print_info "Card programmed with Colossus configuration"
print_info "Configuration from: $YAML_FILE"
echo ""

print_header "─────────────────────────────────────────────────────────"
print_header "  Next Steps"
print_header "─────────────────────────────────────────────────────────"
echo ""

print_info "Your card is ready for transactions!"
echo ""
echo "  Test with:"
echo "    ./run-colossus-tests.sh"
echo ""
echo "  Card configuration:"
echo "    - AID: A0000000951"
echo "    - BIN: 67676767"
echo "    - PIN: 1234"
echo "    - CDA: Enabled (RSA-2048)"
echo "    - Auth: Forced online (ARQC only)"
echo ""

print_success "✓ Card programming complete!"
echo ""

