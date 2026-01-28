#!/bin/bash
# Read APDU logs from the contactless applet after a terminal transaction
# This helps diagnose what commands the terminal actually sent

echo "Reading APDU logs from contactless applet (A0000009511010)..."
echo ""

# Select contactless applet and read all logs
java -jar gp.jar -d \
    -a 00A4040007A0000009511010 \
    -a 8006000000 \
    -a 8006000000 \
    -a 8006000000 \
    -a 8006000000 \
    -a 8006000000 \
    -a 8006000000 \
    -a 8006000000 \
    -a 8006000000 \
    -a 8006000000 \
    -a 8006000000 \
    -a 8006000000 \
    -a 8006000000 \
    -a 8006000000 \
    -a 8006000000 \
    -a 8006000000 \
    -a 8006000000 \
    -a 8006000000 \
    -a 8006000000 \
    -a 8006000000 \
    -a 8006000000 2>&1 | grep -E "(A>>|A<<)" | while read line; do

    # Check for log response (not 6A83 record not found)
    if [[ "$line" == *"9000"* ]] && [[ "$line" == *"A<<"* ]] && [[ "$line" != *"6F"* ]]; then
        # Extract hex data after A<< and before 9000
        hex=$(echo "$line" | sed 's/.*A<< (\([0-9]*\)+2).*) //' | sed 's/ 9000$//')
        if [[ -n "$hex" ]] && [[ "$hex" != "6A83" ]]; then
            echo "APDU Log: $hex"
            # Decode common commands
            case "${hex:0:4}" in
                00A4) echo "  -> SELECT" ;;
                80A8) echo "  -> GET PROCESSING OPTIONS" ;;
                00B2) echo "  -> READ RECORD P1=${hex:4:2} P2=${hex:6:2}" ;;
                80AE) echo "  -> GENERATE AC" ;;
                80CA) echo "  -> GET DATA" ;;
                0020) echo "  -> VERIFY" ;;
                *)    echo "  -> Unknown" ;;
            esac
            echo ""
        fi
    fi
done

echo ""
echo "To compare, here's what gp.jar reads for SFI 1 Record 2:"
java -jar gp.jar -a 00A4040007A0000009511010 -a 00B2020C00 2>&1 | grep -E "A<<.*70"
