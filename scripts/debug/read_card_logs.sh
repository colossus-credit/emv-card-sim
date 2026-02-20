#!/bin/bash
# Read APDU logs stored on the smartcard
# Uses GlobalPlatformPro (gp.jar) to communicate with the card

set -e

GP_JAR="./gp.jar"
APPLET_AID="A0000009510001"

echo "========================================="
echo "Reading APDU Logs from Smartcard"
echo "========================================="
echo ""

# Check if gp.jar exists
if [ ! -f "$GP_JAR" ]; then
    echo "Error: gp.jar not found in current directory"
    exit 1
fi

# Counter for log entries
counter=0

echo "Retrieving log entries (reading until no more logs)..."
echo ""

while true; do
    # Send command 80 06 00 00 to read next log entry
    # This is a destructive read - it removes the log entry after reading
    response=$(java -jar "$GP_JAR" --applet "$APPLET_AID" --apdu 80060000 2>&1 || true)

    # Check if we got "6A83" (record not found - no more logs)
    if echo "$response" | grep -q "6A83"; then
        echo "No more log entries (6A83 - Record Not Found)"
        break
    fi

    # Check if we got "9000" (success)
    if echo "$response" | grep -q "9000"; then
        counter=$((counter + 1))
        echo "--- Log Entry #$counter ---"
        echo "$response" | grep -A 2 "A>> "
        echo ""
    else
        echo "Error reading log entry:"
        echo "$response"
        break
    fi
done

echo ""
echo "========================================="
echo "Total log entries retrieved: $counter"
echo "========================================="
