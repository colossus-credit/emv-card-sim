#!/bin/bash
# Read all APDU logs from the smartcard and format them nicely

GP_JAR="./gp.jar"
APPLET_AID="A0000009510001"

echo "========================================="
echo "Reading APDU Logs from Smartcard"
echo "Applet: $APPLET_AID"
echo "========================================="
echo ""

counter=0

while true; do
    # Read one log entry
    output=$(java -jar "$GP_JAR" --applet "$APPLET_AID" --apdu 80060000 2>&1)

    # Extract the hex response (line before the status word)
    log_data=$(echo "$output" | grep -v "^#" | grep -v "^A>>" | grep -v "^A<<" | grep -v "Warning" | grep -v "^$" | tail -1)

    # Check if response contains error (6A83 = no more records)
    if echo "$output" | grep -q "6A83"; then
        echo ""
        echo "--- No more log entries (6A83) ---"
        break
    fi

    # Check if we got valid data
    if [ -n "$log_data" ] && [ "$log_data" != "9000" ]; then
        counter=$((counter + 1))

        # Parse the APDU to make it more readable
        cla="${log_data:0:2}"
        ins="${log_data:2:2}"
        p1="${log_data:4:2}"
        p2="${log_data:6:2}"
        lc="${log_data:8:2}"

        # Determine command name
        cmd_name="UNKNOWN"
        case "$ins" in
            "A4") cmd_name="SELECT" ;;
            "B2") cmd_name="READ RECORD" ;;
            "A8") cmd_name="GET PROCESSING OPTIONS" ;;
            "AE") cmd_name="GENERATE AC" ;;
            "88") cmd_name="INTERNAL AUTHENTICATE (DDA)" ;;
            "CA") cmd_name="GET DATA" ;;
            "84") cmd_name="GET CHALLENGE" ;;
            "20") cmd_name="VERIFY PIN" ;;
            "82") cmd_name="EXTERNAL AUTHENTICATE" ;;
            "C0") cmd_name="GET RESPONSE" ;;
        esac

        printf "#%-3d  %s  [CLA=%s INS=%s P1=%s P2=%s Lc=%s]  %s\n" \
            "$counter" "$log_data" "$cla" "$ins" "$p1" "$p2" "$lc" "$cmd_name"
    else
        # Likely reached end or error
        break
    fi
done

echo ""
echo "========================================="
echo "Total APDU log entries: $counter"
echo "========================================="
