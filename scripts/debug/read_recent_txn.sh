#!/bin/bash
# Read recent transaction logs

GP_JAR="./gp.jar"
APPLET_AID="A0000009510001"

echo "========================================="
echo "Recent Transaction APDU Logs"
echo "========================================="
echo ""

counter=0

while [ $counter -lt 50 ]; do
    output=$(java -jar "$GP_JAR" --applet "$APPLET_AID" --apdu 80060000 2>&1)
    log_data=$(echo "$output" | grep -v "^#" | grep -v "^A>>" | grep -v "^A<<" | grep -v "Warning" | grep -v "^$" | tail -1)

    if echo "$output" | grep -q "6A83"; then
        break
    fi

    if [ -n "$log_data" ] && [ "$log_data" != "9000" ]; then
        counter=$((counter + 1))
        log_upper=$(echo "$log_data" | tr 'a-f' 'A-F')

        # Parse
        cla=$(echo "$log_data" | cut -c1-2 | tr 'a-f' 'A-F')
        ins=$(echo "$log_data" | cut -c3-4 | tr 'a-f' 'A-F')

        # Decode
        case "$ins" in
            "A4") cmd="SELECT AID" ;;
            "B2") cmd="READ RECORD" ;;
            "A8") cmd="GET PROCESSING OPTIONS" ;;
            "AE") cmd="GENERATE AC" ;;
            "88") cmd="INTERNAL AUTHENTICATE (DDA)" ;;
            "CA") cmd="GET DATA" ;;
            *) cmd="INS=$ins" ;;
        esac

        printf "%3d. %s  (%s)\n" "$counter" "$log_upper" "$cmd"
    else
        break
    fi
done

echo ""
echo "Total: $counter commands"
