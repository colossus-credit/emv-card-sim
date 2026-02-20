#!/bin/bash
# Read and decode APDU logs from the smartcard

GP_JAR="./gp.jar"
APPLET_AID="A0000009510001"

echo "========================================="
echo "APDU Logs from Smartcard"
echo "========================================="
echo ""

counter=0

while true; do
    output=$(java -jar "$GP_JAR" --applet "$APPLET_AID" --apdu 80060000 2>&1)
    log_data=$(echo "$output" | grep -v "^#" | grep -v "^A>>" | grep -v "^A<<" | grep -v "Warning" | grep -v "^$" | tail -1)

    if echo "$output" | grep -q "6A83"; then
        break
    fi

    if [ -n "$log_data" ] && [ "$log_data" != "9000" ]; then
        counter=$((counter + 1))

        # Parse APDU
        cla=$(echo "$log_data" | cut -c1-2 | tr 'a-f' 'A-F')
        ins=$(echo "$log_data" | cut -c3-4 | tr 'a-f' 'A-F')
        p1=$(echo "$log_data" | cut -c5-6 | tr 'a-f' 'A-F')
        p2=$(echo "$log_data" | cut -c7-8 | tr 'a-f' 'A-F')
        lc=$(echo "$log_data" | cut -c9-10 | tr 'a-f' 'A-F')

        # Decode command
        cmd_desc=""
        case "$ins" in
            "A4") cmd_desc="SELECT" ;;
            "B2")
                # Decode READ RECORD: P1=record number, P2 bits 1-3 = SFI
                record_num=$((16#$p1))
                sfi=$((16#$p2 >> 3))
                cmd_desc="READ RECORD (Rec=$record_num, SFI=$sfi)"
                ;;
            "A8") cmd_desc="GET PROCESSING OPTIONS" ;;
            "AE") cmd_desc="GENERATE AC" ;;
            "88")
                # Decode DDA
                data_len=$((16#$lc))
                cmd_desc="INTERNAL AUTHENTICATE (DDA, Lc=$data_len bytes)"
                ;;
            "CA") cmd_desc="GET DATA" ;;
            "84") cmd_desc="GET CHALLENGE" ;;
            "20") cmd_desc="VERIFY PIN" ;;
            "82") cmd_desc="EXTERNAL AUTHENTICATE" ;;
            "C0") cmd_desc="GET RESPONSE" ;;
            *) cmd_desc="INS=$ins" ;;
        esac

        # Format output
        log_upper=$(echo "$log_data" | tr 'a-f' 'A-F')
        printf "#%-2d  %s\n     %s\n\n" "$counter" "$log_upper" "$cmd_desc"
    else
        break
    fi
done

echo "========================================="
echo "Total: $counter APDU commands logged"
echo "========================================="
