#!/bin/bash
# Capture and decode full EMV transaction logs from smartcard
# Run this immediately after completing a transaction

GP_JAR="./gp.jar"
CONTACT_AID="A0000009510001"
CONTACTLESS_AID="A0000009511010"

decode_cmd() {
    local log_data="$1"
    local log_upper=$(echo "$log_data" | tr 'a-f' 'A-F')

    local cla=$(echo "$log_data" | cut -c1-2 | tr 'a-f' 'A-F')
    local ins=$(echo "$log_data" | cut -c3-4 | tr 'a-f' 'A-F')
    local p1=$(echo "$log_data" | cut -c5-6 | tr 'a-f' 'A-F')
    local p2=$(echo "$log_data" | cut -c7-8 | tr 'a-f' 'A-F')

    local cmd_name=""
    case "$ins" in
        "A4")
            if [ "$p1" == "04" ]; then
                cmd_name="SELECT (by name)"
            else
                cmd_name="SELECT"
            fi
            ;;
        "B2")
            local rec=$((16#$p1))
            local sfi=$((16#$p2 >> 3))
            cmd_name="READ RECORD (rec=$rec, SFI=$sfi)"
            ;;
        "A8") cmd_name="GET PROCESSING OPTIONS (GPO)" ;;
        "AE")
            if [ "$p1" == "80" ]; then
                cmd_name="GENERATE AC (TC)"
            elif [ "$p1" == "40" ]; then
                cmd_name="GENERATE AC (ARQC)"
            else
                cmd_name="GENERATE AC"
            fi
            ;;
        "88") cmd_name="INTERNAL AUTHENTICATE (DDA)" ;;
        "CA") cmd_name="GET DATA (tag $p1$p2)" ;;
        "84") cmd_name="GET CHALLENGE" ;;
        "C0") cmd_name="GET RESPONSE" ;;
        *) cmd_name="CLA=$cla INS=$ins" ;;
    esac

    echo "$log_upper"
    echo "    → $cmd_name"
}

read_applet_logs() {
    local aid="$1"
    local name="$2"
    local counter=0

    echo ""
    echo "========================================="
    echo "$name Logs (AID: $aid)"
    echo "========================================="

    while [ $counter -lt 50 ]; do
        output=$(java -jar "$GP_JAR" --applet "$aid" --apdu 80060000 2>&1)
        log_data=$(echo "$output" | grep -v "^#" | grep -v "^A>>" | grep -v "^A<<" | grep -v "Warning" | grep -v "^$" | tail -1)

        if echo "$output" | grep -q "6A83"; then
            break
        fi

        if [ -n "$log_data" ] && [ "$log_data" != "9000" ]; then
            counter=$((counter + 1))
            printf "\n#%-2d  " "$counter"
            decode_cmd "$log_data"
        else
            break
        fi
    done

    if [ $counter -eq 0 ]; then
        echo "(No commands logged)"
    else
        echo ""
        echo "Total: $counter commands"
    fi
}

echo ""
echo "╔════════════════════════════════════════╗"
echo "║   EMV Transaction Log Capture          ║"
echo "╚════════════════════════════════════════╝"

# Read from both applets
read_applet_logs "$CONTACTLESS_AID" "CONTACTLESS"
read_applet_logs "$CONTACT_AID" "CONTACT"

echo ""
echo "========================================="
echo "Capture complete"
echo "========================================="
