#!/bin/bash

# Visa Test Card Personalization Script
# Uses Visa BIN 4111111111111111 with new ICC certificate

set -e

APPLET_AID="A0000009510001"
PAN="4111111111111111"

RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m'

print_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
print_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
print_error() { echo -e "${RED}[ERROR]${NC} $1"; }

send_apdu() {
    local description="$1"
    local apdu="$2"
    print_info "$description"
    apdu_clean=$(echo "$apdu" | tr -d ' \n')
    output=$(java -jar gp.jar --applet "$APPLET_AID" --apdu "${apdu_clean}" -d 2>&1)
    response_sw=$(echo "$output" | grep "A<<" | tail -1 | grep -oE '[0-9A-F]{4}$')
    if [ "$response_sw" = "9000" ]; then
        print_success "✓ 9000"
    else
        print_error "✗ Got $response_sw"
        return 1
    fi
}

print_info "========================================"
print_info "Visa Test Card Personalization"
print_info "========================================"
print_info "PAN: $PAN (Visa BIN)"
print_info "AID: $APPLET_AID"
echo ""

# Step 1: Factory Reset
print_info "Step 1: Factory Reset"
send_apdu "Factory reset" "80 05 00 00 00"

# Step 2: Enable CDA
print_info "Step 2: Enable CDA Mode"
send_apdu "Enable CDA" "80 00 00 07 01 01"

# Step 3: Load new ICC RSA-1984 Keys (for Visa PAN)
print_info "Step 3: Loading ICC RSA-1984 Keys"

# New ICC modulus - chunk 1 (124 bytes)
send_apdu "RSA modulus chunk 1/2" \
"90 00 00 04 7C \
D0 E7 74 8E E9 17 8C 3C DB 1C 20 C9 DF A0 E3 8D \
25 7C 2A B2 50 77 D3 A4 AC ED 21 6D A7 A5 B3 F1 \
F1 09 DC A5 B3 F2 5C A0 2E 0D 5C DE 92 BC 69 76 \
7A 72 74 9A 1F 24 F7 41 C6 57 87 E8 A6 EF 9E F2 \
0D 2B 32 28 33 CC 68 19 55 62 55 24 01 70 C8 70 \
7D FE AE 84 E5 4D 4E A0 A4 71 EC 86 50 11 21 2E \
C9 5C CD B7 70 0F 34 BD 1D 85 F2 05 44 F3 77 5F \
86 71 CD 82 E7 7D A5 6E C4 25 8B 75"

# New ICC modulus - chunk 2 (124 bytes)
send_apdu "RSA modulus chunk 2/2" \
"80 00 00 04 7C \
78 E1 D3 68 5D DC 0D 0A 62 0B 12 BC F3 17 F0 80 \
59 1F 07 20 41 13 DF D1 08 0E 0C 12 3E 00 A6 0D \
7C C0 80 C2 1E F8 6E 12 22 C5 96 9C 75 57 C1 85 \
44 BC 60 8A E0 AB 19 51 CF 37 31 24 25 B4 16 4F \
EF 2E C2 72 BC B9 0B F0 B0 BA D7 31 07 E9 A9 CB \
91 F3 B4 AD D0 A9 78 CB A7 05 1A 34 D2 72 3F 3E \
AC BA 16 D9 CE 52 35 35 15 E3 0F 20 51 85 52 B0 \
63 1C 8C 93 7C 82 04 C3 91 4A FF 33"

# New ICC private exponent - chunk 1 (124 bytes)
send_apdu "RSA exponent chunk 1/2" \
"90 00 00 05 7C \
8B 44 F8 5F 46 0F B2 D3 3C BD 6B 31 3F C0 97 B3 \
6E 52 C7 21 8A FA 8D 18 73 48 C0 F3 C5 19 22 A1 \
4B 5B E8 6E 77 F6 E8 6A C9 5E 3D E9 B7 28 46 4E \
FC 4C 4D BC 14 C3 4F 81 2E E5 05 45 C4 9F BF 4C \
08 C7 76 C5 77 DD 9A BB 8E 41 8E 18 00 F5 DA F5 \
A9 54 74 58 98 DE 34 6B 18 4B F3 04 35 60 C0 C9 \
DB 93 33 CF A0 0A 23 28 BE 59 4C 03 83 4C FA 3F \
AE F6 89 01 EF A9 18 F4 82 C3 B2 4D"

# New ICC private exponent - chunk 2 (124 bytes)
send_apdu "RSA exponent chunk 2/2" \
"80 00 00 05 7C \
1B 13 2C 28 42 88 BD F9 E9 DD 0D A9 EB 91 67 9B \
53 98 80 97 9A 6C 5F A4 4F 18 34 F7 16 5E CC 18 \
7C 8D 02 AC 63 8B 9F 0D E1 3F AE BD F5 34 27 B4 \
6C C2 C3 9F 79 A4 23 9E 6F 8C FC 30 16 DD 3C 94 \
F8 37 93 0F D1 A9 D9 88 81 6D 64 50 58 30 CE 62 \
10 E5 DE 32 1D 0A 85 D9 D5 00 A6 E0 DB 9F 44 A6 \
45 E4 2D EC 81 5A 6A 28 A9 48 DB DB E1 90 A7 12 \
3F FB D7 FC 56 F4 69 22 81 AB F8 1B"

# Step 4: Load Certificate Chain (keep same issuer cert, update ICC cert)
print_info "Step 4: Loading Certificate Chain"
send_apdu "CA Public Key Index (8F)" "80 01 00 8F 01 92"
send_apdu "Issuer PK Exponent (9F32)" "80 01 9F 32 01 03"

# Same Issuer cert as before
send_apdu "Issuer PK Cert (90)" \
"80 01 00 90 F8 \
5B AF CA B3 C7 4C CE 9B 9B D5 55 60 07 00 4F E3 \
E4 6C F4 6B D3 33 47 B6 CF 38 C6 C5 5F C8 FD 4D \
B3 C8 E3 1B 57 D0 07 97 28 9E A5 4E 4D B6 D7 53 \
3E 40 FC EC 48 A5 33 9D 78 75 BE 25 73 99 48 C8 \
F5 9C E8 DD EB F0 EE AB 6F 08 DE 78 CD DB 8D DB \
A4 24 AB 5A 2D FF F6 B5 24 16 43 16 78 DD 88 85 \
D0 B5 84 62 EE 00 73 1D 98 25 4C 99 2D B3 EF B8 \
EF 20 0D 41 73 F0 88 F4 5A 16 3F 31 2A 6D FB 94 \
81 79 66 39 66 44 47 43 E7 7C B6 57 7E 17 9F 76 \
2A 97 5F CB C3 E2 9D 15 A1 12 0E 57 93 C1 0B 01 \
76 24 91 FA 61 1F E9 64 4F 9E 4E 0D B2 29 7E F9 \
54 CD D2 A8 13 99 CE 0B 98 E8 C7 F7 03 16 25 CE \
A7 DC A4 1F F8 A9 0D D3 77 2B 92 B0 19 DD D0 C9 \
52 61 B2 B6 B9 E0 92 9D E9 EF 80 7F F5 F6 62 3A \
9D 5A 56 C3 92 B8 E8 66 0F 19 C3 06 FF 03 7D 3B \
78 19 DF 68 02 95 36 03"

send_apdu "Issuer PK Remainder (92)" \
"80 01 00 92 24 \
41 8E E5 D4 DB 98 D5 E0 56 C1 21 C3 5A F3 60 A4 \
EE 57 89 FA 80 F3 21 B8 9B B6 5D E5 37 CF B0 8A \
29 1A 24 6B"

send_apdu "ICC PK Exponent (9F47)" "80 01 9F 47 01 03"

# NEW ICC cert for Visa PAN
send_apdu "ICC PK Cert (9F46)" \
"80 01 9F 46 F8 \
97 61 6A E3 74 07 76 BE C1 E8 6C F7 FB FC A5 40 \
BE B9 67 BD EE 8E BE BB CE E0 22 BB 40 1A 94 3C \
F4 4A 70 07 4D 62 C0 66 2F 3D D6 67 7E 6D 9C 2E \
0E BB BF 72 83 BF 20 D4 B1 C9 1C B0 C4 24 1C AC \
3D B4 85 6A 09 33 EB FE 72 60 17 4A 28 52 88 12 \
3B 27 9F B8 98 66 77 F0 DF FA 7B 05 FF C1 34 0F \
44 34 11 90 60 A2 E5 44 C3 B8 8D BE A9 A9 C2 86 \
B7 B2 E8 08 D3 99 A5 B3 5E 1C 65 D8 51 55 25 80 \
9D D2 AA 80 3E B3 C4 1F 07 C2 EB 64 23 47 CA 6E \
08 6B 1F 51 B5 01 96 29 4A 2D 98 73 03 E1 95 E4 \
A7 20 53 BA 7F 96 82 29 48 23 75 8D 56 70 5C 91 \
E6 54 F7 DC 70 51 41 60 D2 58 F6 7D F9 42 94 20 \
DD 02 0C 2C DB EF EC C7 66 87 DC 47 30 53 45 F3 \
D7 D7 C9 59 FB 65 D4 89 5C EE 51 19 5D 42 B3 33 \
34 E5 63 4B F2 75 13 E3 67 57 7B 22 D1 16 66 B5 \
29 EA 65 06 D0 9D 75 AC"

# NEW ICC remainder for Visa PAN
send_apdu "ICC PK Remainder (9F48)" \
"80 01 9F 48 2A \
B4 AD D0 A9 78 CB A7 05 1A 34 D2 72 3F 3E AC BA \
16 D9 CE 52 35 35 15 E3 0F 20 51 85 52 B0 63 1C \
8C 93 7C 82 04 C3 91 4A FF 33"

# Step 5: Configure Settings
print_info "Step 5: Configure Settings"
send_apdu "Set PIN code" "80 00 00 01 02 12 34"
send_apdu "Use response template 77" "80 00 00 02 02 00 77"

# Step 6: Setup Templates
print_info "Step 6: Setup Response Templates"
send_apdu "Template 1: GPO response" "80 02 00 01 04 00 82 00 94"
send_apdu "Template 2: DDA response" "80 02 00 02 02 9F 4B"
send_apdu "Template 3: GENERATE AC (CDA enabled)" "80 02 00 03 0A 9F 27 9F 36 9F 26 9F 10 9F 4B"
send_apdu "Template 5: A5 FCI Proprietary" "80 02 00 05 04 00 50 00 87"
send_apdu "Template 4: 6F FCI Template" "80 02 00 04 04 00 84 00 A5"

# Step 6b: READ RECORD Templates
print_info "Step 6b: Setup READ RECORD Templates"
send_apdu "Record SFI1 Rec2: Card data" "80 03 02 0C 0C 00 5A 5F 24 5F 34 00 57 5F 20 9F 08"
send_apdu "Record SFI2 Rec1: CDOL data" "80 03 01 14 08 00 8C 00 8D 9F 10 9F 36"
send_apdu "Record SFI2 Rec2: Additional data" "80 03 02 14 04 00 82 00 94"
send_apdu "Record SFI3 Rec1: CAPK/Exp/9F4A" "80 03 01 1C 06 00 8F 9F 32 9F 4A"
send_apdu "Record SFI3 Rec2: Issuer cert" "80 03 02 1C 02 00 90"
send_apdu "Record SFI3 Rec3: Issuer rem" "80 03 03 1C 02 00 92"
send_apdu "Record SFI3 Rec4: ICC cert" "80 03 04 1C 02 9F 46"
send_apdu "Record SFI3 Rec5: ICC exp/rem" "80 03 05 1C 04 9F 47 9F 48"

# Step 7: Setup Card Data
print_info "Step 7: Setup Card Data"
send_apdu "ATC (counter)" "80 01 9F 36 02 00 01"
send_apdu "AID (A0000009510001)" "80 01 00 84 07 A0 00 00 09 51 00 01"
send_apdu "PAN (4111111111111111)" "80 01 00 5A 08 41 11 11 11 11 11 11 11"
send_apdu "Expiry date" "80 01 5F 24 03 27 12 31"
send_apdu "PAN sequence" "80 01 5F 34 01 01"
send_apdu "Track 2 Equivalent" "80 01 00 57 13 41 11 11 11 11 11 11 11 D2 71 22 01 00 00 00 00 00 00 0F"
send_apdu "Application label" "80 01 00 50 08 43 4F 4C 4F 53 53 55 53"
send_apdu "Application Priority Indicator" "80 01 00 87 01 01"
send_apdu "Cardholder name" "80 01 5F 20 14 43 4F 4C 4F 53 53 55 53 2F 43 41 52 44 48 4F 4C 44 45 52 20"
send_apdu "Application Version Number (9F08)" "80 01 9F 08 02 00 01"

# Step 8: Setup AIP and AFL
print_info "Step 8: Setup AIP and AFL"
send_apdu "AIP (DDA+CDA supported)" "80 01 00 82 02 3D 01"
send_apdu "AFL" "80 01 00 94 0C 08 02 02 00 10 01 02 00 18 01 05 00"
send_apdu "Static Data Auth Tag List (9F4A)" "80 01 9F 4A 01 82"

# Step 9: Setup CDOL
print_info "Step 9: Setup CDOL Structure"
send_apdu "CDOL1" "80 01 00 8C 1E 9F 02 06 9F 03 06 9F 1A 02 95 05 5F 2A 02 9A 03 9C 01 9F 37 04 9F 1C 08 9F 16 0F 9F 01 06"
send_apdu "CDOL2" "80 01 00 8D 20 8A 02 9F 02 06 9F 03 06 9F 1A 02 95 05 5F 2A 02 9A 03 9C 01 9F 37 04 9F 1C 08 9F 16 0F 9F 01 06"

# Step 10: Setup IAD
print_info "Step 10: Setup Issuer Application Data"
send_apdu "IAD" "80 01 9F 10 07 06 01 0A 03 A4 A0 02"

print_success "========================================"
print_success "Visa Test Card Personalization Complete!"
print_success "========================================"
print_info "PAN: 4111111111111111"
print_info "AID: A0000009510001"
print_info "Features: RSA-1984, DDA+CDA, ODA"
