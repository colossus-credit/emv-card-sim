#!/usr/bin/env python3
"""Read records over contact interface to verify READ RECORD response bytes."""
from smartcard.System import readers
from smartcard.util import toBytes

def tx(conn, apdu_hex):
    apdu = toBytes(apdu_hex.replace(" ", ""))
    data, sw1, sw2 = conn.transmit(apdu)
    return bytes(data), (sw1 << 8) | sw2

r = readers()
conn = r[0].createConnection()
conn.connect()

# Select contactless app
resp, sw = tx(conn, "00 A4 04 00 07 A0000009511010 00")
print(f"SELECT: SW={sw:04X}, FCI={resp.hex().upper()}")

# GPO with dummy PDOL data (just enough to get AFL)
# Build GPO: 80 A8 00 00 Lc 83 Len [PDOL data]
pdol_data = bytes([
    0x00, 0x00, 0x00, 0x00, 0x10, 0x00,  # Amount
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  # Amount Other
    0x08, 0x40,                            # Country
    0x00, 0x00, 0x00, 0x00, 0x00,          # TVR
    0x08, 0x40,                            # Currency
    0x26, 0x04, 0x03,                      # Date
    0x00,                                  # Type
    0xDE, 0xAD, 0xBE, 0xEF,               # UN
    0x54, 0x45, 0x52, 0x4D, 0x30, 0x30, 0x30, 0x31,  # TermID
    0x4D, 0x45, 0x52, 0x43, 0x48, 0x41, 0x4E, 0x54,  # MerchID
    0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x31,
    0x00, 0x00, 0x01, 0x23, 0x45, 0x67     # AcqID
])
gpo_cmd = bytes([0x80, 0xA8, 0x00, 0x00, len(pdol_data) + 2, 0x83, len(pdol_data)]) + pdol_data
data, sw1, sw2 = conn.transmit(list(gpo_cmd))
resp = bytes(data)
sw = (sw1 << 8) | sw2
print(f"GPO: SW={sw:04X}, resp={resp.hex().upper()}")

if sw != 0x9000:
    print("GPO failed, cannot read records")
    exit(1)

# Parse AFL from Format 1 response (tag 80)
if resp[0] == 0x80:
    gpo_len = resp[1]
    aip = resp[2:4]
    afl = resp[4:2+gpo_len]
    print(f"AIP={aip.hex().upper()} AFL={afl.hex().upper()}")
else:
    print(f"Unexpected GPO tag: {resp[0]:02X}")
    exit(1)

# Read each record per AFL
print("\n=== READ RECORD responses ===")
for i in range(0, len(afl), 4):
    afl_byte = afl[i]
    first_rec = afl[i+1]
    last_rec = afl[i+2]
    oda_count = afl[i+3]
    sfi = (afl_byte >> 3) & 0x1F
    p2 = afl_byte | 0x04  # proper EMV P2

    for rec in range(first_rec, last_rec + 1):
        cmd = f"00 B2 {rec:02X} {p2:02X} 00"
        resp, sw = tx(conn, cmd)
        print(f"\nSFI{sfi}/REC{rec}: SW={sw:04X}, {len(resp)} bytes")
        if sw == 0x9000 and len(resp) > 0:
            hex_str = resp.hex().upper()
            # Show first line
            print(f"  RAW: {hex_str[:80]}")
            if len(hex_str) > 80:
                print(f"       {hex_str[80:160]}")
                if len(hex_str) > 160:
                    print(f"       {hex_str[160:240]}")
                    if len(hex_str) > 240:
                        print(f"       ...({len(hex_str)//2} bytes total)")
            # Validate tag 70
            if resp[0] == 0x70:
                if resp[1] == 0x81:
                    inner_len = resp[2]
                    inner_start = 3
                else:
                    inner_len = resp[1]
                    inner_start = 2
                actual_inner = len(resp) - inner_start
                if actual_inner == inner_len:
                    print(f"  TAG 70: OK (inner={inner_len} bytes)")
                else:
                    print(f"  TAG 70: LENGTH MISMATCH! declared={inner_len}, actual={actual_inner}")
                # Parse inner TLVs
                pos = inner_start
                while pos < len(resp):
                    tag_byte = resp[pos]
                    if (tag_byte & 0x1F) == 0x1F:
                        # 2-byte tag
                        tag = (resp[pos] << 8) | resp[pos+1]
                        pos += 2
                    else:
                        tag = tag_byte
                        pos += 1
                    # Length
                    if resp[pos] == 0x81:
                        tlen = resp[pos+1]
                        pos += 2
                    elif resp[pos] == 0x82:
                        tlen = (resp[pos+1] << 8) | resp[pos+2]
                        pos += 3
                    else:
                        tlen = resp[pos]
                        pos += 1
                    print(f"    {tag:04X} len={tlen}")
                    pos += tlen
            else:
                print(f"  ERROR: does NOT start with tag 70 (got {resp[0]:02X})")
        elif sw != 0x9000:
            print(f"  ERROR: {sw:04X}")

print("\nDone.")
