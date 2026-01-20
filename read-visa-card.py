#!/usr/bin/env python3
"""
Read all EMV fields from a Visa card for comparison
"""

from smartcard.System import readers
from smartcard.util import toHexString, toBytes
import struct
import time

_connection_protocol = None

def send_apdu(connection, apdu):
    """Send APDU and return response with T=0 handling"""
    global _connection_protocol
    try:
        data, sw1, sw2 = connection.transmit(apdu, _connection_protocol)
    except Exception as e:
        print(f"Transmit error: {e}")
        return [], 0x6F, 0x00

    # Handle 61XX - More data available (GET RESPONSE)
    while sw1 == 0x61:
        get_response = [0x00, 0xC0, 0x00, 0x00, sw2]
        more_data, sw1, sw2 = connection.transmit(get_response, _connection_protocol)
        data.extend(more_data)

    # Handle 6CXX - Wrong Le, retry with correct length
    if sw1 == 0x6C:
        # Retry with correct Le
        new_apdu = apdu[:-1] + [sw2] if len(apdu) > 4 else apdu + [sw2]
        data, sw1, sw2 = connection.transmit(new_apdu, _connection_protocol)
        while sw1 == 0x61:
            get_response = [0x00, 0xC0, 0x00, 0x00, sw2]
            more_data, sw1, sw2 = connection.transmit(get_response, _connection_protocol)
            data.extend(more_data)

    return data, sw1, sw2

def parse_tlv(data, offset=0, depth=0):
    """Parse TLV data recursively"""
    result = []
    pos = offset

    while pos < len(data):
        # Parse tag
        if pos >= len(data):
            break

        tag = data[pos]
        pos += 1

        # Two-byte tag?
        if (tag & 0x1F) == 0x1F:
            if pos >= len(data):
                break
            tag = (tag << 8) | data[pos]
            pos += 1
            # Could be 3-byte tag
            if data[pos-1] & 0x80:
                if pos >= len(data):
                    break
                tag = (tag << 8) | data[pos]
                pos += 1

        # Parse length
        if pos >= len(data):
            break
        length = data[pos]
        pos += 1

        if length & 0x80:
            num_bytes = length & 0x7F
            length = 0
            for _ in range(num_bytes):
                if pos >= len(data):
                    break
                length = (length << 8) | data[pos]
                pos += 1

        if pos + length > len(data):
            length = len(data) - pos

        value = data[pos:pos+length]
        pos += length

        # Check if constructed (has nested TLV)
        is_constructed = bool(tag & 0x20 if tag < 0x100 else (tag >> 8) & 0x20)

        if is_constructed and length > 0:
            children = parse_tlv(list(value), 0, depth+1)
            result.append({'tag': tag, 'length': length, 'value': value, 'children': children})
        else:
            result.append({'tag': tag, 'length': length, 'value': value})

    return result

def format_tag(tag):
    """Format tag as hex string"""
    if tag > 0xFFFF:
        return f"{tag:06X}"
    elif tag > 0xFF:
        return f"{tag:04X}"
    else:
        return f"{tag:02X}"

TAG_NAMES = {
    0x4F: "Application DF Name (AID)",
    0x50: "Application Label",
    0x57: "Track 2 Equivalent Data",
    0x5A: "Application PAN",
    0x5F20: "Cardholder Name",
    0x5F24: "Application Expiration Date",
    0x5F25: "Application Effective Date",
    0x5F28: "Issuer Country Code",
    0x5F2D: "Language Preference",
    0x5F34: "PAN Sequence Number",
    0x6F: "FCI Template",
    0x70: "Record Template",
    0x77: "Response Template (Format 2)",
    0x80: "Response Template (Format 1)",
    0x82: "Application Interchange Profile (AIP)",
    0x84: "DF Name",
    0x87: "Application Priority Indicator",
    0x88: "Short File Identifier (SFI)",
    0x8C: "CDOL1",
    0x8D: "CDOL2",
    0x8E: "CVM List",
    0x8F: "CA Public Key Index",
    0x90: "Issuer Public Key Certificate",
    0x91: "Issuer Authentication Data",
    0x92: "Issuer Public Key Remainder",
    0x93: "Signed Static Application Data",
    0x94: "Application File Locator (AFL)",
    0x9F02: "Amount Authorized",
    0x9F03: "Amount Other",
    0x9F05: "Application Discretionary Data",
    0x9F06: "AID (Terminal)",
    0x9F07: "Application Usage Control",
    0x9F08: "Application Version Number",
    0x9F09: "Application Version Number (Terminal)",
    0x9F0D: "IAC Default",
    0x9F0E: "IAC Denial",
    0x9F0F: "IAC Online",
    0x9F10: "Issuer Application Data",
    0x9F11: "Issuer Code Table Index",
    0x9F12: "Application Preferred Name",
    0x9F13: "Last Online ATC Register",
    0x9F14: "Lower Consecutive Offline Limit",
    0x9F17: "PIN Try Counter",
    0x9F1A: "Terminal Country Code",
    0x9F1F: "Track 1 Discretionary Data",
    0x9F20: "Track 2 Discretionary Data",
    0x9F23: "Upper Consecutive Offline Limit",
    0x9F26: "Application Cryptogram",
    0x9F27: "Cryptogram Information Data",
    0x9F32: "Issuer Public Key Exponent",
    0x9F33: "Terminal Capabilities",
    0x9F34: "CVM Results",
    0x9F35: "Terminal Type",
    0x9F36: "Application Transaction Counter (ATC)",
    0x9F37: "Unpredictable Number",
    0x9F38: "PDOL",
    0x9F42: "Application Currency Code",
    0x9F44: "Application Currency Exponent",
    0x9F45: "Data Authentication Code",
    0x9F46: "ICC Public Key Certificate",
    0x9F47: "ICC Public Key Exponent",
    0x9F48: "ICC Public Key Remainder",
    0x9F49: "DDOL",
    0x9F4A: "Static Data Authentication Tag List",
    0x9F4B: "Signed Dynamic Application Data",
    0x9F4C: "ICC Dynamic Number",
    0x9F4D: "Log Entry",
    0x9F4F: "Log Format",
    0xA5: "FCI Proprietary Template",
    0xBF0C: "FCI Issuer Discretionary Data",
}

def get_tag_name(tag):
    return TAG_NAMES.get(tag, "Unknown")

def print_tlv(tlv_list, indent=0):
    """Print TLV data"""
    for item in tlv_list:
        tag = format_tag(item['tag'])
        name = get_tag_name(item['tag'])
        value_hex = toHexString(list(item['value']))

        prefix = "  " * indent
        print(f"{prefix}Tag {tag}: {name}")
        print(f"{prefix}  Length: {item['length']}")

        # Pretty print some values
        if item['tag'] in [0x50, 0x5F20, 0x5F2D]:
            try:
                print(f"{prefix}  Value: {bytes(item['value']).decode('ascii', errors='replace')}")
            except:
                print(f"{prefix}  Value: {value_hex}")
        elif item['tag'] == 0x5A:
            pan = value_hex.replace(' ', '').rstrip('F')
            print(f"{prefix}  Value: {pan}")
        elif item['tag'] in [0x5F24, 0x5F25]:
            # Date format YYMMDD
            print(f"{prefix}  Value: {value_hex} (YYMMDD)")
        elif len(item['value']) <= 32:
            print(f"{prefix}  Value: {value_hex}")
        else:
            print(f"{prefix}  Value: {value_hex[:60]}...")
            print(f"{prefix}         ({item['length']} bytes total)")

        if 'children' in item:
            print_tlv(item['children'], indent+1)
        print()

def read_all_tags(connection):
    """Read all EMV tags from the card"""
    all_tags = {}

    # Try to select common AIDs
    aids = [
        # Visa AIDs
        [0xA0, 0x00, 0x00, 0x00, 0x03, 0x10, 0x10],  # Visa Credit/Debit
        [0xA0, 0x00, 0x00, 0x00, 0x03, 0x20, 0x10],  # Visa Electron
        [0xA0, 0x00, 0x00, 0x00, 0x03, 0x30, 0x10],  # Visa Interlink
        # Mastercard AIDs
        [0xA0, 0x00, 0x00, 0x00, 0x04, 0x10, 0x10],  # Mastercard Credit/Debit
        [0xA0, 0x00, 0x00, 0x00, 0x04, 0x30, 0x60],  # Maestro
        # American Express
        [0xA0, 0x00, 0x00, 0x00, 0x25, 0x01, 0x01],  # Amex
        # Discover
        [0xA0, 0x00, 0x00, 0x01, 0x52, 0x30, 0x10],  # Discover
    ]

    selected_aid = None

    for aid in aids:
        # SELECT command
        select_cmd = [0x00, 0xA4, 0x04, 0x00, len(aid)] + aid
        data, sw1, sw2 = send_apdu(connection, select_cmd)

        if sw1 == 0x90 and sw2 == 0x00:
            print(f"Selected AID: {toHexString(aid)}")
            selected_aid = aid

            # Parse FCI
            if data:
                print("\n=== FCI (File Control Information) ===")
                tlv = parse_tlv(data)
                print_tlv(tlv)

                # Store tags
                def store_tags(items):
                    for item in items:
                        all_tags[item['tag']] = item['value']
                        if 'children' in item:
                            store_tags(item['children'])
                store_tags(tlv)
            break

    if not selected_aid:
        print("No EMV application found!")
        return all_tags

    # GET PROCESSING OPTIONS
    print("\n=== GET PROCESSING OPTIONS ===")
    # Use empty PDOL data for simplicity
    gpo_cmd = [0x80, 0xA8, 0x00, 0x00, 0x02, 0x83, 0x00]
    data, sw1, sw2 = send_apdu(connection, gpo_cmd)

    if sw1 == 0x90:
        print(f"GPO Response: SW={sw1:02X}{sw2:02X}")
        if data:
            tlv = parse_tlv(data)
            print_tlv(tlv)
            def store_tags(items):
                for item in items:
                    all_tags[item['tag']] = item['value']
                    if 'children' in item:
                        store_tags(item['children'])
            store_tags(tlv)
    else:
        print(f"GPO failed: SW={sw1:02X}{sw2:02X}")

    # Get AFL from stored tags
    afl = all_tags.get(0x94, [])

    # READ RECORDS based on AFL
    if afl:
        print("\n=== READING RECORDS (from AFL) ===")
        # AFL format: SFI (5 bits) | first record | last record | num in auth
        pos = 0
        while pos < len(afl):
            sfi = (afl[pos] >> 3) & 0x1F
            first = afl[pos+1]
            last = afl[pos+2]
            auth = afl[pos+3]
            pos += 4

            print(f"\nSFI {sfi}: Records {first}-{last} ({auth} for auth)")

            for record in range(first, last+1):
                read_cmd = [0x00, 0xB2, record, (sfi << 3) | 0x04, 0x00]
                data, sw1, sw2 = send_apdu(connection, read_cmd)

                if sw1 == 0x90:
                    print(f"\n  Record {record}:")
                    tlv = parse_tlv(data)
                    print_tlv(tlv, indent=1)
                    def store_tags(items):
                        for item in items:
                            all_tags[item['tag']] = item['value']
                            if 'children' in item:
                                store_tags(item['children'])
                    store_tags(tlv)
                else:
                    print(f"  Record {record}: SW={sw1:02X}{sw2:02X}")

    return all_tags

def main():
    print("="*60)
    print("EMV Card Reader - Visa Card Analysis")
    print("="*60)
    print()

    # Get available readers
    r = readers()
    if not r:
        print("No smart card readers found!")
        return

    print(f"Found {len(r)} reader(s):")
    for i, reader in enumerate(r):
        print(f"  [{i}] {reader}")

    print("\nPlease insert your Visa card...")

    # Try to connect to each reader
    from smartcard.CardConnection import CardConnection
    global _connection_protocol
    connection = None
    for reader in r:
        try:
            connection = reader.createConnection()
            # Use auto protocol negotiation
            connection.connect()
            protocol = connection.getProtocol()
            _connection_protocol = protocol
            proto_name = "T=0" if protocol == CardConnection.T0_protocol else "T=1" if protocol == CardConnection.T1_protocol else f"Unknown({protocol})"
            print(f"\nConnected to: {reader} ({proto_name})")
            break
        except Exception as e:
            print(f"Failed to connect to {reader}: {e}")
            continue

    if not connection:
        print("No card found in any reader!")
        return

    # Read ATR
    atr = connection.getATR()
    print(f"ATR: {toHexString(atr)}")

    # Read all EMV tags
    all_tags = read_all_tags(connection)

    # Summary
    print("\n" + "="*60)
    print("SUMMARY OF KEY EMV TAGS")
    print("="*60)

    important_tags = [
        0x5A, 0x57, 0x5F24, 0x5F34, 0x82, 0x94, 0x8C, 0x8D, 0x8E,
        0x8F, 0x90, 0x92, 0x93, 0x9F32, 0x9F46, 0x9F47, 0x9F48,
        0x9F07, 0x9F0D, 0x9F0E, 0x9F0F, 0x9F4A, 0x9F49
    ]

    print("\nKey tags for ODA:")
    for tag in important_tags:
        if tag in all_tags:
            name = get_tag_name(tag)
            value = all_tags[tag]
            print(f"  {format_tag(tag)} {name}: {len(value)} bytes")
            if len(value) <= 16:
                print(f"       Value: {toHexString(list(value))}")
        else:
            name = get_tag_name(tag)
            print(f"  {format_tag(tag)} {name}: NOT PRESENT")

    # Check certificate sizes
    print("\n\nCertificate sizes:")
    if 0x90 in all_tags:
        print(f"  Issuer Certificate (90): {len(all_tags[0x90])} bytes")
    if 0x92 in all_tags:
        print(f"  Issuer PK Remainder (92): {len(all_tags[0x92])} bytes")
    if 0x9F46 in all_tags:
        print(f"  ICC Certificate (9F46): {len(all_tags[0x9F46])} bytes")
    if 0x9F48 in all_tags:
        print(f"  ICC PK Remainder (9F48): {len(all_tags[0x9F48])} bytes")

    print("\n")

if __name__ == '__main__':
    main()
