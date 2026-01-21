# Verifone Terminal Logs Show Zeros for EMV Card Data - PCI Compliance Masking

## Executive Summary

When testing an EMV JavaCard applet with a Verifone Android terminal, the terminal logs show **all zeros** for sensitive EMV tags (PAN, Track2, expiry, cardholder name) while the same card returns **correct data** when read via a PC-based reader (e.g., gp.jar). This is **NOT a bug** - it is intentional **PCI-DSS compliant log sanitization** performed by the Verifone SDI (Secure Data Interchange) layer.

## The Problem Observed

### Symptoms
- Card reads correctly on PC with gp.jar: `5A 08 67 67 67 67 12 34 44 44` (PAN visible)
- Same card on Verifone terminal logs: `5A 08 00 00 00 00 00 00 00 00` (all zeros)
- TLV structure remains intact (correct tag IDs and lengths)
- Only specific "sensitive" tags are zeroed
- Non-sensitive tags (AIP, AFL, ATC, CDOLs) show correct values

### Tags Affected (Showing Zeros)
| Tag | Name | Why Sensitive |
|-----|------|---------------|
| 5A | Primary Account Number (PAN) | Cardholder data |
| 57 | Track 2 Equivalent Data | Contains full PAN + expiry |
| 5F20 | Cardholder Name | PII |
| 5F24 | Application Expiration Date | Card security data |
| 5F34 | PAN Sequence Number | Card identification |

### Tags NOT Affected (Showing Correct Data)
| Tag | Name |
|-----|------|
| 82 | Application Interchange Profile (AIP) |
| 94 | Application File Locator (AFL) |
| 9F36 | Application Transaction Counter (ATC) |
| 8C | CDOL1 |
| 8D | CDOL2 |
| 8E | CVM List |
| 9F10 | Issuer Application Data |

## Root Cause: Verifone SDI PCI Compliance Layer

The Verifone SDI library (`emv_common.cpp`) implements PCI-DSS compliant log sanitization. Before any EMV data is written to Android logcat, sensitive tags are either:
1. **Zeroed out completely** (default behavior)
2. **Masked with first-6/last-4 pattern** (when configured)
3. **Removed entirely** from the response

### Evidence from Logs

```
01-20 23:34:30.259 I SDI: (src/emv_common.cpp:218) Remove sensitive tag 57
01-20 23:42:31.381 I SDI: (src/emv_common.cpp:218) Remove sensitive tag 5A
01-20 23:42:31.381 I SDI: (src/emv_common.cpp:218) Remove sensitive tag 57
```

The SDI library explicitly logs when it removes sensitive tags.

### Configuration Files

The Verifone SDI looks for sensitive tag configuration in multiple locations:

1. **emvct.json** - EMV Contact kernel configuration
   - Location: Terminal-specific path
   - Contains list of sensitive tags to mask

2. **sensitivetags.json** - SDI-level sensitive tag list
   - Location: `/data/user/0/com.verifone.sdi/files/flash/sdi/sensitivetags.json`
   - When not found, falls back to hardcoded list

3. **Hardcoded fallback** - Built into `emv_common.cpp`
   - Even if config files are removed, certain tags (5A, 57) are always masked
   - This is a safety net to ensure PCI compliance

### Log Message When Config Not Found

```
(src/emv_common.cpp:288) secureResponseData: sensitive tags file '/data/user/0/com.verifone.sdi/files/flash/sdi/sensitivetags.json' not found
```

Despite this "not found" message, masking still occurs via hardcoded fallback.

## Verification Test Performed

### Test Design
1. Personalized card with distinctive PAN ending in `4444`: `6767676712344444`
2. Ran transaction on Verifone terminal
3. Compared card internal logs vs terminal logs

### Card Internal Logs (via proprietary 8006 command)
```
Response to READ RECORD 00B2011C00:
70 41 5A 08 67 67 67 67 12 34 44 44 5F 24 03 27 12 31 ...
              ^^^^^^^^^^^^^^^^^^^^^^^^
              PAN: 6767676712344444 (correct!)
```

### Terminal Logs (via adb logcat) - Before Config Change
```
5A 08 00 00 00 00 00 00 00 00
       ^^^^^^^^^^^^^^^^^^^^^^^^
       PAN: All zeros (masked!)
```

### Terminal Logs (via adb logcat) - After Removing Tags from emvct.json
```
DF44 10 36373637363758585858585834343434
        ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
        ASCII: "676767XXXXXX4444" (first-6/last-4 masking!)
```

The `4444` ending proves the terminal received the correct PAN but masked it for logging.

## How to Disable Masking (For Development Only)

**WARNING: Never disable PCI masking in production environments.**

### Option 1: Modify emvct.json
Remove sensitive tags from the masking list in the EMV CT kernel configuration.

### Option 2: Create sensitivetags.json
Create an empty or minimal `sensitivetags.json` at:
```
/data/user/0/com.verifone.sdi/files/flash/sdi/sensitivetags.json
```

### Option 3: Check Verifone Debug Settings
Look for settings like:
- "PAN masking"
- "Sensitive data redaction"
- "PCI mode"
- "Debug logging level"

**Note:** Even with config changes, some hardcoded masking may persist for tags 5A and 57.

## How to Verify Card is Working Correctly

If you suspect the zeros are masking (not actual missing data):

### Method 1: Check Card Internal Logs
If your applet has logging capability (like the ApduLog class in this simulator):
```bash
java -jar gp.jar -a 00A4040007A0000009510001 -a 8006000000 -a 8006000000 ...
```
The card's internal logs will show what data was actually sent.

### Method 2: Use PC-Based Reader
Read the card with gp.jar or similar tool:
```bash
java -jar gp.jar -d -a 00A4040007A0000009510001 -a 00B2011C00
```
This bypasses the Verifone SDI layer entirely.

### Method 3: Use Distinctive Test Data
Personalize with a recognizable PAN (e.g., ending in `4444`):
- If terminal UI/receipt shows `...4444` but logs show zeros = masking confirmed
- If terminal UI also shows zeros/errors = actual data problem

### Method 4: Check Non-Sensitive Tags
If tags like 82 (AIP), 94 (AFL), 9F36 (ATC) show correct values but PAN shows zeros, masking is confirmed. A real data transmission problem would affect all tags.

## PCI-DSS Background

### Why This Masking Exists
PCI-DSS (Payment Card Industry Data Security Standard) requires that cardholder data be protected. Requirement 3.4 states that PAN must be rendered unreadable anywhere it is stored, including logs.

### Acceptable Masking Methods
- First 6 and last 4 digits only (BIN + last 4)
- Full redaction (zeros or removal)
- Tokenization
- Encryption

### What Verifone Does
The SDI layer implements multiple masking levels:
1. **Full zero-out**: Replace all bytes with 0x00 (strictest)
2. **First-6/Last-4**: Show `676767XXXXXX4444` pattern
3. **Tag removal**: Completely remove tag from logged output

## Code References

### Verifone SDI (Native Library)
- `src/emv_common.cpp:218` - "Remove sensitive tag" logic
- `src/emv_common.cpp:288` - "secureResponseData" function
- `src/emv_common.cpp:105` - "obfuscatePANTLV" function
- `src/emv_common.cpp:194` - "getTagData" function

### EMV Card Simulator (This Project)
- `EmvApplet.java` - Base applet with tag storage
- `PaymentApplication.java` - Payment app with READ RECORD handling
- `ApduLog.java` - Internal card logging (bypasses terminal masking)

## Troubleshooting Flowchart

```
Card returns zeros on Verifone terminal
                |
                v
    Does PC reader (gp.jar) show correct data?
           /              \
         YES               NO
          |                 |
          v                 v
   PCI MASKING!       Card/Applet bug
   (This document)    (Debug applet code)
          |
          v
   Verify with card internal logs
   or distinctive PAN test
          |
          v
   If confirmed, card works correctly.
   Zeros are expected PCI behavior.
```

## Summary

| Observation | Explanation |
|-------------|-------------|
| Zeros only for specific tags (5A, 57, 5F20, 5F24, 5F34) | These are PCI-sensitive tags |
| TLV structure intact (correct lengths) | Data received correctly, then masked |
| Non-sensitive tags show correct values | Masking is selective, not transmission failure |
| PC reader shows correct data | Proves card sends correct data |
| Card internal logs show correct data | Proves card believes it sent correct data |
| Log message "Remove sensitive tag" | Explicit confirmation of masking |
| First-6/last-4 visible after config change | Proves terminal received full PAN |

**Bottom Line:** If you see zeros for PAN/Track2 on Verifone but correct data on PC reader, your card works fine. The zeros are PCI-DSS compliant log sanitization, not a bug.

## Document History

- **Created:** 2026-01-21
- **Issue:** EMV card simulator showing zeros on Verifone terminal
- **Resolution:** Confirmed as PCI compliance masking, not a bug
- **Test Card PAN:** 6767676712344444 (distinctive `4444` ending for verification)
