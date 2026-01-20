# How to Read EMV Transaction Logs from Verifone Terminal

This document explains how to retrieve and analyze EMV transaction logs from a Verifone Android terminal connected via ADB.

## Prerequisites

- ADB (Android Debug Bridge) installed and configured
- Verifone terminal connected via USB
- Terminal has run at least one EMV transaction

## Step 1: Pull Log Archives from Device

Transaction logs are stored as compressed archives on the device's SD card:

```bash
# List available log archives (most recent last)
adb shell "ls -la /sdcard/Download/*.tgz" | tail -20

# Pull the most recent log archive
adb pull "/sdcard/Download/[SERIAL]_[DATE]_[TIME]_AndroidLogs.tgz" /tmp/emv_logs/
```

Example:
```bash
adb pull "/sdcard/Download/713-392-264_20260119_120656_AndroidLogs.tgz" /tmp/emv_logs/
```

## Step 2: Extract the Archive

```bash
cd /tmp/emv_logs
tar -xzf *_AndroidLogs.tgz
```

This creates:
- `logcat.log` - Main log file with all Android and EMV kernel logs
- `data/` - Additional data files
- `mnt/` - Mount point data

## Step 3: Search for EMV Transaction Data

### Find Transaction Flow
```bash
# Search for EMV CT (Contact) transaction events
grep -i "emvct\|sdi\|apdu\|transaction" logcat.log | tail -100

# Find specific transaction time window (example: 12:06)
grep -E "12:06:[0-9]{2}" logcat.log | grep -iE "emvct|sdi"
```

### Key Log Patterns

| Pattern | Description |
|---------|-------------|
| `SdiCardCT: Command Result:` | Transaction result status |
| `EMVSTATUS_FALLBACK` | ODA/CDA verification failed |
| `EMVSTATUS_OK` | Transaction succeeded |
| `EMV CT TRANSACTION FLOW COMPLETE` | Transaction finished |
| `First GEN AC response:` | GENERATE AC result |
| `EMV_ADK_DEBUG_EXITCODE=` | Kernel exit code |

### Check ODA/CDA Status
```bash
# Find ODA-related logs
grep -i "cda\|dda\|oda\|signature\|cert\|capk" logcat.log | grep -i emv

# Check exit codes
grep "EMV_ADK_DEBUG_EXITCODE" logcat.log
```

### Common Exit Codes

| Code | Meaning |
|------|---------|
| `00` | Success |
| `33` | ODA Failed |
| `BC` | CDA Failed / Fallback |
| `F4` | Fallback decision |

## Step 4: Analyze Card Data

### Find Card-Related Tags
```bash
# Search for EMV tags in logs
grep -E "9F46|9F48|9F47|9F4B|5A|57" logcat.log | grep -i emv | tail -30

# Check READ RECORD responses
grep "L1 Receive:" logcat.log | tail -30
```

### Parse Tag Values
Look for lines like:
```
*** Tag found in L2 shared object, standard store: 005a: 8 ***
*** L1 Receive: 70 81 FC 9F 46 81 F8 ... 90 00 ***
```

The `70` is the record template, `9F 46 81 F8` is ICC certificate (248 bytes).

## Step 5: Identify Common Issues

### Issue: Certificate Data is All Zeros
```
9F 46 81 F8 00 00 00 00 00 00 00...
```
**Cause**: ICC certificate not loaded to card during personalization.
**Fix**: Load correct ICC certificate using:
```bash
ICC_CERT=$(xxd -p keys/icc/icc_certificate.bin | tr -d '\n' | tr 'a-f' 'A-F')
java -jar gp.jar --applet A0000009510001 --apdu "80019F46F8${ICC_CERT}" -d
```

### Issue: CAPK Not Found
```
CAPK not found for RID/Index
```
**Cause**: Terminal doesn't have the Colossus CA Public Key configured.
**Fix**: Configure CAPK index 0x92 on the terminal.

### Issue: PAN Mismatch in Certificate
**Cause**: ICC certificate was generated for different PAN than card has.
**Fix**: Regenerate ICC certificate with correct PAN:
```bash
./generate-icc-cert.sh ./keys/issuer/issuer_private.pem [PAN] ./keys/icc
```

## Log Configuration

Log verbosity is controlled by config files in:
```
/Users/dangerousfood/Dev/psdk_android_sdi_reference_app/resources/log_config/
```

Files:
- `EMVCT_log.conf` - EMV Contact kernel logs
- `EMVCTLS_log.conf` - EMV Contactless kernel logs
- `SDI_log.conf` - SDI interface logs

Each config has format:
```json
{
    "schema_version": "1.0",
    "enabled": true,
    "mask": 255,
    "output": "LOGAPI_ALL",
    "verbosity": 7
}
```

Set `verbosity: 7` for maximum detail.

## Quick Reference Commands

```bash
# Pull latest logs
adb shell "ls -la /sdcard/Download/*.tgz" | tail -1
adb pull "/sdcard/Download/[latest].tgz" /tmp/emv_logs/

# Extract
cd /tmp/emv_logs && tar -xzf *.tgz

# Find EMV transaction result
grep "EMVSTATUS\|Transaction completed\|GEN AC response" logcat.log

# Check certificate data
grep "9F 46\|9F 48\|9F 47" logcat.log | grep "L1 Receive"

# Check debug exit code
grep "EMV_ADK_DEBUG_EXITCODE" logcat.log | tail -5
```

## Transaction Flow Summary

1. **SELECT PSE** (1PAY.SYS.DDF01)
2. **READ RECORD** from PSE directory
3. **SELECT AID** (A0000009510001 for Colossus)
4. **GET PROCESSING OPTIONS** (GPO)
5. **READ RECORD** for card data and certificates
6. **Offline Data Authentication** (DDA/CDA verification)
7. **GENERATE AC** (request cryptogram)
8. **Transaction Complete** or **Fallback**

Look for these steps in sequence in the logs to identify where failure occurred.
