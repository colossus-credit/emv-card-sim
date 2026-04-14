# Open CPS v2.0 Compliance Issues

Remaining gaps between the applet and CPS v2.0 (EMV Card Personalisation Specification with AES, August 2021). Issue #1 was fixed in commit `fix(cps): reject unrecognised DGIs with 6A88`.

## Issue #2 — Reserved DGIs 7FF0-7FFE Not Rejected

**Spec reference:** CPS v2.0 SS3.2 bullet 10

> "Data grouping identifiers (DGIs) '7FF0' through '7FFE' are reserved for application-independent personalisation processing and must not be used as a DGI by an EMV CPS compliant application."

**Current behavior:** Falls through to the 6A88 catch-all after Issue #1 fix, so these are now correctly rejected. No further action needed unless the spec requires a distinct status word (it does not — 6A88 is correct).

**Status:** Resolved by Issue #1 fix.

## Issue #3 — No Multi-STORE DATA DGI Chunking

**Spec reference:** CPS v2.0 SS4.3.4.4 and SS4.3.4.5

When a single DGI exceeds 255 bytes (the short APDU limit), the bureau splits it across multiple STORE DATA commands. The applet must reassemble the DGI data:

> "The first APDU contains a STORE DATA command according to Table 4-8, truncated at the maximum allowable length (Lc equals 255 bytes including possible MAC). The subsequent APDU contains a STORE DATA command with any remaining data."

**Current behavior:** Each `processOneDgi` call expects the full DGI payload within a single STORE DATA command. A DGI split across two commands would be misinterpreted — the continuation bytes would be parsed as a new DGI header.

**Risk:** Low for our card. Record DGIs are well under 255 bytes. RSA-2048 keys (256 bytes) would trigger this, but we use RSA-1024 (128 bytes). Extended APDU support (which our card has) eliminates the need for chunking entirely since the bureau can send up to 65535 bytes in one command.

**Fix:** Track partial DGI state across consecutive STORE DATA commands when `Lc` truncation is detected (remaining bytes < declared DGI length). Only needed if RSA-2048 keys or large proprietary DGIs are added.

## Issue #4 — DGI 9000 KCV Not Verified

**Spec reference:** CPS v2.0 SS7.15

> "The Key Check Value for any DES key will be computed by encrypting 8 bytes of '00' using ECB 3DES with the key concerned and for an AES key by encrypting 16 bytes of '01' using ECB AES with the key concerned."

**Current behavior:** DGI 9000 (Key Check Values) is accepted as a no-op. The applet acknowledges the DGI with `9000` but does not verify the KCV against the loaded keys.

**Risk:** Low for development and testing. A real perso bureau would rely on KCV verification to catch key loading errors. Without it, a corrupted key would be silently accepted and produce invalid cryptograms at transaction time.

**Fix:** After processing key DGIs (8000, 8201, 8202), compute the KCV and compare against the values in DGI 9000. Return `6A80` on mismatch.
