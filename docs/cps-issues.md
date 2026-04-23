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

## Issue #5 — Personalization Interface (F-07 / SCP STORE DATA) Needs Newer Card for Live Verification

**Spec reference:** GP Card Spec v2.3.1 §7.3.2, EMV CPS v2.0 §4.3.4

Implementation landed and then was reverted because our current dev card (JCOP 2.4.1) can't run it:

- **Applet-side code was correct and tested**: `EmvApplet` and PPSE implemented `org.globalplatform.Personalization`, `processData()` delegated to a shared `handleStoreDataPayload()` helper used by both the APDU path and the ISD-forwarded path; 117 Java tests passed. Committed briefly as `7bb9804`, then reverted via commit above this note.
- **Three-layer tooling mismatch on JCOP 2.4.1**:
  1. Our GP Card API 1.8 distribution ships `globalplatform.exp` in **exp format 2.3** only.
  2. JC 3.0.5 converter (which targets JCOP 2.4.1 cards) only reads exp format 2.2.
  3. JC 3.1 converter reads exp 2.3 but produces **CAP format 2.3**, which JCOP 2.4.1 rejects on LOAD with `6985`.
  Additionally, JCOP 2.4.1 firmware does not expose the `Personalization` privilege on its ISD (confirmed via `gp --info` — privilege list omits it), so even with a loadable CAP, `INSTALL [for personalization]` would fail.

**Next step — waits on newer hardware:**

- Get JCOP 3 (SmartMX2) or JCOP 4 (SmartMX3) sample card; Joseph has JCOP 3 on hand. Bureau production cards will be JCOP 4.
- Cherry-pick `7bb9804` back onto the branch.
- Run `java -jar gp.jar --applet A0000009510001 --store-data <hex>` — should now complete SCP02 session + `INSTALL [for personalization]` + SCP-wrapped STORE DATA, with our applet's `processData()` receiving cleartext identical to what the direct APDU path sees today.
- If this works, the Python perso tool can be migrated to route through the ISD instead of sending direct APDUs — main work item is replacing direct `00 E2` sends with `gp.jar --install-for-personalization` orchestration.

**Current state** (with revert applied):
- All perso goes via the direct `00 E2 STORE DATA` path, no SCP wrapping at the applet boundary
- SCP02 is still used by gp.jar for LOAD and INSTALL commands (card-content management)
- The bureau hand-off path will need F-07 reapplied when running against modern cards — the committed version at `7bb9804` is correct per spec, just can't be loaded on our 10-year-old dev sample

## Issue #4 — DGI 9000 KCV Not Verified

**Spec reference:** CPS v2.0 SS7.15

> "The Key Check Value for any DES key will be computed by encrypting 8 bytes of '00' using ECB 3DES with the key concerned and for an AES key by encrypting 16 bytes of '01' using ECB AES with the key concerned."

**Current behavior:** DGI 9000 (Key Check Values) is accepted as a no-op. The applet acknowledges the DGI with `9000` but does not verify the KCV against the loaded keys.

**Risk:** Low for development and testing. A real perso bureau would rely on KCV verification to catch key loading errors. Without it, a corrupted key would be silently accepted and produce invalid cryptograms at transaction time.

**Fix:** After processing key DGIs (8000, 8201, 8202), compute the KCV and compare against the values in DGI 9000. Return `6A80` on mismatch.
