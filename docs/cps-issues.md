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

**Fix:** After processing key DGIs (8000, 8101, 8103, 8105 — post F-32), compute the KCV and compare against the values in DGI 9000. Return `6A80` on mismatch.

## Issue #6 — Direct `INS=E2` STORE DATA Path Bypasses CPS Secure-Messaging Requirement

**Spec reference:** CPS v2.0 §5.4.3 Secure Messaging; §2.3; GP Card Spec v2.3.1 §7.3.2 + Table 11-2 (Minimum Security Level for STORE DATA = AUTHENTICATED)

CPS §5.4.3 verbatim:

> "Secure messaging **shall** be required by all applications for the following personalisation commands: EXTERNAL AUTHENTICATE command; STORE DATA command if indicated by the security level of the EXTERNAL AUTHENTICATE command"

And §5.4.3.1:

> "Commands requiring a MAC shall include a C-MAC … that must be verified by the IC card prior to accepting the command. If the C-MAC fails to verify successfully, the IC card must reject the command with SW1 SW2 = '6982' and the secure channel session is terminated."

GP Card Spec v2.3.1 Table 11-2: STORE DATA minimum security level is **AUTHENTICATED** (i.e. valid active SCP session with C-MAC).

**Current behavior (deviation):** `EmvApplet.process(APDU)` and `ProximityPaymentSystemEnvironment.process(APDU)` bind `INS = 0xE2` directly and route to applet-local STORE DATA handlers. Neither handler establishes or validates a GP secure channel, nor calls `GPSystem.getSecureChannel().unwrap()`. Our Python perso tool takes advantage of this: it SELECTs each applet and sends bare `00 E2 …` APDUs — no `INITIALIZE UPDATE`, no `EXTERNAL AUTHENTICATE`, no C-MAC.

Why this is technically outside spec:

- CPS frames the entire perso flow as SCP-protected (§2.3 "a secure channel is established between the personalisation device and the IC card EMV application"). Table 4-7 enumerates security levels; none of them is "no secure messaging". If an applet accepts STORE DATA without any of those levels, it doesn't match the spec's state machine.
- GP enforces the AUTHENTICATED minimum only on APDUs that flow **through** the platform layer (LOAD, INSTALL, DELETE, ISD-forwarded STORE DATA via `Personalization.processData`). Once an applet is SELECTed directly, the platform stops intermediating and our own `process()` is free to accept any INS byte with any security posture. The spec doesn't explicitly forbid this, but it also doesn't bless it as a CPS-compliant perso path — it's application-private behavior that happens to use the same INS byte.

**What "not compliant" means in practice:**

- **CPS conformance audit (EMVCo, scheme security review, bureau security review):** flagged. An auditor walking the spec state machine would find no SCP session established for perso and rule the path non-compliant with §5.4.3.
- **Functional correctness (taps, transactions, bureau-loaded CAPs):** unaffected. The resulting perso'd card transacts normally — the deviation is about *how* the data got onto the card, not whether the data is correct.
- **Bureau-side tooling compatibility:** standard bureau perso scripts (Thales/Gemalto/Idemia) send SCP-wrapped STORE DATA by default. Those wouldn't be exercising our direct path at all; they'd target the `Personalization.processData()` entry point (F-07 / Issue #5). A real bureau never touches the direct path.

**Mitigations already in the codebase:**

- **F-07 committed at `7bb9804`** (currently reverted pending JCOP 3/4 hardware per Issue #5). Provides the spec-compliant ISD-mediated path: SCP-wrapped STORE DATA → ISD unwraps + C-MAC verifies → `Applet.processData()` receives cleartext on an AUTHENTICATED session. When F-07 is re-applied on hardware that supports it, spec compliance is achieved for any bureau using the standard flow.
- **Applet-internal lifecycle gate** (PERSO_PENDING → PERSO_DONE): ensures the direct path can only be exercised once per applet instance. After the final STORE DATA with P1 b8 = 1, all subsequent STORE DATAs return `6985` regardless of SCP state. This limits the attack surface of the direct path to a single window during the personalisation event.

**Next steps for full compliance:**

1. **Keep F-07 as the canonical perso path.** Re-apply `7bb9804` once JCOP 3/4 hardware lands (per Issue #5).
2. **In production builds, strip or guard the direct `INS=E2` path** so the only way STORE DATA reaches the applet is through the ISD-mediated SCP-wrapped flow. Options: gate with a `BuildConfig.PRODUCTION` check that makes the direct handler return `6E00` / `6982` in prod, or have the direct handler call `GPSystem.getSecureChannel()` and require an active AUTHENTICATED session before accepting payload bytes.
3. **Until then, document the deviation explicitly** in any conformance submission with a note that the direct path is a dev-time convenience; production perso is intended to be F-07-only. Auditors generally accept documented deviations + compensating controls (here: lifecycle lock + BuildConfig gating).

**Risk assessment for our current model:**

- Default ISD keys + direct path = anyone with physical card + `gp.jar` can SELECT our applet and rewrite PAN/keys until the lifecycle commits. F-60 + lifecycle commit on last STORE DATA limits this to exactly one perso run.
- Rotated (Arculus-held) ISD keys + direct path = physical attacker can still SELECT applet and send direct STORE DATA (no SCP needed for direct path), so the same one-perso-window risk applies until lifecycle commits.
- Either way, the practical mitigation is **always finalize perso on cards that ship to cardholders** (default behavior; `--no-finalize` is opt-in for dev cards only).
