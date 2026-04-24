# Known Issue: ECDSA signature bytes leak into next SELECT's FCI

## Problem

Contact GenAC overwrites several standard EMV tags in the applet's tag store
with pieces of the ECDSA signature:

| Tag    | Current GenAC value | Where else it's referenced |
|--------|---------------------|----------------------------|
| `9F26` | s[0:8]              | Not in any record/FCI — safe |
| `9F10` | r[0:32]             | Not in any record/FCI — safe |
| `4F`   | s[8:24]             | Not in FCI template — safe |
| `5F2D` | s[24:32]            | **In FCI A5 template** — LEAKS |
| `84`   | Unchanged (direct write in builder) | FCI 6F template — safe |

Because `5F2D` is listed in the FCI A5 template, every SELECT after the first
transaction returns an FCI whose Language Preference field is actually the
previous transaction's signature bytes (not `"656E"`).

Tag `84` is safe because the builder writes the `84` TLV directly into the
response buffer without calling `EmvTag.setTag` — the stored value keeps the
real AID.

## Impact

- Terminal displays/processes stale crypto bytes as a language code. Most
  terminals ignore malformed language codes, but:
  - It's non-deterministic / user-visible noise in the FCI
  - Processors that strictly validate `5F2D` format could reject the SELECT
  - Cross-transaction information leak (last transaction's signature bytes
    readable from the FCI of the current transaction before any GenAC runs)

## Fix options

1. **Direct-write 5F2D too** — like we do for `84`. Write the TLV bytes
   directly into the GenAC response buffer in `sendGenerateAcResponseNoCda`
   and don't call `EmvTag.setTag((short)0x5F2D, ...)` in
   `generateEcdsaAtGenAc`. Keeps the stored value as the personalized
   `"656E"`.

2. **Restore tags at end of GenAC** — snapshot the real values before
   `generateEcdsaAtGenAc` and restore them after the response is sent. More
   complex, but keeps the tag store consistent.

3. **Remove 5F2D from FCI A5 template** — accept that language preference
   isn't advertised. Simplest from a code perspective but a deliberate profile
   regression.

**Recommendation:** Option 1. Symmetrical with how `84` already works.

## Scope

Contact flow only. Contactless uses the template-based builder
(`sendResponseTemplate`) and doesn't overwrite `5F2D` — it's safe.
