# Known Issue: AID-suffix-based interface detection is non-standard

## Current behavior

`PaymentApplication.java` classifies the interface (contact vs contactless) by
inspecting the last 2 bytes of the SELECT AID:

```java
// processSelect()
short suffixOffset = (short) (ISO7816.OFFSET_CDATA + aidLen - 2);
isContactInterface = !(buf[suffixOffset] == (byte) 0x10
                    && buf[(short) (suffixOffset + 1)] == (byte) 0x10);
```

- AID ends in `10 10` → contactless
- Anything else → contact

This matches our deployment model where contact is installed with
`A0000009510001` and contactless with `A0000009511010`.

## Why this is non-standard

Real payment applets (Visa, Mastercard, Amex, Discover, UnionPay) use the
**same AID on both interfaces** and detect the interface via
`APDU.getProtocol()`:

```java
byte media = (byte) (APDU.getProtocol() & APDU.PROTOCOL_MEDIA_MASK);
boolean contactless =
    (media == APDU.PROTOCOL_MEDIA_CONTACTLESS_TYPE_A) ||
    (media == APDU.PROTOCOL_MEDIA_CONTACTLESS_TYPE_B);
```

This is defined by the JavaCard Classic API and supported by every modern
JCOP card. It's also how EMV-compliant card OS implementations expect the
applet to behave.

## Problems we've hit

1. **MC spoofing forced AID choice.** To test with FDRC demo mode, we wanted
   to use MC Credit AID `A0000000041010`. Our detection would have classified
   it as contactless (suffix `10 10`), so we couldn't test the contact
   ECDSA-at-GenAC path. We ended up using US Maestro AID `A0000000042203`
   instead — purely because of the detection heuristic.

2. **Visa AIDs collide.** `A0000000031010` (Visa Credit) would be classified
   as contactless even when inserted as a contact card.

3. **Same-AID deployment impossible.** We can never install a single applet
   instance that handles both interfaces on the same AID, which is the
   industry norm.

4. **Personalization fragility.** If a bureau deploys with an AID suffix we
   didn't anticipate, behavior silently misclassifies.

5. **Cannot align with ColossusNet spec production model.** The spec assumes
   the applet detects interface via protocol, not AID. Our current code
   couples deployment topology to runtime behavior in a way the spec doesn't.

## Fix options

### Option A (recommended): switch to `APDU.getProtocol()`

Replace the AID-suffix block in `processSelect` with:

```java
byte protocol = (byte) (APDU.getProtocol() & APDU.PROTOCOL_MEDIA_MASK);
isContactInterface = !(protocol == APDU.PROTOCOL_MEDIA_CONTACTLESS_TYPE_A
                    || protocol == APDU.PROTOCOL_MEDIA_CONTACTLESS_TYPE_B);
```

**Tradeoff:** jcardsim may always report a single protocol (typically T=1
contact) regardless of the test context, so our existing contactless test
paths would need a different mechanism to exercise both sides:
- Option A.1: conditionally enable a test hook that forces
  `isContactInterface = false` via a dev APDU (gated by `!BuildConfig.PRODUCTION`).
- Option A.2: extend jcardsim (or mock `APDU.getProtocol()`) in the test
  framework so tests can set the protocol per-transaction.

Either way, production code uses the standard path and only tests diverge.

### Option B: personalization-time flag

Add a new DGI (e.g., `A008`) carrying 1 byte `{00|01}` that
`setAppSpecificSetting` writes to `isContactInterface`. Same code handles
both interfaces, flag chosen at perso. This is what some contactless-only
kernels do in practice.

**Tradeoff:** requires correct DGI during perso and no longer self-detects —
if the wrong flag is personalized, the applet misbehaves.

### Option C: separate applet classes

`PaymentApplicationContact extends EmvApplet` and
`PaymentApplicationContactless extends EmvApplet`, each with its own logic.
No runtime detection needed.

**Tradeoff:** duplicated logic across two classes; doubled CAP size; but
zero ambiguity.

## Recommendation

**Option A** before any production deployment. It's the EMV-convention path,
removes deployment-coupled fragility, and makes same-AID-both-interfaces
models possible.

Test-harness concerns are solvable — either a dev-only APDU for jcardsim
control, or fixing the test AIDs to match production expectations and
running the contact/contactless split only on the physical card for
integration tests.

## Current-state summary

- Production code: AID-suffix detection in `processSelect` (fragile)
- Tests: extended to use `A0000009511010`-style AIDs to force contactless path
  - `ColossusPaymentApplicationTest.testFullEmvContactlessWithEcdsaGenAc`
  - `PropertyTest.PAYMENT_AID` constant
- New contact-specific test: `testContactGenAcEcdsaDistributed` uses
  `A0000009510001`

## Scope

All flows (contact, contactless, CDA, ECDSA at GPO vs GenAC) depend on this
flag. Any fix must be reviewed against both interfaces' tests.
