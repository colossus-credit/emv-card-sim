package emvcardsimulator;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import emvcardsimulator.ppse.ProximityPaymentSystemEnvironmentContainer;

import javax.smartcardio.CardException;
import javax.smartcardio.ResponseAPDU;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Parity test: {@link AppletLifecycle} (used by EmvApplet / PSE / PaymentApp)
 * and PPSE's inline lifecycle (in
 * {@code ProximityPaymentSystemEnvironment}) must transition identically for
 * the same input sequence.
 *
 * <p>PPSE inlines the state machine rather than importing AppletLifecycle
 * because of a cross-package JC-converter export limitation (see the note in
 * {@link AppletLifecycle} class javadoc). This test asserts byte-identical
 * state behavior so drift between the two implementations surfaces as a test
 * failure.
 *
 * <p>Sequence walked: {@code (fresh → PERSO_PENDING) → non-last STORE DATA
 * (still PENDING) → last STORE DATA (now DONE) → another STORE DATA (rejected
 * with 6985)}. At each step we check the reference AppletLifecycle against
 * PPSE's observable behavior (SW codes on STORE DATA APDUs, since PPSE's
 * state isn't directly introspectable from outside the applet).
 */
public class AppletLifecyclePpseParityTest {

    // 2PAY.SYS.DDF01
    private static final byte[] PPSE_AID = new byte[] {
        (byte) 0x32, (byte) 0x50, (byte) 0x41, (byte) 0x59, (byte) 0x2E,
        (byte) 0x53, (byte) 0x59, (byte) 0x53, (byte) 0x2E,
        (byte) 0x44, (byte) 0x44, (byte) 0x46, (byte) 0x30, (byte) 0x31
    };

    // Minimal PPSE STORE DATA payload — DGI D001 (directory entry) with 3 bytes
    // of content. The exact bytes don't matter for lifecycle testing; we care
    // about the SW returned for each call.
    private static final byte[] STORE_DATA_PAYLOAD = new byte[] {
        (byte) 0xD0, (byte) 0x01, (byte) 0x03, (byte) 0xAA, (byte) 0xBB, (byte) 0xCC
    };

    @BeforeAll
    public static void setup() throws CardException {
        SmartCard.connect();
        SmartCard.install(PPSE_AID, ProximityPaymentSystemEnvironmentContainer.class);
    }

    @AfterAll
    public static void disconnect() throws CardException {
        SmartCard.disconnect();
    }

    @Test
    @DisplayName("AppletLifecycle ↔ PPSE parity: fresh instance both report PERSO_PENDING")
    public void testFreshStateIsPending() throws CardException {
        factoryResetPpse();

        // Reference behavior: a fresh AppletLifecycle is in PERSO_PENDING.
        AppletLifecycle ref = new AppletLifecycle();
        assertTrue(ref.isPersoPending(), "AppletLifecycle: fresh instance → PERSO_PENDING");
        assertFalse(ref.isPersoDone(), "AppletLifecycle: fresh instance is NOT PERSO_DONE");

        // PPSE behavior: accepts a non-last STORE DATA → 9000
        ResponseAPDU r = sendStoreData(false);
        assertEquals(0x9000, r.getSW(),
            "PPSE: fresh instance accepts STORE DATA (matches PERSO_PENDING)");
    }

    @Test
    @DisplayName("AppletLifecycle ↔ PPSE parity: non-last STORE DATA does not commit")
    public void testNonLastStoreDataStaysPending() throws CardException {
        factoryResetPpse();

        AppletLifecycle ref = new AppletLifecycle();
        // Non-last STORE DATA on reference: no commit called → stays PENDING
        assertTrue(ref.isPersoPending(), "ref: stays PENDING without commit");

        // PPSE: send several non-last STORE DATAs, each should 9000
        for (int i = 0; i < 3; i++) {
            ResponseAPDU r = sendStoreData(false);
            assertEquals(0x9000, r.getSW(),
                "PPSE: non-last STORE DATA " + (i + 1) + " stays accepted (PENDING)");
        }
    }

    @Test
    @DisplayName("AppletLifecycle ↔ PPSE parity: last STORE DATA (P1 b8=1) commits to PERSO_DONE")
    public void testLastStoreDataCommits() throws CardException {
        factoryResetPpse();

        AppletLifecycle ref = new AppletLifecycle();
        ref.commitPersonalization();
        assertTrue(ref.isPersoDone(), "ref: after commit → PERSO_DONE");
        assertFalse(ref.isPersoPending(), "ref: after commit is NOT PENDING");

        // PPSE: one last STORE DATA (P1 b8 = 1) should 9000
        ResponseAPDU r1 = sendStoreData(true);
        assertEquals(0x9000, r1.getSW(), "PPSE: last STORE DATA succeeds");

        // The next STORE DATA (any kind) should 6985 — PPSE is now DONE
        ResponseAPDU r2 = sendStoreData(false);
        assertEquals(0x6985, r2.getSW(),
            "PPSE: post-commit STORE DATA rejected (matches PERSO_DONE)");
    }

    @Test
    @DisplayName("AppletLifecycle ↔ PPSE parity: reset brings both back to PERSO_PENDING")
    public void testResetReturnsToPending() throws CardException {
        factoryResetPpse();

        AppletLifecycle ref = new AppletLifecycle();
        ref.commitPersonalization();
        assertTrue(ref.isPersoDone(), "ref: committed to DONE");
        ref.resetForTesting();
        assertTrue(ref.isPersoPending(), "ref: reset → back to PENDING");

        // PPSE: commit via last STORE DATA, reset via factory reset dev command,
        // then confirm STORE DATA is accepted again.
        sendStoreData(true);
        assertEquals(0x6985, sendStoreData(false).getSW(),
            "PPSE: committed → rejects writes");
        factoryResetPpse();
        assertEquals(0x9000, sendStoreData(false).getSW(),
            "PPSE: after factory reset → accepts writes again");
    }

    // -------------------------------------------------------------------------

    private static ResponseAPDU sendStoreData(boolean isLast) throws CardException {
        byte p1 = isLast ? (byte) 0x80 : (byte) 0x00;
        byte[] apdu = new byte[5 + STORE_DATA_PAYLOAD.length];
        apdu[0] = (byte) 0x00;             // CLA
        apdu[1] = (byte) 0xE2;             // INS STORE DATA
        apdu[2] = p1;                      // P1 — bit 8 = last block
        apdu[3] = (byte) 0x00;             // P2
        apdu[4] = (byte) STORE_DATA_PAYLOAD.length;
        System.arraycopy(STORE_DATA_PAYLOAD, 0, apdu, 5, STORE_DATA_PAYLOAD.length);
        return SmartCard.transmitCommand(apdu);
    }

    /** Dev-mode factory reset: 80 05 00 00 00 — resets PPSE's lifecycle to PENDING. */
    private static void factoryResetPpse() throws CardException {
        SmartCard.transmitCommand(new byte[] {
            (byte) 0x80, (byte) 0xA4, (byte) 0x04, (byte) 0x00, (byte) 0x0E,
            (byte) 0x32, (byte) 0x50, (byte) 0x41, (byte) 0x59, (byte) 0x2E,
            (byte) 0x53, (byte) 0x59, (byte) 0x53, (byte) 0x2E,
            (byte) 0x44, (byte) 0x44, (byte) 0x46, (byte) 0x30, (byte) 0x31
        });  // SELECT PPSE — in case test ran without prior select
        SmartCard.transmitCommand(new byte[] {
            (byte) 0x00, (byte) 0xA4, (byte) 0x04, (byte) 0x00, (byte) 0x0E,
            (byte) 0x32, (byte) 0x50, (byte) 0x41, (byte) 0x59, (byte) 0x2E,
            (byte) 0x53, (byte) 0x59, (byte) 0x53, (byte) 0x2E,
            (byte) 0x44, (byte) 0x44, (byte) 0x46, (byte) 0x30, (byte) 0x31
        });
        SmartCard.transmitCommand(new byte[] {
            (byte) 0x80, (byte) 0x05, (byte) 0x00, (byte) 0x00, (byte) 0x00
        });
    }
}
