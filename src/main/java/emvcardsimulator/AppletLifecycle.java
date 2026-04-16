package emvcardsimulator;

import emvcardsimulator.EmvApplet;
import javacard.framework.JCSystem;

/**
 * Applet-internal personalization lifecycle.
 *
 * <p>Tracks whether the applet is still being personalized (writes allowed) or has
 * finished personalization (writes rejected with 6985). The transition is triggered
 * by bit 8 of P1 in the last STORE DATA command, per CPS v2.0 §4.3.4 Table 4-9 and
 * §4.3.5.1.
 *
 * <p>This is an applet-internal state, not a GlobalPlatform card content state.
 * The GP API only defines APPLICATION_INSTALLED / APPLICATION_SELECTABLE /
 * APPLICATION_LOCKED for ordinary applets — there is no APPLICATION_PERSONALIZED
 * constant. The "perso done" distinction must therefore be tracked by the applet
 * itself in persistent storage.
 *
 * <p>State is stored in a single persistent byte. Each applet instance (PSE,
 * PaymentApp, PPSE) gets its own AppletLifecycle so they can be personalized
 * independently.
 */
public final class AppletLifecycle {

    /** Initial state — STORE DATA writes are accepted. */
    public static final byte PERSO_PENDING = (byte) 0x01;

    /** Post-finalization state — STORE DATA writes are rejected with 6985. */
    public static final byte PERSO_DONE = (byte) 0x07;

    private final byte[] state;

    public AppletLifecycle() {
        state = new byte[1];
        state[0] = PERSO_PENDING;
    }

    public byte getState() {
        return state[0];
    }

    public boolean isPersoPending() {
        return state[0] == PERSO_PENDING;
    }

    public boolean isPersoDone() {
        return state[0] == PERSO_DONE;
    }

    /**
     * Reject the call with 6985 if personalization has already completed.
     *
     * <p>Inserted at the top of every write entry point (STORE DATA, the dev
     * 80xx commands when not stripped by BuildConfig.PRODUCTION).
     */
    public void requirePersoPending() {
        if (state[0] != PERSO_PENDING) {
            EmvApplet.logAndThrow(PersoSw.SW_PERSO_DONE);
        }
    }

    /**
     * Atomically transition to PERSO_DONE.
     *
     * <p>Called when the last STORE DATA command (P1 bit 8 = 1) is processed
     * successfully. Once committed, no further STORE DATA writes will be accepted.
     */
    public void commitPersonalization() {
        JCSystem.beginTransaction();
        state[0] = PERSO_DONE;
        JCSystem.commitTransaction();
    }

    /**
     * Reset the lifecycle back to PERSO_PENDING.
     *
     * <p>Dev-only path used by the {@code 8005 factoryReset} command. In a
     * production build (BuildConfig.PRODUCTION = true) the dev factoryReset
     * command is stripped, so this method becomes unreachable from outside the
     * applet. It is still used internally by the constructor's first-install
     * initialization.
     */
    public void resetForTesting() {
        JCSystem.beginTransaction();
        state[0] = PERSO_PENDING;
        JCSystem.commitTransaction();
    }
}
