package emvcardsimulator;

/**
 * Status word constants from EMV Card Personalization Specification v2.0.
 *
 * <p>Sources:
 * <ul>
 *   <li>Table 4-10 (STORE DATA status conditions)
 *   <li>§4.3.5.1 (last STORE DATA transition)
 *   <li>§4.3.5.4 (post-perso STORE DATA disabled)
 *   <li>§5.4.2.3 (unrecognised DGI)
 * </ul>
 */
public final class PersoSw {

    /** §5.4.2.3 — IC card application does not recognise the DGI. */
    public static final short SW_UNRECOGNIZED_DGI = (short) 0x6A88;

    /** §4.3.5.1 — last STORE DATA arrived but conditions to transition to PERSONALIZED are not satisfied. */
    public static final short SW_PERSO_NOT_COMPLETE = (short) 0x6A86;

    /** Table 4-10 — incorrect parameters in the data field (malformed DGI 0062, oversized record). */
    public static final short SW_INCORRECT_DATA = (short) 0x6A80;

    /** §4.3.5.4 — STORE DATA acceptance disabled after successful personalisation. */
    public static final short SW_PERSO_DONE = (short) 0x6985;

    /** Standard ISO 7816-4 — referenced record not found. */
    public static final short SW_RECORD_NOT_FOUND = (short) 0x6A83;

    /** Standard ISO 7816-4 — referenced file not found. */
    public static final short SW_FILE_NOT_FOUND = (short) 0x6A82;

    private PersoSw() {
        // utility class
    }
}
