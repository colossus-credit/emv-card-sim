package emvcardsimulator;

import javacard.framework.JCSystem;
import javacard.framework.Util;

/**
 * Persistent record storage indexed by (SFI, recordNumber).
 *
 * <p>Stores raw record body bytes — the contents that go inside the tag-70
 * wrapper, NOT the wrapper itself. Read-side code wraps in tag 70 when sending
 * the READ RECORD response.
 *
 * <p>JavaCard does not support multi-dimensional arrays, so we model the store
 * as a static linked list of {@code RecordStore} nodes — the same pattern
 * {@link EmvTag} uses. Each node holds a single record's {@code (sfi,
 * recordNo, body)} triple plus a {@code next} pointer. Per-SFI preallocation
 * metadata lives in static 1-D arrays indexed by SFI.
 *
 * <p>Record numbering is 1-based per EMV Book 3 §6.5.11. SFI range is 1..30
 * per Book 3 §5.3.2.2 and CPS Annex A.5 Table A-27 (tag 88 = '01'..'1E').
 *
 * <p>Preallocation via {@link #preallocateSfi} is optional — it lets the
 * applet enforce CPS Annex A.5 (Table A-27) bounds (max record size, number
 * of records). If preallocation hasn't happened when {@link #setRecord} is
 * called, the SFI is lazily allocated with default capacity.
 */
public class RecordStore {

    /** Maximum SFI per CPS Annex A.5 Table A-27 ('01' to '1E' = 1..30). */
    public static final byte MAX_SFI = (byte) 30;

    /** Maximum records per SFI in this implementation. */
    public static final byte MAX_RECORDS_PER_SFI = (byte) 16;

    /** Maximum record body length per EMV Book 3 §6.5.11 (Lc 8-bit bound). */
    public static final short MAX_RECORD_BYTES = (short) 254;

    // --- Static linked list head + per-SFI metadata (all 1-D arrays) ---
    private static RecordStore head = null;
    private static byte[] numRecordsPerSfi = new byte[(short) (MAX_SFI + 1)];
    private static short[] maxBytesPerSfi = new short[(short) (MAX_SFI + 1)];

    // --- Per-instance (linked list node) ---
    protected RecordStore next;
    private byte sfi;
    private byte recordNo;
    private byte[] body;

    /**
     * Private constructor — use {@link #setRecord} as the factory entry point.
     */
    private RecordStore(byte sfi, byte recordNo, byte[] src, short srcOff, short len) {
        this.sfi = sfi;
        this.recordNo = recordNo;
        this.body = new byte[len];
        if (len > 0) {
            Util.arrayCopyNonAtomic(src, srcOff, this.body, (short) 0, len);
        }
        this.next = null;
    }

    /**
     * Preallocate storage for an SFI with declared capacity. Called by
     * {@link Dgi0062Parser} for each FCP TLV in DGI 0062.
     *
     * <p>If the SFI is already preallocated, the call replaces the previous
     * declaration (legal during personalization per CPS).
     *
     * @throws javacard.framework.ISOException with 6A80 on out-of-range params
     */
    public static void preallocateSfi(byte sfi, byte numRecords, short maxRecordBytes) {
        if (sfi < 1 || sfi > MAX_SFI) {
            EmvApplet.logAndThrow(PersoSw.SW_INCORRECT_DATA);
        }
        if (numRecords < 1 || numRecords > MAX_RECORDS_PER_SFI) {
            EmvApplet.logAndThrow(PersoSw.SW_INCORRECT_DATA);
        }
        if (maxRecordBytes < 1 || maxRecordBytes > MAX_RECORD_BYTES) {
            EmvApplet.logAndThrow(PersoSw.SW_INCORRECT_DATA);
        }
        JCSystem.beginTransaction();
        numRecordsPerSfi[sfi] = numRecords;
        maxBytesPerSfi[sfi] = maxRecordBytes;
        JCSystem.commitTransaction();
    }

    /**
     * Store a record body. Called by the STORE DATA dispatcher for DGI XXYY
     * where XX = SFI (01..1E) and YY = record number (01..FF).
     *
     * <p>If the SFI was preallocated via {@link #preallocateSfi}, the record
     * number and length are validated against the declared bounds. Otherwise
     * the SFI is lazily allocated with the maximum default capacity.
     *
     * @throws javacard.framework.ISOException with various perso SW codes on
     *     validation failure
     */
    public static void setRecord(byte sfi, byte recordNo, byte[] src, short srcOff, short len) {
        if (sfi < 1 || sfi > MAX_SFI) {
            EmvApplet.logAndThrow(PersoSw.SW_UNRECOGNIZED_DGI);
        }
        if (recordNo < 1) {
            EmvApplet.logAndThrow(PersoSw.SW_INCORRECT_DATA);
        }
        if (len < 0 || len > MAX_RECORD_BYTES) {
            EmvApplet.logAndThrow(PersoSw.SW_INCORRECT_DATA);
        }

        // Lazy SFI allocation if no DGI 0062 was sent for this SFI
        if (numRecordsPerSfi[sfi] == 0) {
            JCSystem.beginTransaction();
            numRecordsPerSfi[sfi] = MAX_RECORDS_PER_SFI;
            maxBytesPerSfi[sfi] = MAX_RECORD_BYTES;
            JCSystem.commitTransaction();
        }

        if (recordNo > numRecordsPerSfi[sfi]) {
            EmvApplet.logAndThrow(PersoSw.SW_INCORRECT_DATA);
        }
        if (len > maxBytesPerSfi[sfi]) {
            EmvApplet.logAndThrow(PersoSw.SW_INCORRECT_DATA);
        }

        // Update existing entry or create new one
        RecordStore existing = findEntry(sfi, recordNo);
        JCSystem.beginTransaction();
        if (existing != null) {
            // Reuse the node but replace its body with a fresh array of the
            // right size. JC has no reliable in-place resize for byte[].
            existing.body = new byte[len];
            if (len > 0) {
                Util.arrayCopyNonAtomic(src, srcOff, existing.body, (short) 0, len);
            }
        } else {
            RecordStore entry = new RecordStore(sfi, recordNo, src, srcOff, len);
            entry.next = head;
            head = entry;
        }
        JCSystem.commitTransaction();
    }

    /**
     * Retrieve a stored record body, or null if not present.
     *
     * @return raw bytes (no tag-70 wrapper) or null
     */
    public static byte[] getRecord(byte sfi, byte recordNo) {
        if (sfi < 1 || sfi > MAX_SFI) {
            return null;
        }
        if (recordNo < 1 || recordNo > numRecordsPerSfi[sfi]) {
            return null;
        }
        RecordStore entry = findEntry(sfi, recordNo);
        return entry != null ? entry.body : null;
    }

    /** Whether an SFI has been preallocated or lazily created. */
    public static boolean hasSfi(byte sfi) {
        if (sfi < 1 || sfi > MAX_SFI) {
            return false;
        }
        return numRecordsPerSfi[sfi] > 0;
    }

    /**
     * Drop all stored records and preallocation metadata. Called from
     * {@code factoryReset()}.
     */
    public static void clearAll() {
        JCSystem.beginTransaction();
        head = null;
        for (short i = (short) 0; i <= (short) MAX_SFI; i++) {
            numRecordsPerSfi[i] = (byte) 0;
            maxBytesPerSfi[i] = (short) 0;
        }
        JCSystem.commitTransaction();
        if (JCSystem.isObjectDeletionSupported()) {
            JCSystem.requestObjectDeletion();
        }
    }

    private static RecordStore findEntry(byte sfi, byte recordNo) {
        for (RecordStore iter = head; iter != null; iter = iter.next) {
            if (iter.sfi == sfi && iter.recordNo == recordNo) {
                return iter;
            }
        }
        return null;
    }
}
