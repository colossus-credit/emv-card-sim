package emvcardsimulator.perso;

import emvcardsimulator.EmvApplet;
import javacard.framework.JCSystem;
import javacard.framework.Util;

/**
 * Persistent record storage indexed by (SFI, recordNumber).
 *
 * <p>Stores raw record body bytes — the contents that go inside the tag-70
 * wrapper, NOT the wrapper itself. Read-side code wraps in tag 70 when sending
 * the READ RECORD response.
 *
 * <p>This replaces the template-indirection approach where the applet stored a
 * list of tag IDs and expanded them at read time by looking each tag up in the
 * EmvTag list. The new design stores actual record bytes, which is what CPS
 * personalization streams (DGI 01XX..1EXX) deliver after stripping the
 * optional tag-70 wrapper.
 *
 * <p>Record numbering is 1-based per EMV Book 3 §6.5.11. SFI range is 1..30 per
 * Book 3 §5.3.2.2 and CPS Annex A.5 Table A-27 (tag 88 = '01'..'1E').
 *
 * <p>Preallocation via {@link #preallocateSfi} is optional — it lets the
 * applet enforce CPS Annex A.5 (Table A-27) bounds (max record size, number of
 * records). If preallocation hasn't happened when {@link #setRecord} is called,
 * the SFI is lazily allocated with default capacity.
 */
public final class RecordStore {

    /** Maximum SFI per CPS Annex A.5 Table A-27 ('01' to '1E' = 1..30). */
    public static final byte MAX_SFI = (byte) 30;

    /** Maximum records per SFI in this implementation. EMV permits up to 16 records per linear-fixed EF. */
    public static final byte MAX_RECORDS_PER_SFI = (byte) 16;

    /** Maximum record body length per EMV Book 3 §6.5.11 (Lc 8-bit bound, leaving room for tag-70 wrapper). */
    public static final short MAX_RECORD_BYTES = (short) 254;

    // SFI 0 is unused (READ RECORD by SFI is 1-based). Indices 1..30 are valid.
    private final byte[][][] records;
    private final byte[] numRecordsPerSfi;
    private final short[] maxBytesPerSfi;

    public RecordStore() {
        records = new byte[MAX_SFI + 1][][];
        numRecordsPerSfi = new byte[MAX_SFI + 1];
        maxBytesPerSfi = new short[MAX_SFI + 1];
    }

    /**
     * Preallocate storage for an SFI with declared capacity. Called by
     * {@link Dgi0062Parser} for each FCP TLV in DGI 0062.
     *
     * <p>If the SFI is already preallocated, the call replaces the previous
     * declaration (legal during personalization per CPS).
     *
     * @throws javacard.framework.ISOException with 6A80 if any parameter is out of range
     */
    public void preallocateSfi(byte sfi, byte numRecords, short maxRecordBytes) {
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
        records[sfi] = new byte[numRecords][];
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
     * @throws javacard.framework.ISOException with various perso SW codes on validation failure
     */
    public void setRecord(byte sfi, byte recordNo, byte[] src, short srcOff, short len) {
        if (sfi < 1 || sfi > MAX_SFI) {
            EmvApplet.logAndThrow(PersoSw.SW_UNRECOGNIZED_DGI);
        }
        if (recordNo < 1) {
            EmvApplet.logAndThrow(PersoSw.SW_INCORRECT_DATA);
        }
        if (len < 0 || len > MAX_RECORD_BYTES) {
            EmvApplet.logAndThrow(PersoSw.SW_INCORRECT_DATA);
        }

        if (records[sfi] == null) {
            // Lazy alloc — no preallocation, accept any (sfi, recordNo) up to limits
            JCSystem.beginTransaction();
            records[sfi] = new byte[MAX_RECORDS_PER_SFI][];
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

        // Atomic write of (size, body) for the record cell
        JCSystem.beginTransaction();
        byte[] body = new byte[len];
        if (len > 0) {
            Util.arrayCopyNonAtomic(src, srcOff, body, (short) 0, len);
        }
        records[sfi][(short) (recordNo - 1)] = body;
        JCSystem.commitTransaction();
    }

    /**
     * Retrieve a stored record body, or null if not present.
     *
     * @return raw bytes (no tag-70 wrapper) or null
     */
    public byte[] getRecord(byte sfi, byte recordNo) {
        if (sfi < 1 || sfi > MAX_SFI) {
            return null;
        }
        if (records[sfi] == null) {
            return null;
        }
        if (recordNo < 1 || recordNo > numRecordsPerSfi[sfi]) {
            return null;
        }
        return records[sfi][(short) (recordNo - 1)];
    }

    /**
     * Whether an SFI has been preallocated or lazily created.
     */
    public boolean hasSfi(byte sfi) {
        if (sfi < 1 || sfi > MAX_SFI) {
            return false;
        }
        return records[sfi] != null;
    }

    /**
     * Drop all stored records. Called from {@code factoryReset()}.
     */
    public void clearAll() {
        JCSystem.beginTransaction();
        for (short i = (short) 0; i <= MAX_SFI; i++) {
            records[i] = null;
            numRecordsPerSfi[i] = (byte) 0;
            maxBytesPerSfi[i] = (short) 0;
        }
        JCSystem.commitTransaction();
        if (JCSystem.isObjectDeletionSupported()) {
            JCSystem.requestObjectDeletion();
        }
    }
}
