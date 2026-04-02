package emvcardsimulator;

import javacard.framework.JCSystem;
import javacard.framework.Util;

public class ApduLog {

    ApduLog next;
    ApduLog previous;
    private static ApduLog head = null;
    static ApduLog tail = null;

    private byte[] data;
    private byte   length;

    private static short maxCount = 20;
    private static short count = 0;

    protected ApduLog(byte[] src, short srcOffset, byte length) {
        data = new byte[(short) (length & 0x00FF)];
        this.length = length;

        // Inline setData to avoid this-escape warning
        Util.arrayCopy(src, srcOffset, data, (short) 0, (short) (this.length & 0x00FF));

        next = null;
        previous = tail;
        if (previous != null) {
            previous.next = this;
        }

        if (head == null) {
            head = this;
        }
        tail = this;
    }

    /**
     * Add APDU log entry.
     */
    public static void addLogEntry(short responseTrailer) {
        Util.setShort(EmvApplet.tmpBuffer, (short) 0, responseTrailer);
        addLogEntry(EmvApplet.tmpBuffer, (short) 0, (byte) 0x02);
    }

    /**
     * Add APDU log entry.
     */
    public static void addLogEntry(byte[] src, short srcOffset, byte length) {
        if (maxCount == (short) 0) {
            return;
        }

        // Only skip internal admin commands (80 01 through 80 0B), not EMV commands like 80 AE
        if (src[srcOffset] == (byte) 0x80 && length >= (byte) 2) {
            byte ins = src[(short)(srcOffset + 1)];
            if (ins >= (byte) 0x01 && ins <= (byte) 0x0B) {
                // Internal admin command - don't log
                return;
            }
        }

        new ApduLog(src, srcOffset, length);
        count += (short) 1;
        if (count > maxCount) {
            ApduLog.removeLog(head);
        }
    }

    /**
     * Remove all stored logs.
     */
    public static short clear() {
        short count = (short) 0;

        for (ApduLog iter = ApduLog.head; iter != null; ) {
            ApduLog removeEntry = iter;
            iter = iter.next;

            if (removeLog(removeEntry)) {
                count++;
            }
        }    

        if (JCSystem.isObjectDeletionSupported()) {
            JCSystem.requestObjectDeletion();
        }

        return count;
    }

    /**
     * Remove log entry.
     */
    public static boolean removeLog(ApduLog logEntry) {
        if (logEntry == null) {
            return false;
        }

        ApduLog previousLogEntry = logEntry.previous;
        ApduLog nextLogEntry = logEntry.next;

        JCSystem.beginTransaction();

        if (head == logEntry) {
            head = nextLogEntry;
        }
        if (tail == logEntry) {
            tail = previousLogEntry;
        }
        if (previousLogEntry != null) {
            previousLogEntry.next = nextLogEntry;
        }
        if (nextLogEntry != null) {
            nextLogEntry.previous = previousLogEntry;
        }

        count -= (short) 1;

        JCSystem.commitTransaction();

        return true;
    }

    /**
     * Set the data/value and length of the tag.
     */
    public final void setData(byte[] src, short srcOffset, byte length) {
        this.length = length;
        Util.arrayCopy(src, srcOffset, data, (short) 0, (short) (this.length & 0x00FF));
    }

    /**
     * Return first ApduLog instance.
     */
    public static ApduLog getHead() {
        return ApduLog.head;
    }

    /**
     * Return next ApduLog instance.
     */
    public ApduLog getNext() {
        return next;
    }

    /**
     * Get tag data/value.
     */
    public byte[] getData() {
        return data;
    }

    /**
     * Get data length.
     */
    public byte getLength() {
        return length;
    }

    /**
     * Copy log data to array.
     */
    public short copyDataToArray(byte[] dst, short dstOffset) {
        short shortLength = (short) (length & 0x00FF);

        Util.arrayCopy(data, (short) 0, dst, dstOffset, shortLength);

        return (short) (dstOffset + shortLength);
    }
}
