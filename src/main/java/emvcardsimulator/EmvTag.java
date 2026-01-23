package emvcardsimulator;

import javacard.framework.JCSystem;
import javacard.framework.Util;

public class EmvTag {

    protected EmvTag next;
    protected EmvTag previous;
    private static EmvTag head = null;
    private static EmvTag tail = null;

    private byte[] tag;
    private byte[] data;
    private short  length;

    public byte fuzzOffset      = (byte) 0x00;
    public byte fuzzLength      = (byte) 0x00;
    public byte fuzzFlags       = (byte) 0x00;
    public byte fuzzOccurrence  = (byte) 0x00;

    protected EmvTag(short tagId, byte[] src, short srcOffset, short length) {
        tag = new byte[2];
        data = new byte[300];  // Increased for RSA-2048 certificates (256 bytes)
        this.length = length;

        Util.setShort(tag, (short) 0, tagId);
        if (this.length != 0) {
            setData(src, srcOffset, this.length);
        }

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
     * Add or update BER-TLV EMV tag to memory.
     */
    public static EmvTag setTag(short tagId, byte[] src, short srcOffset, short length) {
        EmvTag tag = EmvTag.findTag(tagId);
        if (tag == null) {
            tag = new EmvTag(tagId, src, srcOffset, length);
        } else {
            tag.setData(src, srcOffset, length);
        }

        return tag;
    }

    /**
     * Find BER-TLV EMV tag.
     */
    public static EmvTag findTag(short tag) {
        for (EmvTag iter = EmvTag.head; iter != null; iter = iter.next) {
            short iterTag = Util.getShort(iter.tag, (short) 0);
            if (tag == iterTag) {
                return iter;
            }
        }

        return null;
    }

    /**
     * Remove all stored tags.
     */
    public static short clear() {
        short count = (short) 0;

        for (EmvTag iter = EmvTag.head; iter != null; ) {
            short iterTag = Util.getShort(iter.tag, (short) 0);

            iter = iter.next;

            if (removeTag(iterTag)) {
                count++;
            }
        }    

        if (JCSystem.isObjectDeletionSupported()) {
            JCSystem.requestObjectDeletion();
        }

        return count;
    }

    /**
     * Clear all fuzz settings.
     */
    public static void clearFuzz() {
        for (EmvTag iter = EmvTag.head; iter != null; iter = iter.next) {            
            iter.fuzzOffset      = (byte) 0x00;
            iter.fuzzLength      = (byte) 0x00;
            iter.fuzzFlags       = (byte) 0x00;
            iter.fuzzOccurrence  = (byte) 0x00;
        }
    }

    /**
     * Remove tag.
     */
    public static boolean removeTag(short tagId) {
        EmvTag tag = findTag(tagId);
        if (tag == null) {
            return false;
        }

        EmvTag previousTag = tag.previous;
        EmvTag nextTag = tag.next;

        JCSystem.beginTransaction();

        if (head == tag) {
            head = nextTag;
        }
        if (tail == tag) {
            tail = previousTag;
        }
        if (previousTag != null) {
            previousTag.next = nextTag;
        }
        if (nextTag != null) {
            nextTag.previous = previousTag;
        }

        JCSystem.commitTransaction();

        return true;
    }

    /**
     * Set the data/value and length of the tag.
     * Uses byte-by-byte copy for T=0 compatibility.
     */
    public void setData(byte[] src, short srcOffset, short length) {
        this.length = length;
        // Byte-by-byte copy for T=0 compatibility instead of Util.arrayCopy
        for (short i = 0; i < this.length; i++) {
            data[i] = src[(short)(srcOffset + i)];
        }
    }

    /**
     * Return first EmvTag instance.
     */
    public static EmvTag getHead() {
        return EmvTag.head;
    }

    /**
     * Return next EmvTag instance.
     */
    public EmvTag getNext() {
        return next;
    }

    /**
     * Get tag name.
     */
    public byte[] getTag() {
        return tag;
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
    public short getLength() {
        return length;
    }

    /**
     * Serialize tag as BER-TLV to array.
     * Uses byte-by-byte copy for T=0 compatibility.
     */
    public short copyToArray(byte[] dst, short dstOffset) {
        short copyOffset = dstOffset;

        if (tag[0] == (byte) 0x00) {
            // Single byte tag - copy byte-by-byte for T=0 compatibility
            dst[dstOffset] = tag[1];
            copyOffset += (short) 1;
        } else {
            // Two byte tag - copy byte-by-byte for T=0 compatibility
            dst[dstOffset] = tag[0];
            dst[(short)(dstOffset + 1)] = tag[1];
            copyOffset += (short) 2;
        }

        // TLV length encoding
        if (length > 255) {
            // 82 XX XX format for lengths > 255
            dst[copyOffset] = (byte) 0x82;
            dst[(short)(copyOffset + 1)] = (byte) ((length >> 8) & 0xFF);
            dst[(short)(copyOffset + 2)] = (byte) (length & 0xFF);
            copyOffset += (short) 3;
        } else if (length >= 128) {
            // 81 XX format for lengths 128-255
            dst[copyOffset] = (byte) 0x81;
            dst[(short)(copyOffset + 1)] = (byte) (length & 0xFF);
            copyOffset += (short) 2;
        } else {
            // Single byte for lengths < 128
            dst[copyOffset] = (byte) (length & 0xFF);
            copyOffset += (short) 1;
        }
        copyOffset = copyDataToArray(dst, copyOffset);

        // Note: Fuzz length override not implemented for extended length encoding
        // TODO: Implement fuzz length handling for TLV length > 127

        return copyOffset;
    }

    /**
     * Serialize tag's data to array, i.e. no BER-TLV header.
     * Uses byte-by-byte copy for T=0 compatibility.
     */
    public short copyDataToArray(byte[] dst, short dstOffset) {
        // Byte-by-byte copy for T=0 compatibility instead of Util.arrayCopy
        for (short i = 0; i < length; i++) {
            dst[(short)(dstOffset + i)] = data[i];
        }

        short copyLength = length;
        if (fuzzLength > (byte) 0x00) {
            byte doFuzzing = (byte) 0x00;

            if (fuzzOccurrence > (byte) 0x00) {
                EmvApplet.randomData.generateData(EmvApplet.tmpBuffer, (short) 0, (short) 1);
                doFuzzing = (byte) (EmvApplet.tmpBuffer[(short) 0] % fuzzOccurrence);
            }

            if (doFuzzing == (byte) 0x00) {
                EmvApplet.randomData.generateData(dst, (short) (dstOffset + (fuzzOffset & 0x00FF)), (short) (fuzzLength & 0x00FF));

                if ((short)((fuzzLength & 0xFF) + (fuzzOffset & 0xFF)) > copyLength) {
                    copyLength = (short) ((fuzzLength & 0x00FF) + (fuzzOffset & 0x00FF));
                }
            }
        }

        return (short) (dstOffset + copyLength);
    }
}
