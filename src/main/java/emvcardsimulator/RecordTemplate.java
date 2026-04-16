package emvcardsimulator;

import javacard.framework.JCSystem;

/**
 * A record template holding direct EmvTag references for O(1) READ RECORD.
 *
 * <p>Instead of storing tag IDs and re-walking the EmvTag linked list at
 * READ RECORD time, each template stores an array of EmvTag object pointers.
 * Since setData() modifies the EmvTag node in place, dynamic tags (9F6E, ATC)
 * are automatically resolved to their current value.
 *
 * <p>Templates are stored in a static linked list keyed by the canonical
 * record key: (recordNo &lt;&lt; 8) | (SFI &lt;&lt; 3).
 */
public class RecordTemplate {

    private static RecordTemplate head = null;

    private RecordTemplate next;
    private short recordKey;
    private EmvTag[] tags;
    private short tagCount;

    private RecordTemplate(short recordKey, EmvTag[] tags, short tagCount) {
        this.recordKey = recordKey;
        this.tags = tags;
        this.tagCount = tagCount;

        // Prepend to list (most recently stored records tend to be read first)
        this.next = head;
        head = this;
    }

    /**
     * Store or update a record template with direct EmvTag references.
     *
     * @param recordKey canonical key: (recordNo &lt;&lt; 8) | (SFI &lt;&lt; 3)
     * @param tagRefs   array of resolved EmvTag references
     * @param count     number of valid entries in tagRefs
     */
    public static void setTemplate(short recordKey, EmvTag[] tagRefs, short count) {
        RecordTemplate existing = findTemplate(recordKey);
        if (existing != null) {
            // Re-use existing node — update refs in place
            if (count > (short) existing.tags.length) {
                existing.tags = new EmvTag[count];
            }
            existing.tagCount = count;
            for (short i = 0; i < count; i++) {
                existing.tags[i] = tagRefs[i];
            }
        } else {
            // Allocate a right-sized copy
            EmvTag[] copy = new EmvTag[count];
            for (short i = 0; i < count; i++) {
                copy[i] = tagRefs[i];
            }
            new RecordTemplate(recordKey, copy, count);
        }
    }

    /**
     * Find a record template by canonical record key.
     * O(m) where m = number of records (typically 5-10, much smaller than
     * the full EmvTag list of 60+).
     */
    public static RecordTemplate findTemplate(short recordKey) {
        for (RecordTemplate iter = head; iter != null; iter = iter.next) {
            if (iter.recordKey == recordKey) {
                return iter;
            }
        }
        return null;
    }

    /**
     * Expand this template into a TLV byte array by serializing each
     * referenced tag's current value. Returns the total bytes written.
     */
    public short expandToArray(byte[] dst, short dstOffset) {
        short pos = dstOffset;
        for (short i = 0; i < tagCount; i++) {
            pos = tags[i].copyToArray(dst, pos);
        }
        return pos;
    }

    /**
     * Remove all record templates (called by factoryReset).
     */
    public static void clearAll() {
        head = null;
        if (JCSystem.isObjectDeletionSupported()) {
            JCSystem.requestObjectDeletion();
        }
    }
}
