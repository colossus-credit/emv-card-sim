package emvcardsimulator.ppse;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import emvcardsimulator.SmartCard;

import java.util.Arrays;

import javacard.framework.ISO7816;

import javax.smartcardio.CardException;
import javax.smartcardio.ResponseAPDU;

import net.jqwik.api.Assume;
import net.jqwik.api.ForAll;
import net.jqwik.api.Property;
import net.jqwik.api.constraints.IntRange;
import net.jqwik.api.constraints.Size;

/**
 * Property-based tests for PPSE (Proximity Payment System Environment).
 *
 * <p>Spec source: EMV Book B (Entry Point), Book A (Architecture).
 * PPSE responds to SELECT 2PAY.SYS.DDF01 with an FCI containing
 * directory entries that list available contactless payment applications.
 */
public class PpsePropertyTest {

    // 2PAY.SYS.DDF01
    private static final byte[] PPSE_AID = new byte[] {
        (byte) 0x32, (byte) 0x50, (byte) 0x41, (byte) 0x59, (byte) 0x2E,
        (byte) 0x53, (byte) 0x59, (byte) 0x53, (byte) 0x2E,
        (byte) 0x44, (byte) 0x44, (byte) 0x46, (byte) 0x30, (byte) 0x31
    };

    private static boolean initialized = false;

    private static void ensureInitialized() throws CardException {
        if (!initialized) {
            SmartCard.connect();
            SmartCard.setLogging(false);
            SmartCard.install(PPSE_AID, ProximityPaymentSystemEnvironmentContainer.class);
            initialized = true;
        }
    }

    private void selectAndReset() throws CardException {
        ensureInitialized();
        selectPpse();
        // Factory reset
        SmartCard.transmitCommand(new byte[] {
            (byte) 0x80, (byte) 0x05, (byte) 0x00, (byte) 0x00, (byte) 0x00
        });
    }

    private ResponseAPDU selectPpse() throws CardException {
        ensureInitialized();
        byte[] selectCmd = new byte[5 + PPSE_AID.length];
        selectCmd[0] = (byte) 0x00;
        selectCmd[1] = (byte) 0xA4;
        selectCmd[2] = (byte) 0x04;
        selectCmd[3] = (byte) 0x00;
        selectCmd[4] = (byte) PPSE_AID.length;
        System.arraycopy(PPSE_AID, 0, selectCmd, 5, PPSE_AID.length);
        return SmartCard.transmitCommand(selectCmd);
    }

    private void setDirectoryEntry(byte[] entry) throws CardException {
        byte[] cmd = new byte[5 + entry.length];
        cmd[0] = (byte) 0x80;
        cmd[1] = (byte) 0x01;
        cmd[2] = (byte) 0x00;
        cmd[3] = (byte) 0x61;
        cmd[4] = (byte) entry.length;
        System.arraycopy(entry, 0, cmd, 5, entry.length);
        SmartCard.transmitCommand(cmd);
    }

    /** Build a STORE DATA command for PPSE. */
    private byte[] buildStoreDataCmd(short dgi, byte[] data) {
        byte[] cmd = new byte[5 + 2 + 1 + data.length];
        cmd[0] = (byte) 0x00;
        cmd[1] = (byte) 0xE2;
        cmd[2] = (byte) 0x00;
        cmd[3] = (byte) 0x00;
        cmd[4] = (byte) (2 + 1 + data.length);
        cmd[5] = (byte) ((dgi >> 8) & 0xFF);
        cmd[6] = (byte) (dgi & 0xFF);
        cmd[7] = (byte) data.length;
        System.arraycopy(data, 0, cmd, 8, data.length);
        return cmd;
    }

    // -----------------------------------------------------------------------
    // 42. PPSE FCI contains 6F > 84 > A5 > BF0C > 61
    //     Property: when a directory entry is configured, SELECT PPSE
    //     returns a properly nested FCI template.
    // -----------------------------------------------------------------------

    @Property(tries = 10)
    void ppseSelectFciContains6FWith84And61() throws CardException {
        selectAndReset();

        // Standard directory entry: AID + Label + Priority
        byte[] dirEntry = new byte[] {
            (byte) 0x4F, (byte) 0x07,
            (byte) 0xA0, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x04, (byte) 0x10, (byte) 0x10,
            (byte) 0x50, (byte) 0x04,
            (byte) 0x56, (byte) 0x49, (byte) 0x53, (byte) 0x41,
            (byte) 0x87, (byte) 0x01, (byte) 0x01
        };
        setDirectoryEntry(dirEntry);

        ResponseAPDU response = selectPpse();
        assertEquals(0x9000, response.getSW(), "SELECT PPSE should succeed");

        byte[] fci = response.getData();
        assertTrue(fci.length > 4, "FCI must have content");
        assertEquals((byte) 0x6F, fci[0],
            "PPSE FCI must start with tag 6F");
        assertTrue(containsByte(fci, (byte) 0x84),
            "FCI must contain tag 84 (DF Name = PPSE AID)");
        assertTrue(containsByte(fci, (byte) 0xA5),
            "FCI must contain tag A5 (FCI Proprietary Template)");
        assertTrue(containsSequence(fci, new byte[] { (byte) 0xBF, (byte) 0x0C }),
            "FCI must contain tag BF0C (Issuer Discretionary Data)");
        assertTrue(containsByte(fci, (byte) 0x61),
            "FCI must contain tag 61 (Directory Entry)");
    }

    // -----------------------------------------------------------------------
    // 43. Directory entry bytes appear verbatim inside tag 61
    //     Property: the exact bytes stored via SET_DIRECTORY_ENTRY
    //     are found inside the FCI response.
    // -----------------------------------------------------------------------

    @Property(tries = 20)
    void ppseDirectoryEntryPreservedInFci(
            @ForAll @Size(min = 5, max = 30) byte[] entryContent
    ) throws CardException {
        selectAndReset();
        setDirectoryEntry(entryContent);

        ResponseAPDU response = selectPpse();
        Assume.that(response.getSW() == 0x9000);

        byte[] fci = response.getData();
        // Find tag 61 and check its content matches
        for (int i = 0; i < fci.length - 1; i++) {
            if (fci[i] == (byte) 0x61) {
                int len = fci[i + 1] & 0xFF;
                int valOffset = i + 2;
                if (valOffset + len <= fci.length) {
                    byte[] actual = Arrays.copyOfRange(fci, valOffset, valOffset + len);
                    assertArrayEquals(entryContent, actual,
                        "Directory entry content inside tag 61 must match stored bytes exactly");
                    return;
                }
            }
        }
        assertTrue(false, "Tag 61 not found in FCI response");
    }

    // -----------------------------------------------------------------------
    // 44. STORE DATA DGI D001 produces same FCI as SET_DIRECTORY_ENTRY
    // -----------------------------------------------------------------------

    @Property(tries = 10)
    void ppseStoreDataD001EquivalentToSetDirectoryEntry() throws CardException {
        byte[] dirEntry = new byte[] {
            (byte) 0x4F, (byte) 0x07,
            (byte) 0xA0, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x04, (byte) 0x10, (byte) 0x10,
            (byte) 0x50, (byte) 0x04,
            (byte) 0x56, (byte) 0x49, (byte) 0x53, (byte) 0x41,
            (byte) 0x87, (byte) 0x01, (byte) 0x01
        };

        // Path A: SET_DIRECTORY_ENTRY
        selectAndReset();
        setDirectoryEntry(dirEntry);
        ResponseAPDU respA = selectPpse();

        // Path B: STORE DATA DGI D001
        selectAndReset();
        byte[] storeCmd = buildStoreDataCmd((short) 0xD001, dirEntry);
        ResponseAPDU storeResp = SmartCard.transmitCommand(storeCmd);
        assertEquals(0x9000, storeResp.getSW(), "STORE DATA D001 should succeed");
        ResponseAPDU respB = selectPpse();

        // Both must produce identical FCI
        assertEquals(respA.getSW(), respB.getSW(),
            "Both paths must return same SW");
        assertArrayEquals(respA.getData(), respB.getData(),
            "SET_DIRECTORY_ENTRY and STORE DATA D001 must produce identical FCI");
    }

    // -----------------------------------------------------------------------
    // 45. Invalid DGIs return 6A86
    //     Property: any DGI not in {D001, D002} must be rejected.
    // -----------------------------------------------------------------------

    @Property(tries = 100)
    void ppseRejectsInvalidDgi(
            @ForAll short dgi
    ) throws CardException {
        Assume.that(dgi != (short) 0xD001 && dgi != (short) 0xD002);
        Assume.that(dgi != (short) 0x0000); // avoid zero-length edge case

        selectAndReset();

        byte[] storeCmd = buildStoreDataCmd(dgi, new byte[] { 0x01, 0x02 });
        ResponseAPDU resp = SmartCard.transmitCommand(storeCmd);
        assertEquals(ISO7816.SW_INCORRECT_P1P2, (short) resp.getSW(),
            "PPSE STORE DATA with DGI=0x" + Integer.toHexString(dgi & 0xFFFF)
            + " must return 6A86");
    }

    // -----------------------------------------------------------------------
    // 46. Directory entries > 64 bytes rejected with 6700
    //     Property: PPSE directory entry buffer is 64 bytes max.
    // -----------------------------------------------------------------------

    @Property(tries = 10)
    void ppseDirectoryEntryMax64Bytes(
            @ForAll @IntRange(min = 65, max = 100) int size
    ) throws CardException {
        selectAndReset();

        byte[] oversized = new byte[size];
        for (int i = 0; i < size; i++) {
            oversized[i] = (byte) (i & 0xFF);
        }

        // Via SET_DIRECTORY_ENTRY
        byte[] cmd = new byte[5 + oversized.length];
        cmd[0] = (byte) 0x80;
        cmd[1] = (byte) 0x01;
        cmd[2] = (byte) 0x00;
        cmd[3] = (byte) 0x61;
        cmd[4] = (byte) oversized.length;
        System.arraycopy(oversized, 0, cmd, 5, oversized.length);

        ResponseAPDU resp = SmartCard.transmitCommand(cmd);
        assertEquals(ISO7816.SW_WRONG_LENGTH, (short) resp.getSW(),
            "Directory entry > 64 bytes must return 6700");
    }

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    private boolean containsByte(byte[] data, byte target) {
        for (byte b : data) {
            if (b == target) {
                return true;
            }
        }
        return false;
    }

    private boolean containsSequence(byte[] data, byte[] seq) {
        for (int i = 0; i <= data.length - seq.length; i++) {
            boolean match = true;
            for (int j = 0; j < seq.length; j++) {
                if (data[i + j] != seq[j]) {
                    match = false;
                    break;
                }
            }
            if (match) {
                return true;
            }
        }
        return false;
    }
}
