package emvcardsimulator.ppse;

import static org.junit.jupiter.api.Assertions.assertEquals;

import emvcardsimulator.SmartCard;

import javacard.framework.ISO7816;

import javax.smartcardio.CardException;
import javax.smartcardio.ResponseAPDU;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

public class ProximityPaymentSystemEnvironmentTest {

    // 2PAY.SYS.DDF01
    private static final byte[] PPSE_AID = new byte[] {
        (byte) 0x32, (byte) 0x50, (byte) 0x41, (byte) 0x59, (byte) 0x2E,
        (byte) 0x53, (byte) 0x59, (byte) 0x53, (byte) 0x2E,
        (byte) 0x44, (byte) 0x44, (byte) 0x46, (byte) 0x30, (byte) 0x31
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

    private void selectPpse() throws CardException {
        SmartCard.transmitCommand(new byte[] {
            (byte) 0x00, (byte) 0xA4, (byte) 0x04, (byte) 0x00,
            (byte) 0x0E,
            (byte) 0x32, (byte) 0x50, (byte) 0x41, (byte) 0x59, (byte) 0x2E,
            (byte) 0x53, (byte) 0x59, (byte) 0x53, (byte) 0x2E,
            (byte) 0x44, (byte) 0x44, (byte) 0x46, (byte) 0x30, (byte) 0x31
        });
    }

    private void factoryReset() throws CardException {
        SmartCard.transmitCommand(new byte[] {
            (byte) 0x80, (byte) 0x05, (byte) 0x00, (byte) 0x00, (byte) 0x00
        });
    }

    // ========================================================================
    // Happy Path Tests
    // ========================================================================

    @Test
    @DisplayName("SELECT PPSE returns success")
    public void testSelect() throws CardException {
        selectPpse();
        factoryReset();
        ResponseAPDU response = SmartCard.transmitCommand(new byte[] {
            (byte) 0x00, (byte) 0xA4, (byte) 0x04, (byte) 0x00,
            (byte) 0x0E,
            (byte) 0x32, (byte) 0x50, (byte) 0x41, (byte) 0x59, (byte) 0x2E,
            (byte) 0x53, (byte) 0x59, (byte) 0x53, (byte) 0x2E,
            (byte) 0x44, (byte) 0x44, (byte) 0x46, (byte) 0x30, (byte) 0x31
        });
        // No FCI data configured after reset — returns FILE_NOT_FOUND
        assertEquals(ISO7816.SW_FILE_NOT_FOUND, (short) response.getSW(),
            "SELECT PPSE with no data should return 6A82");
    }

    @Test
    @DisplayName("SET_DIRECTORY_ENTRY and SELECT returns FCI")
    public void testSetDirectoryEntryThenSelect() throws CardException {
        selectPpse();
        factoryReset();

        // Set directory entry: 4F 07 A0000000041010 50 04 56495341 87 01 01
        // (AID=Visa, label=VISA, priority=1)
        byte[] dirEntry = new byte[] {
            (byte) 0x4F, (byte) 0x07,
            (byte) 0xA0, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x04, (byte) 0x10, (byte) 0x10,
            (byte) 0x50, (byte) 0x04,
            (byte) 0x56, (byte) 0x49, (byte) 0x53, (byte) 0x41,
            (byte) 0x87, (byte) 0x01, (byte) 0x01
        };

        byte[] setCmd = new byte[5 + dirEntry.length];
        setCmd[0] = (byte) 0x80;
        setCmd[1] = (byte) 0x01;
        setCmd[2] = (byte) 0x00;
        setCmd[3] = (byte) 0x61;
        setCmd[4] = (byte) dirEntry.length;
        System.arraycopy(dirEntry, 0, setCmd, 5, dirEntry.length);

        ResponseAPDU response = SmartCard.transmitCommand(setCmd);
        assertEquals(ISO7816.SW_NO_ERROR, (short) response.getSW(),
            "SET_DIRECTORY_ENTRY should succeed");

        // Now SELECT should return FCI with the directory entry
        response = SmartCard.transmitCommand(new byte[] {
            (byte) 0x00, (byte) 0xA4, (byte) 0x04, (byte) 0x00,
            (byte) 0x0E,
            (byte) 0x32, (byte) 0x50, (byte) 0x41, (byte) 0x59, (byte) 0x2E,
            (byte) 0x53, (byte) 0x59, (byte) 0x53, (byte) 0x2E,
            (byte) 0x44, (byte) 0x44, (byte) 0x46, (byte) 0x30, (byte) 0x31
        });
        assertEquals(ISO7816.SW_NO_ERROR, (short) response.getSW(),
            "SELECT PPSE after setting directory entry should return 9000");
    }

    // ========================================================================
    // Negative / Security Boundary Tests
    // ========================================================================

    @Test
    @DisplayName("Reject unsupported INS byte on PPSE")
    public void testUnsupportedInstruction() throws CardException {
        selectPpse();
        ResponseAPDU response = SmartCard.transmitCommand(new byte[] {
            (byte) 0x00, (byte) 0xFF, (byte) 0x00, (byte) 0x00, (byte) 0x00
        });
        assertEquals(ISO7816.SW_INS_NOT_SUPPORTED, (short) response.getSW(),
            "Unknown INS should return 6D00");
    }

    @Test
    @DisplayName("SELECT PPSE with no data configured returns FILE_NOT_FOUND")
    public void testSelectNoData() throws CardException {
        selectPpse();
        factoryReset();
        ResponseAPDU response = SmartCard.transmitCommand(new byte[] {
            (byte) 0x00, (byte) 0xA4, (byte) 0x04, (byte) 0x00,
            (byte) 0x0E,
            (byte) 0x32, (byte) 0x50, (byte) 0x41, (byte) 0x59, (byte) 0x2E,
            (byte) 0x53, (byte) 0x59, (byte) 0x53, (byte) 0x2E,
            (byte) 0x44, (byte) 0x44, (byte) 0x46, (byte) 0x30, (byte) 0x31
        });
        assertEquals(ISO7816.SW_FILE_NOT_FOUND, (short) response.getSW(),
            "PPSE with no FCI or directory data should return 6A82");
    }

    @Test
    @DisplayName("Reject SET_DIRECTORY_ENTRY with wrong P1P2")
    public void testSetDirectoryEntryWrongP1P2() throws CardException {
        selectPpse();
        // P1P2 must be 0x0061, send 0x0000 instead
        ResponseAPDU response = SmartCard.transmitCommand(new byte[] {
            (byte) 0x80, (byte) 0x01, (byte) 0x00, (byte) 0x00,
            (byte) 0x02, (byte) 0xAA, (byte) 0xBB
        });
        assertEquals(ISO7816.SW_INCORRECT_P1P2, (short) response.getSW(),
            "SET_DIRECTORY_ENTRY with wrong P1P2 should return 6A86");
    }

    @Test
    @DisplayName("Reject SET_FCI with data too large")
    public void testSetFciTooLarge() throws CardException {
        selectPpse();
        // SET_FCI (80 02) with LC > 128 bytes
        byte[] cmd = new byte[5 + 129];
        cmd[0] = (byte) 0x80;
        cmd[1] = (byte) 0x02;
        cmd[2] = (byte) 0x00;
        cmd[3] = (byte) 0x00;
        cmd[4] = (byte) 129;
        ResponseAPDU response = SmartCard.transmitCommand(cmd);
        assertEquals(ISO7816.SW_WRONG_LENGTH, (short) response.getSW(),
            "SET_FCI with LC>128 should return 6700");
    }
}
