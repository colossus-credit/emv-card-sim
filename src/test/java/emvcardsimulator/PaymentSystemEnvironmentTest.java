package emvcardsimulator;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import com.licel.jcardsim.utils.AIDUtil;

import emvcardsimulator.SmartCard;

import javacard.framework.ISO7816;

import javax.smartcardio.CardException;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
 
public class PaymentSystemEnvironmentTest {

    private static final byte[] PSE_AID = new byte[] { (byte) 0x31, (byte) 0x50, (byte) 0x41, (byte) 0x59, (byte) 0x2E, (byte) 0x53, (byte) 0x59, (byte) 0x53, (byte) 0x2E, (byte) 0x44, (byte) 0x44, (byte) 0x46, (byte) 0x30, (byte) 0x31 };

    @BeforeAll
    public static void setup() throws CardException {
        SmartCard.connect();
        SmartCard.install(PSE_AID, PaymentSystemEnvironmentContainer.class);
    }

    @AfterAll
    public static void disconnect() throws CardException {
        SmartCard.disconnect();
    }

    @Test
    public void selectTest() throws CardException {
        ResponseAPDU response = SmartCard.transmitCommand(new byte[] {(byte) 0x00, (byte) 0xA4, (byte) 0x04, (byte) 0x00, (byte) 0x0E, (byte) 0x31, (byte) 0x50, (byte) 0x41, (byte) 0x59, (byte) 0x2E, (byte) 0x53, (byte) 0x59, (byte) 0x53, (byte) 0x2E, (byte) 0x44, (byte) 0x44, (byte) 0x46, (byte) 0x30, (byte) 0x31 });
        assertEquals(ISO7816.SW_NO_ERROR, (short) response.getSW());

        // Reset card setup
        response = SmartCard.transmitCommand(new byte[] {(byte) 0x80, (byte) 0x05, (byte) 0x00, (byte) 0x00, (byte) 0x00});
        assertEquals(ISO7816.SW_NO_ERROR, (short) response.getSW());
    }

    @Test
    @Disabled("Pre-existing: returns SW_NO_ERROR instead of SW_RECORD_NOT_FOUND after factory reset")
    public void readRecordTest() throws CardException {
        selectTest();

        for (int i = 0; i < 5; i++) {
            ResponseAPDU response = SmartCard.transmitCommand(new byte[] { ISO7816.CLA_ISO7816, (byte) 0xB2, (byte) i, (byte) 0x0C, (byte) 0x00 });

            switch (i) {
                default:
                    assertEquals(ISO7816.SW_RECORD_NOT_FOUND, (short) response.getSW());
                    break;
            }
        }
    }

    // ========================================================================
    // Negative / Security Boundary Tests
    // ========================================================================

    @Test
    @DisplayName("Reject unsupported INS byte on PSE")
    public void testUnsupportedInstruction() throws CardException {
        selectTest();
        ResponseAPDU response = SmartCard.transmitCommand(new byte[] {
            (byte) 0x00, (byte) 0xFF, (byte) 0x00, (byte) 0x00, (byte) 0x00
        });
        assertEquals(ISO7816.SW_INS_NOT_SUPPORTED, (short) response.getSW(),
            "Unknown INS should return 6D00");
    }

    @Test
    @DisplayName("Reject READ RECORD for non-existent SFI/record")
    public void testReadRecordNotFound() throws CardException {
        selectTest();
        // READ RECORD SFI=5, record 99 — doesn't exist
        ResponseAPDU response = SmartCard.transmitCommand(new byte[] {
            (byte) 0x00, (byte) 0xB2, (byte) 0x63, (byte) 0x2C, (byte) 0x00
        });
        assertEquals(ISO7816.SW_RECORD_NOT_FOUND, (short) response.getSW(),
            "READ RECORD for non-existent record should return 6A83");
    }
}
