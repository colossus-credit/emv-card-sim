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
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
 
public class PaymentApplicationTest {
    private static final byte[] APPLET_AID = new byte[] { (byte) 0xAF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0x12, (byte) 0x34 };

    @BeforeAll
    public static void setup() throws CardException {
        SmartCard.connect();
        SmartCard.install(APPLET_AID, PaymentApplicationContainer.class);
    }

    @AfterAll
    public static void disconnect() throws CardException {
        SmartCard.disconnect();
    }

    @Test
    public void selectTest() throws CardException {
        ResponseAPDU response = SmartCard.transmitCommand(new byte[] { (byte) 0x00, (byte) 0xA4, (byte) 0x04, (byte) 0x00, (byte) 0x07, (byte) 0xAF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0x12, (byte) 0x34 });
        assertEquals(ISO7816.SW_NO_ERROR, (short) response.getSW());

        // Reset card setup
        response = SmartCard.transmitCommand(new byte[] {(byte) 0x80, (byte) 0x05, (byte) 0x00, (byte) 0x00, (byte) 0x00});
        assertEquals(ISO7816.SW_NO_ERROR, (short) response.getSW());
    }

    // ========================================================================
    // Negative / Security Boundary Tests
    // ========================================================================

    @Test
    @DisplayName("Reject unsupported INS byte")
    public void testUnsupportedInstruction() throws CardException {
        selectTest();
        ResponseAPDU response = SmartCard.transmitCommand(new byte[] {
            (byte) 0x00, (byte) 0xFF, (byte) 0x00, (byte) 0x00, (byte) 0x00
        });
        assertEquals(ISO7816.SW_INS_NOT_SUPPORTED, (short) response.getSW(),
            "Unknown INS should return 6D00");
    }

    @Test
    @DisplayName("Reject GPO with wrong P1P2")
    public void testGpoWrongP1P2() throws CardException {
        selectTest();
        ResponseAPDU response = SmartCard.transmitCommand(new byte[] {
            (byte) 0x80, (byte) 0xA8, (byte) 0x01, (byte) 0x01,
            (byte) 0x02, (byte) 0x83, (byte) 0x00
        });
        assertEquals(ISO7816.SW_INCORRECT_P1P2, (short) response.getSW(),
            "GPO with wrong P1P2 should return 6A86");
    }

    @Test
    @DisplayName("Reject GET RESPONSE when no pending data")
    public void testGetResponseNoPendingData() throws CardException {
        selectTest();
        ResponseAPDU response = SmartCard.transmitCommand(new byte[] {
            (byte) 0x00, (byte) 0xC0, (byte) 0x00, (byte) 0x00, (byte) 0x00
        });
        assertEquals((short) 0x6985, (short) response.getSW(),
            "GET RESPONSE without pending data should return 6985");
    }
}
