package emvcardsimulator;

import static org.junit.jupiter.api.Assertions.*;

import javacard.framework.ISO7816;

import javax.smartcardio.CardException;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;

/**
 * Test to verify SDAD (9F4B) length is exactly 256 bytes for RSA-2048.
 * Uses the exact CDOL data from the terminal log.
 */
public class SdadLengthTest {
    private static final byte[] COLOSSUS_AID = new byte[] {
        (byte) 0xA0, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x09, (byte) 0x51
    };

    // RSA-2048 modulus (256 bytes) - from ColossusPaymentApplicationTest
    private static final byte[] RSA_2048_MODULUS = new byte[] {
        (byte) 0xB4, (byte) 0xB4, (byte) 0x58, (byte) 0x78, (byte) 0x31, (byte) 0x29, (byte) 0x27, (byte) 0x92,
        (byte) 0xEE, (byte) 0x57, (byte) 0x5D, (byte) 0x28, (byte) 0x4C, (byte) 0xCB, (byte) 0x40, (byte) 0xA9,
        (byte) 0x09, (byte) 0x4A, (byte) 0xD2, (byte) 0x02, (byte) 0x9D, (byte) 0xC4, (byte) 0x56, (byte) 0x55,
        (byte) 0x35, (byte) 0x9C, (byte) 0x57, (byte) 0x73, (byte) 0x5B, (byte) 0x09, (byte) 0xA8, (byte) 0xAF,
        (byte) 0x58, (byte) 0xDC, (byte) 0x32, (byte) 0x26, (byte) 0x47, (byte) 0x57, (byte) 0xCC, (byte) 0xB4,
        (byte) 0x07, (byte) 0x11, (byte) 0xA5, (byte) 0xB5, (byte) 0x7B, (byte) 0xAA, (byte) 0x58, (byte) 0x64,
        (byte) 0x23, (byte) 0x3A, (byte) 0x3F, (byte) 0x0B, (byte) 0xD3, (byte) 0x05, (byte) 0x71, (byte) 0x55,
        (byte) 0xB9, (byte) 0x8E, (byte) 0x8D, (byte) 0xA1, (byte) 0x30, (byte) 0x8D, (byte) 0xBA, (byte) 0x9D,
        (byte) 0x36, (byte) 0xF8, (byte) 0x1F, (byte) 0x18, (byte) 0x7D, (byte) 0x9D, (byte) 0x2A, (byte) 0xBF,
        (byte) 0xBA, (byte) 0xFE, (byte) 0x2F, (byte) 0xC0, (byte) 0x94, (byte) 0xF0, (byte) 0x17, (byte) 0x94,
        (byte) 0x1A, (byte) 0x9D, (byte) 0x8A, (byte) 0x94, (byte) 0x13, (byte) 0x22, (byte) 0x27, (byte) 0x00,
        (byte) 0xA5, (byte) 0x59, (byte) 0x63, (byte) 0x2C, (byte) 0xF1, (byte) 0xDB, (byte) 0x24, (byte) 0xCD,
        (byte) 0x89, (byte) 0xB8, (byte) 0x91, (byte) 0xE7, (byte) 0x2F, (byte) 0x73, (byte) 0xD4, (byte) 0x85,
        (byte) 0xE3, (byte) 0xD1, (byte) 0x49, (byte) 0x25, (byte) 0x82, (byte) 0xF6, (byte) 0x42, (byte) 0x5F,
        (byte) 0x98, (byte) 0x15, (byte) 0x94, (byte) 0x8A, (byte) 0x04, (byte) 0x52, (byte) 0xB8, (byte) 0x48,
        (byte) 0x6F, (byte) 0xE4, (byte) 0x17, (byte) 0x62, (byte) 0x76, (byte) 0xC7, (byte) 0x5E, (byte) 0xF7,
        (byte) 0xB6, (byte) 0xE7, (byte) 0xC2, (byte) 0xEB, (byte) 0x11, (byte) 0xBD, (byte) 0x5B, (byte) 0xDD,
        (byte) 0x12, (byte) 0x46, (byte) 0x5B, (byte) 0x15, (byte) 0x42, (byte) 0x2C, (byte) 0x5F, (byte) 0x51,
        (byte) 0xB4, (byte) 0xA8, (byte) 0x72, (byte) 0xB3, (byte) 0xBE, (byte) 0xF8, (byte) 0xFC, (byte) 0x0E,
        (byte) 0xAB, (byte) 0xD4, (byte) 0xDE, (byte) 0xF6, (byte) 0x7C, (byte) 0x78, (byte) 0x3D, (byte) 0xBE,
        (byte) 0x9D, (byte) 0x65, (byte) 0x63, (byte) 0xE0, (byte) 0xE5, (byte) 0x45, (byte) 0x25, (byte) 0xE9,
        (byte) 0xA8, (byte) 0x83, (byte) 0xEF, (byte) 0xD4, (byte) 0x73, (byte) 0x31, (byte) 0x18, (byte) 0x9D,
        (byte) 0xB0, (byte) 0x10, (byte) 0x9C, (byte) 0x51, (byte) 0xB7, (byte) 0xCC, (byte) 0x70, (byte) 0xE8,
        (byte) 0xB1, (byte) 0xEF, (byte) 0x8F, (byte) 0x66, (byte) 0xEE, (byte) 0xFC, (byte) 0xD5, (byte) 0x18,
        (byte) 0x93, (byte) 0xBF, (byte) 0xFC, (byte) 0x6A, (byte) 0xF7, (byte) 0xDF, (byte) 0x55, (byte) 0x47,
        (byte) 0x09, (byte) 0x68, (byte) 0xB7, (byte) 0x5D, (byte) 0x4E, (byte) 0xF5, (byte) 0x1D, (byte) 0xB0,
        (byte) 0x08, (byte) 0xA7, (byte) 0xC5, (byte) 0x91, (byte) 0xC1, (byte) 0xAF, (byte) 0xED, (byte) 0xB3,
        (byte) 0xC1, (byte) 0x87, (byte) 0x29, (byte) 0x63, (byte) 0x7E, (byte) 0x1A, (byte) 0x07, (byte) 0x87,
        (byte) 0xA9, (byte) 0x10, (byte) 0x38, (byte) 0x24, (byte) 0x89, (byte) 0x6C, (byte) 0xEB, (byte) 0xDF,
        (byte) 0x0D, (byte) 0xE0, (byte) 0x71, (byte) 0x0E, (byte) 0xF5, (byte) 0x24, (byte) 0xB6, (byte) 0xD0,
        (byte) 0x00, (byte) 0x51, (byte) 0x3C, (byte) 0xD0, (byte) 0x17, (byte) 0x20, (byte) 0x25, (byte) 0xC4,
        (byte) 0x00, (byte) 0xB2, (byte) 0x5F, (byte) 0x5F, (byte) 0x06, (byte) 0x74, (byte) 0x45, (byte) 0x57
    };

    // RSA-2048 private exponent (256 bytes) - from ColossusPaymentApplicationTest
    private static final byte[] RSA_2048_EXPONENT = new byte[] {
        (byte) 0x78, (byte) 0x78, (byte) 0x3A, (byte) 0xFA, (byte) 0xCB, (byte) 0x70, (byte) 0xC5, (byte) 0x0C,
        (byte) 0x9E, (byte) 0xE4, (byte) 0xE8, (byte) 0xC5, (byte) 0x88, (byte) 0x87, (byte) 0x80, (byte) 0x70,
        (byte) 0xB0, (byte) 0xDC, (byte) 0x8C, (byte) 0x01, (byte) 0xBE, (byte) 0x82, (byte) 0xE4, (byte) 0x38,
        (byte) 0xCE, (byte) 0x68, (byte) 0x3A, (byte) 0x4C, (byte) 0xE7, (byte) 0x5B, (byte) 0xC5, (byte) 0xCA,
        (byte) 0x3B, (byte) 0x3D, (byte) 0x76, (byte) 0xC4, (byte) 0x2F, (byte) 0x8F, (byte) 0xDD, (byte) 0xCD,
        (byte) 0x5A, (byte) 0x0B, (byte) 0xC3, (byte) 0xCE, (byte) 0x52, (byte) 0x71, (byte) 0x90, (byte) 0x42,
        (byte) 0xC2, (byte) 0x26, (byte) 0xD4, (byte) 0xB2, (byte) 0x8C, (byte) 0xAE, (byte) 0x4B, (byte) 0x8E,
        (byte) 0x7B, (byte) 0xB4, (byte) 0x5E, (byte) 0x6B, (byte) 0x75, (byte) 0xB3, (byte) 0xD1, (byte) 0xBE,
        (byte) 0x24, (byte) 0xA5, (byte) 0x6A, (byte) 0x10, (byte) 0x53, (byte) 0xBE, (byte) 0x1C, (byte) 0x7F,
        (byte) 0xD1, (byte) 0xFE, (byte) 0xCA, (byte) 0x80, (byte) 0x63, (byte) 0x4A, (byte) 0xBA, (byte) 0x62,
        (byte) 0xBC, (byte) 0x69, (byte) 0x07, (byte) 0x0D, (byte) 0x62, (byte) 0x16, (byte) 0xC4, (byte) 0xAB,
        (byte) 0x18, (byte) 0xE6, (byte) 0x42, (byte) 0x1D, (byte) 0xF6, (byte) 0x92, (byte) 0x18, (byte) 0x89,
        (byte) 0x06, (byte) 0x7B, (byte) 0x0B, (byte) 0xEF, (byte) 0x74, (byte) 0xF7, (byte) 0xE3, (byte) 0x03,
        (byte) 0xED, (byte) 0x36, (byte) 0x30, (byte) 0xC3, (byte) 0xAC, (byte) 0xA4, (byte) 0x2C, (byte) 0x3F,
        (byte) 0xBA, (byte) 0xB9, (byte) 0x0D, (byte) 0xB1, (byte) 0x58, (byte) 0x37, (byte) 0x25, (byte) 0x85,
        (byte) 0x9F, (byte) 0xED, (byte) 0x64, (byte) 0xEC, (byte) 0x4F, (byte) 0x2F, (byte) 0x94, (byte) 0xA4,
        (byte) 0x05, (byte) 0x75, (byte) 0xFB, (byte) 0x66, (byte) 0xA5, (byte) 0xD6, (byte) 0x00, (byte) 0x58,
        (byte) 0xCC, (byte) 0x8E, (byte) 0xFE, (byte) 0xA3, (byte) 0x03, (byte) 0x5E, (byte) 0xB6, (byte) 0x74,
        (byte) 0x5E, (byte) 0x61, (byte) 0x98, (byte) 0x98, (byte) 0xC9, (byte) 0x4C, (byte) 0xB5, (byte) 0x20,
        (byte) 0x57, (byte) 0x48, (byte) 0xDD, (byte) 0x25, (byte) 0xB2, (byte) 0x02, (byte) 0xE3, (byte) 0x79,
        (byte) 0x3A, (byte) 0x80, (byte) 0xC8, (byte) 0xE1, (byte) 0x2D, (byte) 0xCD, (byte) 0xAC, (byte) 0xBA,
        (byte) 0xEE, (byte) 0xAE, (byte) 0xA0, (byte) 0x5D, (byte) 0xC7, (byte) 0x45, (byte) 0x17, (byte) 0x21,
        (byte) 0xFD, (byte) 0x4B, (byte) 0x37, (byte) 0x09, (byte) 0x26, (byte) 0x81, (byte) 0xD3, (byte) 0xDD,
        (byte) 0xF0, (byte) 0xB9, (byte) 0xCF, (byte) 0xDE, (byte) 0xF0, (byte) 0x39, (byte) 0x46, (byte) 0x32,
        (byte) 0x40, (byte) 0x9F, (byte) 0x5C, (byte) 0x47, (byte) 0x9B, (byte) 0x6B, (byte) 0x22, (byte) 0x94,
        (byte) 0x2A, (byte) 0x3F, (byte) 0x26, (byte) 0xE0, (byte) 0x7E, (byte) 0x17, (byte) 0xD1, (byte) 0xEE,
        (byte) 0x82, (byte) 0x4E, (byte) 0x26, (byte) 0x73, (byte) 0x50, (byte) 0x65, (byte) 0x11, (byte) 0x8F,
        (byte) 0xA7, (byte) 0x32, (byte) 0xEA, (byte) 0xB9, (byte) 0x36, (byte) 0x07, (byte) 0x9E, (byte) 0xA3,
        (byte) 0xBB, (byte) 0x1F, (byte) 0xBA, (byte) 0xCC, (byte) 0x67, (byte) 0xF7, (byte) 0x30, (byte) 0x7D,
        (byte) 0xBC, (byte) 0x16, (byte) 0xE1, (byte) 0x13, (byte) 0x91, (byte) 0xCA, (byte) 0xD0, (byte) 0x84,
        (byte) 0x29, (byte) 0x36, (byte) 0xAE, (byte) 0x2B, (byte) 0xE5, (byte) 0x0F, (byte) 0xB4, (byte) 0xE5,
        (byte) 0xA2, (byte) 0x67, (byte) 0xA6, (byte) 0x07, (byte) 0x3C, (byte) 0x34, (byte) 0x31, (byte) 0x8B
    };

    @BeforeAll
    public static void setup() throws CardException {
        SmartCard.connect();
        SmartCard.install(COLOSSUS_AID, PaymentApplicationContainer.class);
    }

    @AfterAll
    public static void teardown() throws CardException {
        SmartCard.disconnect();
    }

    @Test
    @DisplayName("Test SDAD is exactly 256 bytes for RSA-2048")
    public void testSdadLength256() throws Exception {
        // Select with correct AID
        ResponseAPDU response = SmartCard.transmitCommand(new byte[] {
            (byte) 0x00, (byte) 0xA4, (byte) 0x04, (byte) 0x00,
            (byte) 0x06, (byte) 0xA0, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x09, (byte) 0x51
        });
        System.out.println("SELECT SW: " + Integer.toHexString(response.getSW()));
        assertEquals(ISO7816.SW_NO_ERROR, (short) response.getSW(), "SELECT should succeed");

        // Initialize card
        response = SmartCard.transmitCommand(new byte[] {
            (byte) 0x80, (byte) 0x05, (byte) 0x00, (byte) 0x00, (byte) 0x00
        });
        System.out.println("INIT SW: " + Integer.toHexString(response.getSW()));

        // Load RSA-2048 modulus using extended APDU (256 bytes in single command)
        byte[] modulusCmd = new byte[7 + 256];  // 7 byte header + 256 byte data
        modulusCmd[0] = (byte) 0x80;  // CLA
        modulusCmd[1] = (byte) 0x04;  // INS (SET_SETTINGS)
        modulusCmd[2] = (byte) 0x00;  // P1
        modulusCmd[3] = (byte) 0x04;  // P2 (modulus setting)
        modulusCmd[4] = (byte) 0x00;  // Extended length indicator
        modulusCmd[5] = (byte) 0x01;  // Lc high byte (256 = 0x0100)
        modulusCmd[6] = (byte) 0x00;  // Lc low byte
        System.arraycopy(RSA_2048_MODULUS, 0, modulusCmd, 7, 256);

        response = SmartCard.transmitCommand(modulusCmd);
        System.out.println("Load modulus SW: " + Integer.toHexString(response.getSW()));
        assertEquals(ISO7816.SW_NO_ERROR, (short) response.getSW(), "RSA-2048 modulus should succeed");

        // Load RSA-2048 exponent using extended APDU (256 bytes in single command)
        byte[] expCmd = new byte[7 + 256];  // 7 byte header + 256 byte data
        expCmd[0] = (byte) 0x80;  // CLA
        expCmd[1] = (byte) 0x04;  // INS (SET_SETTINGS)
        expCmd[2] = (byte) 0x00;  // P1
        expCmd[3] = (byte) 0x05;  // P2 (exponent setting)
        expCmd[4] = (byte) 0x00;  // Extended length indicator
        expCmd[5] = (byte) 0x01;  // Lc high byte (256 = 0x0100)
        expCmd[6] = (byte) 0x00;  // Lc low byte
        System.arraycopy(RSA_2048_EXPONENT, 0, expCmd, 7, 256);

        response = SmartCard.transmitCommand(expCmd);
        System.out.println("Load exponent SW: " + Integer.toHexString(response.getSW()));
        assertEquals(ISO7816.SW_NO_ERROR, (short) response.getSW(), "RSA-2048 exponent should succeed");

        // Set response template tag 77
        response = SmartCard.transmitCommand(new byte[] {
            (byte) 0x80, (byte) 0x04, (byte) 0x00, (byte) 0x02, (byte) 0x02, (byte) 0x00, (byte) 0x77
        });

        // Set response template tags including 9F4B
        response = SmartCard.transmitCommand(new byte[] {
            (byte) 0x80, (byte) 0x02, (byte) 0x00, (byte) 0x03,
            (byte) 0x0A,
            (byte) 0x9F, (byte) 0x27,  // CID
            (byte) 0x9F, (byte) 0x36,  // ATC
            (byte) 0x9F, (byte) 0x26,  // AC
            (byte) 0x9F, (byte) 0x10,  // IAD
            (byte) 0x9F, (byte) 0x4B   // SDAD
        });

        // Set IAD
        response = SmartCard.transmitCommand(new byte[] {
            (byte) 0x80, (byte) 0x01, (byte) 0x9F, (byte) 0x10,
            (byte) 0x07, (byte) 0x06, (byte) 0x01, (byte) 0x0A, (byte) 0x03, (byte) 0xA4, (byte) 0xA0, (byte) 0x02
        });

        // Set ATC
        response = SmartCard.transmitCommand(new byte[] {
            (byte) 0x80, (byte) 0x01, (byte) 0x9F, (byte) 0x36, (byte) 0x02, (byte) 0x00, (byte) 0x01
        });

        // Set CDOL (30 bytes of CDOL definition)
        response = SmartCard.transmitCommand(new byte[] {
            (byte) 0x80, (byte) 0x01, (byte) 0x00, (byte) 0x8C,
            (byte) 0x1E,  // 30 bytes
            (byte) 0x9F, (byte) 0x02, (byte) 0x06,  // Amount
            (byte) 0x9F, (byte) 0x03, (byte) 0x06,  // Other
            (byte) 0x9F, (byte) 0x1A, (byte) 0x02,  // Country
            (byte) 0x95, (byte) 0x05,              // TVR
            (byte) 0x5F, (byte) 0x2A, (byte) 0x02,  // Currency
            (byte) 0x9A, (byte) 0x03,              // Date
            (byte) 0x9C, (byte) 0x01,              // Type
            (byte) 0x9F, (byte) 0x37, (byte) 0x04,  // UN
            (byte) 0x9F, (byte) 0x1C, (byte) 0x08,  // Terminal ID
            (byte) 0x9F, (byte) 0x16, (byte) 0x0F,  // Merchant ID
            (byte) 0x9F, (byte) 0x01, (byte) 0x06   // Acquirer ID
        });

        // GPO
        response = SmartCard.transmitCommand(new byte[] {
            (byte) 0x80, (byte) 0xA8, (byte) 0x00, (byte) 0x00,
            (byte) 0x02, (byte) 0x83, (byte) 0x00, (byte) 0x00
        });
        System.out.println("GPO SW: " + Integer.toHexString(response.getSW()));

        // GENERATE AC with CDA (P1 = 0x50 = TC + CDA)
        // CDOL data from terminal log (50 bytes total based on CDOL definition)
        // 9F02(6) + 9F03(6) + 9F1A(2) + 95(5) + 5F2A(2) + 9A(3) + 9C(1) + 9F37(4) + 9F1C(8) + 9F16(15) + 9F01(6) = 58 bytes
        byte[] cdolData = new byte[] {
            // Amount Auth (6 bytes)
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x01, (byte) 0x00,
            // Amount Other (6 bytes)
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            // Terminal Country (2 bytes)
            (byte) 0x08, (byte) 0x26,
            // TVR (5 bytes)
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x01, (byte) 0x09,
            // Currency (2 bytes)
            (byte) 0x78, (byte) 0x26,
            // Date (3 bytes)
            (byte) 0x02, (byte) 0x04, (byte) 0x00,
            // Type (1 byte)
            (byte) 0xC1,
            // UN (4 bytes)
            (byte) 0x06, (byte) 0x26, (byte) 0x59, (byte) 0x22,
            // Terminal ID (8 bytes)
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            // Merchant ID (15 bytes)
            (byte) 0x00, (byte) 0x00, (byte) 0x1F, (byte) 0x03, (byte) 0x02, (byte) 0x04, (byte) 0x11, (byte) 0x08,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            // Acquirer ID (6 bytes)
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00
        };

        System.out.println("CDOL data length: " + cdolData.length);

        // Build GENERATE AC command with extended APDU for large response
        CommandAPDU genAcCmd = new CommandAPDU(0x80, 0xAE, 0x50, 0x00, cdolData, 512);
        response = SmartCard.transmitCommand(genAcCmd);

        System.out.println("GENERATE AC SW: " + Integer.toHexString(response.getSW()));
        System.out.println("Response length: " + response.getData().length);

        byte[] respData = response.getData();
        System.out.println("Full response: " + bytesToHex(respData));

        // Parse response to find 9F4B
        int sdadLength = findTagLength(respData, (short) 0x9F4B);
        System.out.println("9F4B (SDAD) declared length: " + sdadLength);

        // Find actual SDAD data
        byte[] sdadData = findTagValue(respData, (short) 0x9F4B);
        if (sdadData != null) {
            System.out.println("9F4B (SDAD) actual data length: " + sdadData.length);
            System.out.println("9F4B first 16 bytes: " + bytesToHex(sdadData, 0, Math.min(16, sdadData.length)));
            System.out.println("9F4B last 16 bytes: " + bytesToHex(sdadData, Math.max(0, sdadData.length - 16), Math.min(16, sdadData.length)));

            assertEquals(256, sdadData.length, "SDAD must be exactly 256 bytes for RSA-2048");
        } else {
            fail("9F4B tag not found in response");
        }
    }

    @Test
    @DisplayName("Test GENERATE AC without extended APDU - should reproduce 6700")
    public void testGenAcWithoutExtendedApdu() throws Exception {
        // Select with correct AID
        ResponseAPDU response = SmartCard.transmitCommand(new byte[] {
            (byte) 0x00, (byte) 0xA4, (byte) 0x04, (byte) 0x00,
            (byte) 0x06, (byte) 0xA0, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x09, (byte) 0x51
        });
        assertEquals(ISO7816.SW_NO_ERROR, (short) response.getSW(), "SELECT should succeed");

        // Initialize card
        SmartCard.transmitCommand(new byte[] {
            (byte) 0x80, (byte) 0x05, (byte) 0x00, (byte) 0x00, (byte) 0x00
        });

        // Load RSA-2048 modulus using extended APDU
        byte[] modulusCmd = new byte[7 + 256];
        modulusCmd[0] = (byte) 0x80;
        modulusCmd[1] = (byte) 0x04;
        modulusCmd[2] = (byte) 0x00;
        modulusCmd[3] = (byte) 0x04;
        modulusCmd[4] = (byte) 0x00;
        modulusCmd[5] = (byte) 0x01;
        modulusCmd[6] = (byte) 0x00;
        System.arraycopy(RSA_2048_MODULUS, 0, modulusCmd, 7, 256);
        response = SmartCard.transmitCommand(modulusCmd);
        assertEquals(ISO7816.SW_NO_ERROR, (short) response.getSW());

        // Load RSA-2048 exponent
        byte[] expCmd = new byte[7 + 256];
        expCmd[0] = (byte) 0x80;
        expCmd[1] = (byte) 0x04;
        expCmd[2] = (byte) 0x00;
        expCmd[3] = (byte) 0x05;
        expCmd[4] = (byte) 0x00;
        expCmd[5] = (byte) 0x01;
        expCmd[6] = (byte) 0x00;
        System.arraycopy(RSA_2048_EXPONENT, 0, expCmd, 7, 256);
        response = SmartCard.transmitCommand(expCmd);
        assertEquals(ISO7816.SW_NO_ERROR, (short) response.getSW());

        // Set response template tag 77
        SmartCard.transmitCommand(new byte[] {
            (byte) 0x80, (byte) 0x04, (byte) 0x00, (byte) 0x02, (byte) 0x02, (byte) 0x00, (byte) 0x77
        });

        // Set response template tags including 9F4B
        SmartCard.transmitCommand(new byte[] {
            (byte) 0x80, (byte) 0x02, (byte) 0x00, (byte) 0x03,
            (byte) 0x0A,
            (byte) 0x9F, (byte) 0x27,
            (byte) 0x9F, (byte) 0x36,
            (byte) 0x9F, (byte) 0x26,
            (byte) 0x9F, (byte) 0x10,
            (byte) 0x9F, (byte) 0x4B
        });

        // Set IAD
        SmartCard.transmitCommand(new byte[] {
            (byte) 0x80, (byte) 0x01, (byte) 0x9F, (byte) 0x10,
            (byte) 0x07, (byte) 0x06, (byte) 0x01, (byte) 0x0A, (byte) 0x03, (byte) 0xA4, (byte) 0xA0, (byte) 0x02
        });

        // Set ATC
        SmartCard.transmitCommand(new byte[] {
            (byte) 0x80, (byte) 0x01, (byte) 0x9F, (byte) 0x36, (byte) 0x02, (byte) 0x00, (byte) 0x01
        });

        // Set CDOL
        SmartCard.transmitCommand(new byte[] {
            (byte) 0x80, (byte) 0x01, (byte) 0x00, (byte) 0x8C,
            (byte) 0x1E,
            (byte) 0x9F, (byte) 0x02, (byte) 0x06,
            (byte) 0x9F, (byte) 0x03, (byte) 0x06,
            (byte) 0x9F, (byte) 0x1A, (byte) 0x02,
            (byte) 0x95, (byte) 0x05,
            (byte) 0x5F, (byte) 0x2A, (byte) 0x02,
            (byte) 0x9A, (byte) 0x03,
            (byte) 0x9C, (byte) 0x01,
            (byte) 0x9F, (byte) 0x37, (byte) 0x04,
            (byte) 0x9F, (byte) 0x1C, (byte) 0x08,
            (byte) 0x9F, (byte) 0x16, (byte) 0x0F,
            (byte) 0x9F, (byte) 0x01, (byte) 0x06
        });

        // GPO
        SmartCard.transmitCommand(new byte[] {
            (byte) 0x80, (byte) 0xA8, (byte) 0x00, (byte) 0x00,
            (byte) 0x02, (byte) 0x83, (byte) 0x00, (byte) 0x00
        });

        // CDOL data (58 bytes)
        byte[] cdolData = new byte[] {
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x01, (byte) 0x00,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x08, (byte) 0x26,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x01, (byte) 0x09,
            (byte) 0x78, (byte) 0x26,
            (byte) 0x02, (byte) 0x04, (byte) 0x00,
            (byte) 0xC1,
            (byte) 0x06, (byte) 0x26, (byte) 0x59, (byte) 0x22,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x00, (byte) 0x00, (byte) 0x1F, (byte) 0x03, (byte) 0x02, (byte) 0x04, (byte) 0x11, (byte) 0x08,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00
        };

        // GENERATE AC WITHOUT extended APDU - standard APDU with Le=00 (max 256)
        // This simulates what happens when terminal doesn't request extended response
        byte[] genAcCmd = new byte[5 + cdolData.length + 1];
        genAcCmd[0] = (byte) 0x80;  // CLA
        genAcCmd[1] = (byte) 0xAE;  // INS
        genAcCmd[2] = (byte) 0x50;  // P1 (TC + CDA)
        genAcCmd[3] = (byte) 0x00;  // P2
        genAcCmd[4] = (byte) cdolData.length;  // Lc
        System.arraycopy(cdolData, 0, genAcCmd, 5, cdolData.length);
        genAcCmd[genAcCmd.length - 1] = (byte) 0x00;  // Le = 00 (request up to 256 bytes)

        response = SmartCard.transmitCommand(genAcCmd);

        System.out.println("GENERATE AC (no extended) SW: " + Integer.toHexString(response.getSW()));
        System.out.println("Response length: " + response.getData().length);

        System.out.println("First response SW: " + Integer.toHexString(response.getSW()));
        System.out.println("First response data length: " + response.getData().length);

        // Collect all response data (handle 61XX chaining)
        byte[] fullResponse;
        if ((response.getSW() & 0xFF00) == 0x6100) {
            // 61XX means more data available
            java.io.ByteArrayOutputStream baos = new java.io.ByteArrayOutputStream();
            baos.write(response.getData(), 0, response.getData().length);

            while ((response.getSW() & 0xFF00) == 0x6100) {
                int remaining = response.getSW() & 0x00FF;
                System.out.println("61XX chaining: " + remaining + " more bytes available");

                // Send GET RESPONSE
                byte[] getResponseCmd = new byte[] {
                    (byte) 0x00, (byte) 0xC0, (byte) 0x00, (byte) 0x00, (byte) remaining
                };
                response = SmartCard.transmitCommand(getResponseCmd);
                System.out.println("GET RESPONSE SW: " + Integer.toHexString(response.getSW()));
                System.out.println("GET RESPONSE data length: " + response.getData().length);
                baos.write(response.getData(), 0, response.getData().length);
            }
            fullResponse = baos.toByteArray();
        } else if (response.getSW() == 0x9000) {
            fullResponse = response.getData();
        } else {
            fail("Unexpected SW: " + Integer.toHexString(response.getSW()));
            return;
        }

        System.out.println("Total response length: " + fullResponse.length);
        System.out.println("Full response: " + bytesToHex(fullResponse));

        // Parse and verify SDAD
        byte[] sdadData = findTagValue(fullResponse, (short) 0x9F4B);
        if (sdadData != null) {
            System.out.println("9F4B (SDAD) length: " + sdadData.length);
            assertEquals(256, sdadData.length, "SDAD must be exactly 256 bytes for RSA-2048");
        } else {
            fail("9F4B tag not found in response");
        }
    }

    private static int findTagLength(byte[] data, short tagToFind) {
        int offset = 0;

        // Skip tag 77 header
        if (data[offset] == 0x77) {
            offset++;
            int len = data[offset++] & 0xFF;
            if (len == 0x81) {
                offset++;
            } else if (len == 0x82) {
                offset += 2;
            }
        }

        while (offset < data.length - 2) {
            int tag = data[offset++] & 0xFF;
            if ((tag & 0x1F) == 0x1F) {
                tag = (tag << 8) | (data[offset++] & 0xFF);
            }

            int len = data[offset++] & 0xFF;
            if (len == 0x81) {
                len = data[offset++] & 0xFF;
            } else if (len == 0x82) {
                len = ((data[offset++] & 0xFF) << 8) | (data[offset++] & 0xFF);
            }

            if (tag == (tagToFind & 0xFFFF)) {
                return len;
            }

            offset += len;
        }
        return -1;
    }

    private static byte[] findTagValue(byte[] data, short tagToFind) {
        int offset = 0;

        // Skip tag 77 header
        if (data[offset] == 0x77) {
            offset++;
            int len = data[offset++] & 0xFF;
            if (len == 0x81) {
                offset++;
            } else if (len == 0x82) {
                offset += 2;
            }
        }

        while (offset < data.length - 2) {
            int tag = data[offset++] & 0xFF;
            if ((tag & 0x1F) == 0x1F) {
                tag = (tag << 8) | (data[offset++] & 0xFF);
            }

            int len = data[offset++] & 0xFF;
            if (len == 0x81) {
                len = data[offset++] & 0xFF;
            } else if (len == 0x82) {
                len = ((data[offset++] & 0xFF) << 8) | (data[offset++] & 0xFF);
            }

            if (tag == (tagToFind & 0xFFFF)) {
                // Check if we have enough data - fail if truncated
                int availableBytes = data.length - offset;
                if (availableBytes < len) {
                    throw new RuntimeException("Response truncated! Tag 0x" + Integer.toHexString(tag) +
                        " declares " + len + " bytes but only " + availableBytes + " bytes available");
                }
                byte[] value = new byte[len];
                System.arraycopy(data, offset, value, 0, len);
                return value;
            }

            offset += len;
        }
        return null;
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02X ", b));
        }
        return sb.toString().trim();
    }

    private static String bytesToHex(byte[] bytes, int offset, int length) {
        StringBuilder sb = new StringBuilder();
        for (int i = offset; i < offset + length && i < bytes.length; i++) {
            sb.append(String.format("%02X ", bytes[i]));
        }
        return sb.toString().trim();
    }
}
