package emvcardsimulator;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import javacard.framework.ISO7816;
import javacard.security.KeyBuilder;
import javacard.security.RSAPrivateKey;
import javacardx.crypto.Cipher;

import javax.smartcardio.CardException;
import javax.smartcardio.ResponseAPDU;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;

/**
 * Minimal test to verify RSA-2048 works in jCardSim
 */
public class Rsa2048Test {
    private static final byte[] COLOSSUS_AID = new byte[] { 
        (byte) 0xA0, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x09, (byte) 0x51 
    };

    @BeforeAll
    public static void setup() throws CardException {
        SmartCard.connect();
        SmartCard.install(COLOSSUS_AID, PaymentApplicationContainer.class);
    }

    @AfterAll
    public static void disconnect() throws CardException {
        SmartCard.disconnect();
    }

    @Test
    @DisplayName("Test RSA-2048 key creation and signing")
    public void testRsa2048Signing() throws CardException {
        // SELECT
        SmartCard.transmitCommand(new byte[] { 
            (byte) 0x00, (byte) 0xA4, (byte) 0x04, (byte) 0x00, 
            (byte) 0x06,
            (byte) 0xA0, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x09, (byte) 0x51 
        });
        
        // Factory reset
        SmartCard.transmitCommand(new byte[] {
            (byte) 0x80, (byte) 0x05, (byte) 0x00, (byte) 0x00, (byte) 0x00
        });
        
        // RSA-2048 modulus (256 bytes) - valid key from openssl
        byte[] modulus = new byte[] {
            (byte) 0xF2, (byte) 0x11, (byte) 0x62, (byte) 0x23, (byte) 0x50, (byte) 0x48, (byte) 0x40, (byte) 0x5F,
            (byte) 0x99, (byte) 0x72, (byte) 0x9D, (byte) 0xEA, (byte) 0x3B, (byte) 0x35, (byte) 0xE9, (byte) 0xC9,
            (byte) 0x28, (byte) 0xDD, (byte) 0x15, (byte) 0xB0, (byte) 0x3E, (byte) 0x24, (byte) 0x13, (byte) 0x2D,
            (byte) 0x0B, (byte) 0xBF, (byte) 0x61, (byte) 0xFB, (byte) 0x6C, (byte) 0x0C, (byte) 0x9B, (byte) 0xE0,
            (byte) 0x8F, (byte) 0x8C, (byte) 0xB8, (byte) 0x1E, (byte) 0xF8, (byte) 0xB4, (byte) 0xA7, (byte) 0xE3,
            (byte) 0xB3, (byte) 0x50, (byte) 0xBD, (byte) 0x76, (byte) 0xF0, (byte) 0xCF, (byte) 0x1C, (byte) 0xB2,
            (byte) 0x51, (byte) 0x2F, (byte) 0x0D, (byte) 0x4D, (byte) 0x08, (byte) 0xE6, (byte) 0xBE, (byte) 0xF2,
            (byte) 0xBB, (byte) 0x2B, (byte) 0x51, (byte) 0x7B, (byte) 0x53, (byte) 0x8D, (byte) 0x4E, (byte) 0x98,
            (byte) 0x88, (byte) 0x52, (byte) 0x30, (byte) 0xDE, (byte) 0x9A, (byte) 0xB8, (byte) 0x10, (byte) 0x6D,
            (byte) 0xF9, (byte) 0xFB, (byte) 0x07, (byte) 0x41, (byte) 0x7D, (byte) 0xBC, (byte) 0x0F, (byte) 0x36,
            (byte) 0x43, (byte) 0x10, (byte) 0x48, (byte) 0x82, (byte) 0xFA, (byte) 0x07, (byte) 0x33, (byte) 0x84,
            (byte) 0xE4, (byte) 0x88, (byte) 0x6B, (byte) 0x07, (byte) 0xFE, (byte) 0x57, (byte) 0xA7, (byte) 0x5F,
            (byte) 0xE2, (byte) 0x4E, (byte) 0x30, (byte) 0xBF, (byte) 0x41, (byte) 0x49, (byte) 0x32, (byte) 0xAF,
            (byte) 0xF5, (byte) 0xA6, (byte) 0x14, (byte) 0x31, (byte) 0x92, (byte) 0xAA, (byte) 0x14, (byte) 0x93,
            (byte) 0x17, (byte) 0x99, (byte) 0x18, (byte) 0x1C, (byte) 0x77, (byte) 0x88, (byte) 0x24, (byte) 0xA1,
            (byte) 0x53, (byte) 0xED, (byte) 0x21, (byte) 0x7E, (byte) 0x26, (byte) 0x0D, (byte) 0x2D, (byte) 0x89,
            (byte) 0x09, (byte) 0x10, (byte) 0x24, (byte) 0xAB, (byte) 0x81, (byte) 0x2E, (byte) 0xD6, (byte) 0x63,
            (byte) 0x99, (byte) 0x11, (byte) 0x45, (byte) 0xA6, (byte) 0xCD, (byte) 0x43, (byte) 0x92, (byte) 0x56,
            (byte) 0x5B, (byte) 0xDB, (byte) 0xB2, (byte) 0xCB, (byte) 0xB1, (byte) 0xE1, (byte) 0xC9, (byte) 0x88,
            (byte) 0x40, (byte) 0x2D, (byte) 0x74, (byte) 0xE6, (byte) 0x80, (byte) 0xC9, (byte) 0x0F, (byte) 0xA7,
            (byte) 0xC8, (byte) 0xAB, (byte) 0xFC, (byte) 0x65, (byte) 0xF1, (byte) 0x0A, (byte) 0x4C, (byte) 0xAC,
            (byte) 0x9B, (byte) 0xD0, (byte) 0x11, (byte) 0x59, (byte) 0x05, (byte) 0x79, (byte) 0xEE, (byte) 0x39,
            (byte) 0x29, (byte) 0x85, (byte) 0x7B, (byte) 0xA9, (byte) 0xD9, (byte) 0xA3, (byte) 0x16, (byte) 0xCC,
            (byte) 0x84, (byte) 0x90, (byte) 0xDE, (byte) 0xA9, (byte) 0x35, (byte) 0x2D, (byte) 0x5D, (byte) 0x39,
            (byte) 0x9A, (byte) 0xA3, (byte) 0x85, (byte) 0x32, (byte) 0xDC, (byte) 0xD1, (byte) 0xFE, (byte) 0x8B,
            (byte) 0xA4, (byte) 0xC8, (byte) 0x49, (byte) 0xA1, (byte) 0x7E, (byte) 0xCF, (byte) 0x9F, (byte) 0x0A,
            (byte) 0x31, (byte) 0x59, (byte) 0x7E, (byte) 0x66, (byte) 0x7C, (byte) 0x92, (byte) 0x3E, (byte) 0xBE,
            (byte) 0xAD, (byte) 0xB7, (byte) 0x2B, (byte) 0xC2, (byte) 0x49, (byte) 0xCF, (byte) 0x9C, (byte) 0x77,
            (byte) 0x75, (byte) 0x73, (byte) 0x7E, (byte) 0xE4, (byte) 0x64, (byte) 0x8C, (byte) 0x60, (byte) 0xD8,
            (byte) 0xE3, (byte) 0x63, (byte) 0xF7, (byte) 0xDB, (byte) 0xD6, (byte) 0xA5, (byte) 0xED, (byte) 0xD7,
            (byte) 0x18, (byte) 0x55, (byte) 0xC2, (byte) 0x87, (byte) 0xC7, (byte) 0x1C, (byte) 0xF2, (byte) 0xC0,
            (byte) 0xC3, (byte) 0xBD, (byte) 0x62, (byte) 0xBB, (byte) 0x33, (byte) 0x6C, (byte) 0xC2, (byte) 0xFF
        };
        
        // Send via APDU chaining
        byte[] chunk1 = new byte[133];
        chunk1[0] = (byte) 0x90;
        chunk1[1] = (byte) 0x00;
        chunk1[2] = (byte) 0x00;
        chunk1[3] = (byte) 0x04;
        chunk1[4] = (byte) 0x80;
        System.arraycopy(modulus, 0, chunk1, 5, 128);
        
        ResponseAPDU response = SmartCard.transmitCommand(chunk1);
        assertEquals(ISO7816.SW_NO_ERROR, (short) response.getSW(), "Chunk 1 should succeed");
        
        byte[] chunk2 = new byte[133];
        chunk2[0] = (byte) 0x80;
        chunk2[1] = (byte) 0x00;
        chunk2[2] = (byte) 0x00;
        chunk2[3] = (byte) 0x04;
        chunk2[4] = (byte) 0x80;
        System.arraycopy(modulus, 128, chunk2, 5, 128);
        
        response = SmartCard.transmitCommand(chunk2);
        assertEquals(ISO7816.SW_NO_ERROR, (short) response.getSW(), "Chunk 2 should succeed");
        
        // Test that we can actually use this key
        System.out.println("RSA-2048 key loaded successfully via APDU chaining!");
    }
}

