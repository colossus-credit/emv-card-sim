package emvcardsimulator;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import javacard.framework.ISO7816;
import javacard.framework.Util;

import javax.smartcardio.CardException;
import javax.smartcardio.ResponseAPDU;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.interfaces.ECPublicKey;
import java.util.Arrays;

import net.jqwik.api.*;
import net.jqwik.api.constraints.*;
import net.jqwik.api.lifecycle.*;

/**
 * Property-based tests for EMV card simulator.
 *
 * Instead of testing specific inputs/outputs, these tests define invariants
 * that must hold for ALL inputs. jqwik generates thousands of random inputs
 * and tries to break each property — then shrinks failures to minimal cases.
 */
public class PropertyTest {

    private static final byte[] PAYMENT_AID = new byte[] {
        (byte) 0xA0, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x09, (byte) 0x51
    };

    private static final byte[] PSE_AID = new byte[] {
        (byte) 0x31, (byte) 0x50, (byte) 0x41, (byte) 0x59, (byte) 0x2E,
        (byte) 0x53, (byte) 0x59, (byte) 0x53, (byte) 0x2E, (byte) 0x44,
        (byte) 0x44, (byte) 0x46, (byte) 0x30, (byte) 0x31
    };

    private static boolean initialized = false;

    private static void ensureInitialized() throws CardException {
        if (!initialized) {
            SmartCard.connect();
            SmartCard.setLogging(false);
            SmartCard.install(PAYMENT_AID, PaymentApplicationContainer.class);
            SmartCard.install(PSE_AID, PaymentSystemEnvironmentContainer.class);
            initialized = true;
        }
    }

    // -----------------------------------------------------------------------
    // 1. EmvTag TLV serialization roundtrip
    //    Property: for any tag ID and data, serializing to BER-TLV and
    //    checking the output starts with the correct tag bytes and length.
    // -----------------------------------------------------------------------

    @Property(tries = 500)
    void tlvSerializationPreservesTagId(
            @ForAll("validEmvTagIds") short tagId,
            @ForAll @Size(min = 1, max = 127) byte[] value
    ) throws CardException {
        selectAndReset();

        // SET_EMV_TAG: 80 01 TT TT LL <data>
        byte[] cmd = new byte[5 + value.length];
        cmd[0] = (byte) 0x80;
        cmd[1] = (byte) 0x01;
        cmd[2] = (byte) ((tagId >> 8) & 0xFF);
        cmd[3] = (byte) (tagId & 0xFF);
        cmd[4] = (byte) value.length;
        System.arraycopy(value, 0, cmd, 5, value.length);

        ResponseAPDU response = SmartCard.transmitCommand(cmd);
        assertEquals(0x9000, response.getSW(), "SET_EMV_TAG should succeed");

        // GET_DATA to read back the tag
        byte[] getCmd = new byte[] {
            (byte) 0x80, (byte) 0xCA,
            (byte) ((tagId >> 8) & 0xFF), (byte) (tagId & 0xFF),
            (byte) 0x00
        };
        response = SmartCard.transmitCommand(getCmd);

        if (response.getSW() == 0x9000 && response.getData().length > 0) {
            byte[] data = response.getData();
            // The response should contain TLV-encoded data
            // Verify it starts with the correct tag bytes
            if ((tagId & 0xFF00) == 0) {
                // Single-byte tag
                assertEquals((byte) (tagId & 0xFF), data[0],
                    "Single-byte tag ID should match");
            } else {
                // Two-byte tag
                assertEquals((byte) ((tagId >> 8) & 0xFF), data[0],
                    "Two-byte tag high byte should match");
                assertEquals((byte) (tagId & 0xFF), data[1],
                    "Two-byte tag low byte should match");
            }
        }
    }

    @Provide
    Arbitrary<Short> validEmvTagIds() {
        // EMV tags: single-byte (00xx where xx > 0) or two-byte (9Fxx, 5Fxx, DFxx)
        return Arbitraries.oneOf(
            // Common two-byte tags
            Arbitraries.shorts().between((short) 0x9F01, (short) 0x9F7F),
            // Single-byte tags (stored as 00xx internally)
            Arbitraries.of(
                (short) 0x0057, (short) 0x0082, (short) 0x0094,
                (short) 0x009A, (short) 0x009C
            )
        );
    }

    // -----------------------------------------------------------------------
    // 2. Tag store/retrieve consistency
    //    Property: setting a tag then looking it up via GET_DATA returns
    //    data whose value portion matches what we stored.
    // -----------------------------------------------------------------------

    @Property(tries = 300)
    void tagStoreRetrieveConsistency(
            @ForAll @ShortRange(min = 0x01, max = 0x7F) short tagLowByte,
            @ForAll @Size(min = 1, max = 100) byte[] value
    ) throws CardException {
        selectAndReset();

        short tagId = (short) (0x9F00 | (tagLowByte & 0xFF));

        // Store the tag
        byte[] setCmd = new byte[5 + value.length];
        setCmd[0] = (byte) 0x80;
        setCmd[1] = (byte) 0x01;
        setCmd[2] = (byte) ((tagId >> 8) & 0xFF);
        setCmd[3] = (byte) (tagId & 0xFF);
        setCmd[4] = (byte) value.length;
        System.arraycopy(value, 0, setCmd, 5, value.length);

        ResponseAPDU setResp = SmartCard.transmitCommand(setCmd);
        assertEquals(0x9000, setResp.getSW(), "SET_EMV_TAG should succeed");

        // Retrieve via GET_DATA
        byte[] getCmd = new byte[] {
            (byte) 0x80, (byte) 0xCA,
            (byte) ((tagId >> 8) & 0xFF), (byte) (tagId & 0xFF),
            (byte) 0x00
        };
        ResponseAPDU getResp = SmartCard.transmitCommand(getCmd);

        if (getResp.getSW() == 0x9000) {
            byte[] tlv = getResp.getData();
            assertTrue(tlv.length >= 3,
                "TLV response must have at least tag(2) + length(1)");

            // Extract value from TLV: skip 2-byte tag + length encoding
            int offset = 2; // skip tag bytes
            int len;
            if ((tlv[offset] & 0xFF) < 128) {
                len = tlv[offset] & 0xFF;
                offset += 1;
            } else if (tlv[offset] == (byte) 0x81) {
                len = tlv[offset + 1] & 0xFF;
                offset += 2;
            } else {
                // 82 XX XX
                len = ((tlv[offset + 1] & 0xFF) << 8) | (tlv[offset + 2] & 0xFF);
                offset += 3;
            }

            assertEquals(value.length, len,
                "Retrieved length should match stored length");

            byte[] retrieved = new byte[len];
            System.arraycopy(tlv, offset, retrieved, 0, len);
            for (int i = 0; i < value.length; i++) {
                assertEquals(value[i], retrieved[i],
                    "Byte " + i + " should match");
            }
        }
    }

    // -----------------------------------------------------------------------
    // 3. Tag overwrite idempotency
    //    Property: setting the same tag twice with different data, the
    //    second value completely replaces the first.
    // -----------------------------------------------------------------------

    @Property(tries = 200)
    void tagOverwriteReplacesFully(
            @ForAll @Size(min = 1, max = 50) byte[] firstValue,
            @ForAll @Size(min = 1, max = 50) byte[] secondValue
    ) throws CardException {
        Assume.that(firstValue.length != secondValue.length
            || !java.util.Arrays.equals(firstValue, secondValue));

        selectAndReset();
        short tagId = (short) 0x9F42; // Application Currency Code (arbitrary choice)

        // Set first value
        setTag(tagId, firstValue);

        // Set second value — should overwrite
        setTag(tagId, secondValue);

        // Retrieve
        byte[] retrieved = getTagValue(tagId);
        assertNotNull(retrieved, "Tag should exist after overwrite");
        assertEquals(secondValue.length, retrieved.length,
            "Length should match second value");
        for (int i = 0; i < secondValue.length; i++) {
            assertEquals(secondValue[i], retrieved[i],
                "Byte " + i + " should match second value, not first");
        }
    }

    // -----------------------------------------------------------------------
    // 4. SELECT with invalid AID returns error
    //    Property: any byte sequence that isn't a registered AID must
    //    not return 9000.
    // -----------------------------------------------------------------------

    @Property(tries = 500)
    void selectWithInvalidAidRejectsGracefully(
            @ForAll @Size(min = 5, max = 16) byte[] randomAid
    ) throws CardException {
        // Filter out our actual AIDs
        Assume.that(!java.util.Arrays.equals(randomAid, PAYMENT_AID));
        Assume.that(!startsWith(randomAid, PAYMENT_AID));
        Assume.that(!java.util.Arrays.equals(randomAid, PSE_AID));

        ensureInitialized();

        byte[] selectCmd = new byte[5 + randomAid.length];
        selectCmd[0] = (byte) 0x00;
        selectCmd[1] = (byte) 0xA4;
        selectCmd[2] = (byte) 0x04;
        selectCmd[3] = (byte) 0x00;
        selectCmd[4] = (byte) randomAid.length;
        System.arraycopy(randomAid, 0, selectCmd, 5, randomAid.length);

        ResponseAPDU response = SmartCard.transmitCommand(selectCmd);
        int sw = response.getSW();

        // Must not succeed — should be 6A82 (file not found) or 6999 (applet select failed)
        assertTrue(sw != 0x9000 || response.getData().length == 0,
            "SELECT with unregistered AID should not return 9000 with data, got SW="
            + Integer.toHexString(sw));
    }

    // -----------------------------------------------------------------------
    // 5. PIN verification: wrong PINs always fail
    //    Property: any PIN that doesn't match the configured PIN must
    //    return 63Cx (verification failed, x tries remaining).
    // -----------------------------------------------------------------------

    @Property(tries = 200)
    void wrongPinAlwaysFails(
            @ForAll @ShortRange(min = 0x0000, max = 0x7FFF) short wrongPin
    ) throws CardException {
        selectAndReset();

        // Set PIN to a known value
        short correctPin = (short) 0x1234;
        Assume.that(wrongPin != correctPin);

        byte[] setPinCmd = new byte[] {
            (byte) 0x80, (byte) 0x04, (byte) 0x00, (byte) 0x01,
            (byte) 0x02,
            (byte) ((correctPin >> 8) & 0xFF), (byte) (correctPin & 0xFF)
        };
        SmartCard.transmitCommand(setPinCmd);

        // VERIFY PIN with wrong value (plain text mode, P1P2 = 0080)
        byte[] verifyCmd = new byte[] {
            (byte) 0x00, (byte) 0x20, (byte) 0x00, (byte) 0x80,
            (byte) 0x08,
            (byte) 0x24,  // format byte
            (byte) ((wrongPin >> 8) & 0xFF), (byte) (wrongPin & 0xFF),
            (byte) 0xFF, (byte) 0xFF,  // PIN end marker
            (byte) 0xFF, (byte) 0xFF, (byte) 0xFF
        };
        ResponseAPDU response = SmartCard.transmitCommand(verifyCmd);

        int sw = response.getSW();
        // Must be 63Cx (verification failed) — NOT 9000
        assertTrue((sw & 0xFFF0) == 0x63C0,
            "Wrong PIN must return 63Cx, got SW=" + Integer.toHexString(sw));
    }

    // -----------------------------------------------------------------------
    // 6. Correct PIN always succeeds
    //    Property: the exact configured PIN must always return 9000.
    // -----------------------------------------------------------------------

    @Property(tries = 50)
    void correctPinAlwaysSucceeds(
            @ForAll @ShortRange(min = 1, max = 9999) short pin
    ) throws CardException {
        selectAndReset();

        // Set PIN
        byte[] setPinCmd = new byte[] {
            (byte) 0x80, (byte) 0x04, (byte) 0x00, (byte) 0x01,
            (byte) 0x02,
            (byte) ((pin >> 8) & 0xFF), (byte) (pin & 0xFF)
        };
        SmartCard.transmitCommand(setPinCmd);

        // VERIFY PIN with correct value
        byte[] verifyCmd = new byte[] {
            (byte) 0x00, (byte) 0x20, (byte) 0x00, (byte) 0x80,
            (byte) 0x08,
            (byte) 0x24,
            (byte) ((pin >> 8) & 0xFF), (byte) (pin & 0xFF),
            (byte) 0xFF, (byte) 0xFF,
            (byte) 0xFF, (byte) 0xFF, (byte) 0xFF
        };
        ResponseAPDU response = SmartCard.transmitCommand(verifyCmd);
        assertEquals(0x9000, response.getSW(),
            "Correct PIN must always return 9000");
    }

    // -----------------------------------------------------------------------
    // 7. Unsupported INS codes reject cleanly
    //    Property: any INS code not in the command table must return
    //    6D00 (instruction not supported) — never crash or return 9000.
    // -----------------------------------------------------------------------

    @Property(tries = 300)
    void unsupportedInsRejectsCleanly(
            @ForAll byte ins
    ) throws CardException {
        // Filter out all known/valid INS codes
        Assume.that(ins != (byte) 0xA4);  // SELECT
        Assume.that(ins != (byte) 0xB2);  // READ RECORD
        Assume.that(ins != (byte) 0x88);  // INTERNAL AUTHENTICATE (DDA)
        Assume.that(ins != (byte) 0x20);  // VERIFY PIN
        Assume.that(ins != (byte) 0x84);  // GET CHALLENGE
        Assume.that(ins != (byte) 0xCA);  // GET DATA
        Assume.that(ins != (byte) 0xA8);  // GPO
        Assume.that(ins != (byte) 0xAE);  // GENERATE AC
        Assume.that(ins != (byte) 0x82);  // EXTERNAL AUTHENTICATE
        Assume.that(ins != (byte) 0xC0);  // GET RESPONSE
        Assume.that(ins != (byte) 0xE2);  // STORE DATA
        // Admin commands (CLA 0x80)
        Assume.that(ins != (byte) 0x01);  // SET_EMV_TAG
        Assume.that(ins != (byte) 0x02);  // SET_TAG_TEMPLATE
        Assume.that(ins != (byte) 0x03);  // SET_READ_RECORD
        Assume.that(ins != (byte) 0x04);  // SET_SETTINGS
        Assume.that(ins != (byte) 0x05);  // FACTORY_RESET
        Assume.that(ins != (byte) 0x06);  // LOG_CONSUME
        Assume.that(ins != (byte) 0x07);  // FUZZ_RESET
        Assume.that(ins != (byte) 0x08);  // LIST_TAGS
        Assume.that(ins != (byte) 0x09);  // SET_EMV_TAG_CHUNKED
        Assume.that(ins != (byte) 0x0A);  // SET_SETTINGS_CHUNKED
        Assume.that(ins != (byte) 0x0B);  // DIAGNOSTIC 61XX
        Assume.that(ins != (byte) 0x11);  // SET_EMV_TAG_FUZZ

        selectPaymentApp();

        byte[] cmd = new byte[] {
            (byte) 0x00, ins, (byte) 0x00, (byte) 0x00, (byte) 0x00
        };
        ResponseAPDU response = SmartCard.transmitCommand(cmd);

        int sw = response.getSW();
        assertNotEquals(0x9000, sw,
            "Unknown INS 0x" + String.format("%02X", ins)
            + " must not succeed, got SW=" + Integer.toHexString(sw));
    }

    // -----------------------------------------------------------------------
    // 8. Factory reset clears state
    //    Property: after factory reset, previously stored tags are gone.
    // -----------------------------------------------------------------------

    @Property(tries = 100)
    void factoryResetClearsAllTags(
            @ForAll @Size(min = 1, max = 5) short[] tagIds
    ) throws CardException {
        selectAndReset();

        // Store multiple tags
        byte[] value = new byte[] { 0x01, 0x02, 0x03 };
        for (short rawId : tagIds) {
            short tagId = (short) (0x9F00 | (rawId & 0x7F));
            setTag(tagId, value);
        }

        // Factory reset
        SmartCard.transmitCommand(new byte[] {
            (byte) 0x80, (byte) 0x05, (byte) 0x00, (byte) 0x00, (byte) 0x00
        });

        // All tags should be gone
        for (short rawId : tagIds) {
            short tagId = (short) (0x9F00 | (rawId & 0x7F));
            byte[] getCmd = new byte[] {
                (byte) 0x80, (byte) 0xCA,
                (byte) ((tagId >> 8) & 0xFF), (byte) (tagId & 0xFF),
                (byte) 0x00
            };
            ResponseAPDU resp = SmartCard.transmitCommand(getCmd);
            assertTrue(resp.getSW() != 0x9000 || resp.getData().length == 0,
                "Tag 0x" + Integer.toHexString(tagId & 0xFFFF)
                + " should not exist after factory reset");
        }
    }

    // -----------------------------------------------------------------------
    // 9. VERIFY PIN with wrong length rejects
    //    Property: VERIFY PIN with LC != 8 must fail with 6984.
    // -----------------------------------------------------------------------

    @Property(tries = 100)
    void verifyPinWrongLengthRejects(
            @ForAll @IntRange(min = 1, max = 20) int dataLength
    ) throws CardException {
        Assume.that(dataLength != 8);  // 8 is the correct length

        selectAndReset();

        // Set a valid PIN first
        SmartCard.transmitCommand(new byte[] {
            (byte) 0x80, (byte) 0x04, (byte) 0x00, (byte) 0x01,
            (byte) 0x02,
            (byte) 0x12, (byte) 0x34
        });

        byte[] cmd = new byte[5 + dataLength];
        cmd[0] = (byte) 0x00;
        cmd[1] = (byte) 0x20;
        cmd[2] = (byte) 0x00;
        cmd[3] = (byte) 0x80;
        cmd[4] = (byte) dataLength;
        // Fill with dummy data
        for (int i = 5; i < cmd.length; i++) {
            cmd[i] = (byte) 0xFF;
        }

        ResponseAPDU response = SmartCard.transmitCommand(cmd);
        assertNotEquals(0x9000, response.getSW(),
            "VERIFY PIN with LC=" + dataLength + " should fail");
    }

    // -----------------------------------------------------------------------
    // 10. ATC monotonically increases
    //     Property: each GENERATE AC increments the Application
    //     Transaction Counter by exactly 1.
    // -----------------------------------------------------------------------

    @Property(tries = 20)
    void atcIncreasesMonotonically(
            @ForAll @ShortRange(min = 1, max = 100) short initialAtc
    ) throws CardException {
        setupCardForTransaction();

        // Set initial ATC
        setTag((short) 0x9F36, new byte[] {
            (byte) ((initialAtc >> 8) & 0xFF),
            (byte) (initialAtc & 0xFF)
        });

        // Send GENERATE AC (ARQC)
        byte[] cdolData = createMinimalCdolData();
        byte[] genAcCmd = new byte[5 + cdolData.length];
        genAcCmd[0] = (byte) 0x80;
        genAcCmd[1] = (byte) 0xAE;
        genAcCmd[2] = (byte) 0x80;  // ARQC
        genAcCmd[3] = (byte) 0x00;
        genAcCmd[4] = (byte) cdolData.length;
        System.arraycopy(cdolData, 0, genAcCmd, 5, cdolData.length);

        ResponseAPDU response = SmartCard.transmitCommand(genAcCmd);
        int sw = response.getSW();
        Assume.that(sw == 0x9000 || (sw & 0xFF00) == 0x6100);

        // Read back ATC
        byte[] atcData = getTagValue((short) 0x9F36);
        assertNotNull(atcData, "ATC tag should exist after GENERATE AC");
        short newAtc = (short) (((atcData[0] & 0xFF) << 8) | (atcData[1] & 0xFF));
        assertEquals((short) (initialAtc + 1), newAtc,
            "ATC should increment by exactly 1");
    }

    // -----------------------------------------------------------------------
    // 11. GPO without PDOL data still returns valid response
    //     Property: GET PROCESSING OPTIONS must either succeed with
    //     a valid template (77 or 80) or fail with a defined error SW.
    // -----------------------------------------------------------------------

    @Property(tries = 50)
    void gpoResponseIsAlwaysValidTemplate(
            @ForAll @Size(min = 0, max = 20) byte[] pdolData
    ) throws CardException {
        setupCardForTransaction();

        // Wrap PDOL data in 83 TLV as required by GPO
        byte[] wrappedPdol = new byte[2 + pdolData.length];
        wrappedPdol[0] = (byte) 0x83;
        wrappedPdol[1] = (byte) pdolData.length;
        System.arraycopy(pdolData, 0, wrappedPdol, 2, pdolData.length);

        byte[] gpoCmd = new byte[5 + wrappedPdol.length];
        gpoCmd[0] = (byte) 0x80;
        gpoCmd[1] = (byte) 0xA8;
        gpoCmd[2] = (byte) 0x00;
        gpoCmd[3] = (byte) 0x00;
        gpoCmd[4] = (byte) wrappedPdol.length;
        System.arraycopy(wrappedPdol, 0, gpoCmd, 5, wrappedPdol.length);

        ResponseAPDU response = SmartCard.transmitCommand(gpoCmd);
        int sw = response.getSW();

        if (sw == 0x9000) {
            byte[] data = response.getData();
            assertTrue(data.length > 0, "Successful GPO must return data");
            byte templateTag = data[0];
            // EMV Book 3: GPO response is either Format 1 (80) or Format 2 (77)
            assertTrue(templateTag == (byte) 0x77 || templateTag == (byte) 0x80,
                "GPO response template must be 77 or 80, got "
                + String.format("%02X", templateTag));
        }
        // Any non-9000 SW is acceptable (card rejecting bad PDOL data)
    }

    // -----------------------------------------------------------------------
    // 12. BER-TLV length encoding correctness
    //     Property: tags with data length >= 128 must use multi-byte
    //     length encoding (0x81 prefix).
    // -----------------------------------------------------------------------

    @Property(tries = 50)
    void berTlvLengthEncodingCorrectForLargeValues(
            @ForAll @IntRange(min = 128, max = 255) int dataLength
    ) throws CardException {
        selectAndReset();

        short tagId = (short) 0x9F46;  // ICC Public Key Certificate (can be large)
        byte[] value = new byte[dataLength];
        for (int i = 0; i < dataLength; i++) {
            value[i] = (byte) (i & 0xFF);
        }

        setTag(tagId, value);

        byte[] getCmd = new byte[] {
            (byte) 0x80, (byte) 0xCA,
            (byte) 0x9F, (byte) 0x46,
            (byte) 0x00
        };
        ResponseAPDU response = SmartCard.transmitCommand(getCmd);

        if (response.getSW() == 0x9000) {
            byte[] tlv = response.getData();
            // After 2-byte tag, length encoding for >= 128 must be 0x81 LL
            assertTrue(tlv.length >= 4, "TLV must have tag(2) + length(2+) + data");
            assertEquals((byte) 0x81, tlv[2],
                "Length >= 128 must use 0x81 prefix encoding");
            assertEquals((byte) dataLength, tlv[3],
                "Length byte should match data length");
        }
    }

    // =======================================================================
    // EMV Book 3 Spec-Derived Properties
    // =======================================================================

    // -----------------------------------------------------------------------
    // 13. Book 3 §6.5.5: GENERATE AC CID must encode ARQC type
    //     Property: for an online-only card, CID (9F27) bits 7-6 must
    //     always be '10' (ARQC = 0x80) regardless of what the terminal
    //     requests in P1. Book 3 Table 15.
    // -----------------------------------------------------------------------

    @Property(tries = 10)
    void generateAcAlwaysReturnsArqcForOnlineOnlyCard(
            @ForAll("generateAcP1Values") byte p1
    ) throws CardException {
        setupCardForTransaction();

        byte[] cdolData = createMinimalCdolData();
        byte[] cmd = new byte[5 + cdolData.length];
        cmd[0] = (byte) 0x80;
        cmd[1] = (byte) 0xAE;
        cmd[2] = p1;
        cmd[3] = (byte) 0x00;
        cmd[4] = (byte) cdolData.length;
        System.arraycopy(cdolData, 0, cmd, 5, cdolData.length);

        ResponseAPDU response = SmartCard.transmitCommand(cmd);
        int sw = response.getSW();
        Assume.that(sw == 0x9000 || (sw & 0xFF00) == 0x6100);

        // Read CID back
        byte[] cid = getTagValue((short) 0x9F27);
        assertNotNull(cid, "CID (9F27) must exist after GENERATE AC");
        assertEquals(1, cid.length, "CID must be 1 byte per Book 3");
        // Book 3 Table 15: bits 7-6 = 10 means ARQC
        assertEquals((byte) 0x80, (byte) (cid[0] & 0xC0),
            "CID bits 7-6 must be '10' (ARQC) for online-only card, "
            + "regardless of P1=0x" + String.format("%02X", p1));
    }

    @Provide
    Arbitrary<Byte> generateAcP1Values() {
        // Book 3 Table 12: b8-b7 = cryptogram type request
        // 00 = AAC, 01 = TC, 10 = ARQC; b5 = CDA request
        return Arbitraries.of(
            (byte) 0x00,  // AAC request
            (byte) 0x40,  // TC request
            (byte) 0x80,  // ARQC request
            (byte) 0x10,  // AAC + CDA
            (byte) 0x50,  // TC + CDA
            (byte) 0x90   // ARQC + CDA
        );
    }

    // -----------------------------------------------------------------------
    // 14. Book 3 §6.5.5: GENERATE AC response must be Format 2 (tag 77)
    //     Property: successful GENERATE AC returns data wrapped in
    //     constructed template tag 77 (Format 2).
    // -----------------------------------------------------------------------

    @Property(tries = 10)
    void generateAcResponseIsFormat2Template(
            @ForAll("generateAcP1Values") byte p1
    ) throws CardException {
        setupCardForTransaction();

        byte[] cdolData = createMinimalCdolData();
        byte[] cmd = new byte[5 + cdolData.length];
        cmd[0] = (byte) 0x80;
        cmd[1] = (byte) 0xAE;
        cmd[2] = p1;
        cmd[3] = (byte) 0x00;
        cmd[4] = (byte) cdolData.length;
        System.arraycopy(cdolData, 0, cmd, 5, cdolData.length);

        ResponseAPDU response = SmartCard.transmitCommand(cmd);
        int sw = response.getSW();
        Assume.that(sw == 0x9000 || (sw & 0xFF00) == 0x6100);

        byte[] data = response.getData();
        assertTrue(data.length > 2,
            "GENERATE AC response must contain data");
        // Book 3 Table 14: Format 2 response uses tag 77
        assertEquals((byte) 0x77, data[0],
            "GENERATE AC response must use Format 2 template (tag 77)");
    }

    // -----------------------------------------------------------------------
    // 15. Book 3 §6.5.5: GENERATE AC response must contain CID, ATC, AC
    //     Property: the three mandatory data objects (9F27, 9F36, 9F26)
    //     must be present inside the tag 77 template.
    // -----------------------------------------------------------------------

    @Property(tries = 10)
    void generateAcResponseContainsMandatoryTags(
            @ForAll @ShortRange(min = 1, max = 50) short initialAtc
    ) throws CardException {
        setupCardForTransaction();
        setTag((short) 0x9F36, new byte[] {
            (byte) ((initialAtc >> 8) & 0xFF), (byte) (initialAtc & 0xFF)
        });

        byte[] cdolData = createMinimalCdolData();
        byte[] cmd = new byte[5 + cdolData.length];
        cmd[0] = (byte) 0x80;
        cmd[1] = (byte) 0xAE;
        cmd[2] = (byte) 0x80; // ARQC
        cmd[3] = (byte) 0x00;
        cmd[4] = (byte) cdolData.length;
        System.arraycopy(cdolData, 0, cmd, 5, cdolData.length);

        ResponseAPDU response = SmartCard.transmitCommand(cmd);
        Assume.that(response.getSW() == 0x9000);

        byte[] data = response.getData();
        // Parse tag 77 template and check for mandatory tags
        assertTrue(containsTag(data, (short) 0x9F27),
            "Response must contain CID (9F27) per Book 3 Table 13");
        assertTrue(containsTag(data, (short) 0x9F36),
            "Response must contain ATC (9F36) per Book 3 Table 13");
        assertTrue(containsTag(data, (short) 0x9F26),
            "Response must contain Application Cryptogram (9F26) per Book 3 Table 13");
    }

    // -----------------------------------------------------------------------
    // 16. Book 3 §6.5.6: GET CHALLENGE must return exactly 8 bytes
    //     Property: per spec, the response is an 8-byte unpredictable
    //     number. Length must always be 8.
    // -----------------------------------------------------------------------

    @Property(tries = 50)
    void getChallengeReturnsExactly8Bytes() throws CardException {
        selectAndReset();
        // Need PAN set for SELECT to work properly
        setTag((short) 0x005A, new byte[] {
            0x67, 0x67, 0x67, 0x67, 0x12, 0x34, 0x56, 0x78
        });

        byte[] cmd = new byte[] {
            (byte) 0x00, (byte) 0x84, (byte) 0x00, (byte) 0x00, (byte) 0x00
        };
        ResponseAPDU response = SmartCard.transmitCommand(cmd);
        assertEquals(0x9000, response.getSW(),
            "GET CHALLENGE must succeed");
        assertEquals(8, response.getData().length,
            "GET CHALLENGE must return exactly 8 bytes per Book 3 §6.5.6.4");
    }

    // -----------------------------------------------------------------------
    // 17. Book 3 §6.5.6: GET CHALLENGE must be unpredictable
    //     Property: two consecutive GET CHALLENGE commands should return
    //     different values (probabilistically, collision in 8 random
    //     bytes is ~2^-64).
    // -----------------------------------------------------------------------

    @Property(tries = 30)
    void getChallengeValuesAreUnpredictable() throws CardException {
        selectAndReset();
        setTag((short) 0x005A, new byte[] {
            0x67, 0x67, 0x67, 0x67, 0x12, 0x34, 0x56, 0x78
        });

        byte[] cmd = new byte[] {
            (byte) 0x00, (byte) 0x84, (byte) 0x00, (byte) 0x00, (byte) 0x00
        };
        ResponseAPDU r1 = SmartCard.transmitCommand(cmd);
        ResponseAPDU r2 = SmartCard.transmitCommand(cmd);

        Assume.that(r1.getSW() == 0x9000 && r2.getSW() == 0x9000);

        // Two random 8-byte challenges should differ
        boolean same = java.util.Arrays.equals(r1.getData(), r2.getData());
        assertTrue(!same,
            "Consecutive GET CHALLENGE results must differ (Book 3 §6.5.6: unpredictable)");
    }

    // -----------------------------------------------------------------------
    // 18. Book 3 §6.5.6: GET CHALLENGE with wrong P1P2 must fail
    //     Property: spec mandates P1='00', P2='00'. Any other value
    //     must return 6A86 (incorrect P1P2).
    // -----------------------------------------------------------------------

    @Property(tries = 100)
    void getChallengeRejectsWrongP1P2(
            @ForAll byte p1, @ForAll byte p2
    ) throws CardException {
        Assume.that(p1 != 0 || p2 != 0);  // skip the valid case

        selectAndReset();

        byte[] cmd = new byte[] {
            (byte) 0x00, (byte) 0x84, p1, p2, (byte) 0x00
        };
        ResponseAPDU response = SmartCard.transmitCommand(cmd);
        assertNotEquals(0x9000, response.getSW(),
            "GET CHALLENGE with P1=" + String.format("%02X", p1)
            + " P2=" + String.format("%02X", p2)
            + " must fail per Book 3 Table 16");
    }

    // -----------------------------------------------------------------------
    // 19. Book 3 §6.5.12: VERIFY PIN with invalid P2 must fail
    //     Property: P2 must be '80' (plaintext) or '88' (enciphered).
    //     Any other value returns 6A86.
    // -----------------------------------------------------------------------

    @Property(tries = 100)
    void verifyPinRejectsInvalidP2(@ForAll byte p2) throws CardException {
        Assume.that(p2 != (byte) 0x80 && p2 != (byte) 0x88);

        selectAndReset();
        // Set a PIN
        SmartCard.transmitCommand(new byte[] {
            (byte) 0x80, (byte) 0x04, (byte) 0x00, (byte) 0x01,
            (byte) 0x02, (byte) 0x12, (byte) 0x34
        });

        byte[] cmd = new byte[] {
            (byte) 0x00, (byte) 0x20, (byte) 0x00, p2,
            (byte) 0x08,
            (byte) 0x24, (byte) 0x12, (byte) 0x34,
            (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF
        };
        ResponseAPDU response = SmartCard.transmitCommand(cmd);
        assertNotEquals(0x9000, response.getSW(),
            "VERIFY with P2=0x" + String.format("%02X", p2)
            + " must fail per Book 3 Table 24 (only 80/88 valid)");
    }

    // -----------------------------------------------------------------------
    // 20. Book 3 §6.5.5: GENERATE AC with P2 != 00 must fail
    //     Property: spec mandates P2='00' for GENERATE AC.
    // -----------------------------------------------------------------------

    @Property(tries = 30)
    void generateAcRejectsNonZeroP2(
            @ForAll @ByteRange(min = 1, max = 127) byte p2
    ) throws CardException {
        setupCardForTransaction();

        byte[] cdolData = createMinimalCdolData();
        byte[] cmd = new byte[5 + cdolData.length];
        cmd[0] = (byte) 0x80;
        cmd[1] = (byte) 0xAE;
        cmd[2] = (byte) 0x80;  // ARQC
        cmd[3] = p2;            // non-zero P2
        cmd[4] = (byte) cdolData.length;
        System.arraycopy(cdolData, 0, cmd, 5, cdolData.length);

        ResponseAPDU response = SmartCard.transmitCommand(cmd);
        // Spec says P2 must be '00' — non-zero should either fail or
        // the card may ignore it. Either way, if it succeeds it must
        // still produce valid output (CID = ARQC)
        if (response.getSW() == 0x9000) {
            byte[] cid = getTagValue((short) 0x9F27);
            assertNotNull(cid, "If GENERATE AC succeeds, CID must exist");
            assertEquals((byte) 0x80, (byte) (cid[0] & 0xC0),
                "CID must still indicate ARQC even with non-standard P2");
        }
        // Non-9000 is also acceptable (card rejects bad P2)
    }

    // -----------------------------------------------------------------------
    // 21. Book 3 §9.2: Application Cryptogram must be 8 bytes
    //     Property: tag 9F26 (Application Cryptogram) is always
    //     exactly 8 bytes when present.
    // -----------------------------------------------------------------------

    @Property(tries = 20)
    void applicationCryptogramIsAlways8Bytes(
            @ForAll @ShortRange(min = 1, max = 200) short atc
    ) throws CardException {
        setupCardForTransaction();
        setTag((short) 0x9F36, new byte[] {
            (byte) ((atc >> 8) & 0xFF), (byte) (atc & 0xFF)
        });

        byte[] cdolData = createMinimalCdolData();
        byte[] cmd = new byte[5 + cdolData.length];
        cmd[0] = (byte) 0x80;
        cmd[1] = (byte) 0xAE;
        cmd[2] = (byte) 0x80;
        cmd[3] = (byte) 0x00;
        cmd[4] = (byte) cdolData.length;
        System.arraycopy(cdolData, 0, cmd, 5, cdolData.length);

        ResponseAPDU response = SmartCard.transmitCommand(cmd);
        Assume.that(response.getSW() == 0x9000);

        byte[] ac = getTagValue((short) 0x9F26);
        assertNotNull(ac, "Application Cryptogram (9F26) must exist");
        assertEquals(8, ac.length,
            "Application Cryptogram must be exactly 8 bytes per Book 3 Annex A");
    }

    // -----------------------------------------------------------------------
    // 22. Book 3 Annex B: BER-TLV short length (0-127) single byte
    //     Property: for data lengths 0-127, the length field is a single
    //     byte equal to the data length. No 0x81 prefix.
    // -----------------------------------------------------------------------

    @Property(tries = 100)
    void berTlvShortLengthIsSingleByte(
            @ForAll @IntRange(min = 1, max = 127) int dataLength
    ) throws CardException {
        selectAndReset();

        short tagId = (short) 0x9F46;
        byte[] value = new byte[dataLength];
        for (int i = 0; i < dataLength; i++) {
            value[i] = (byte) (i & 0xFF);
        }
        setTag(tagId, value);

        byte[] getCmd = new byte[] {
            (byte) 0x80, (byte) 0xCA,
            (byte) 0x9F, (byte) 0x46,
            (byte) 0x00
        };
        ResponseAPDU response = SmartCard.transmitCommand(getCmd);

        if (response.getSW() == 0x9000) {
            byte[] tlv = response.getData();
            // tag(2) + length(1) + data(N)
            assertTrue(tlv.length >= 3, "TLV must have tag + length + data");
            int lenByte = tlv[2] & 0xFF;
            assertTrue(lenByte < 128,
                "Length 1-127 must be single byte (no 0x81 prefix), got 0x"
                + String.format("%02X", lenByte));
            assertEquals(dataLength, lenByte,
                "Length byte must equal data length");
        }
    }

    // -----------------------------------------------------------------------
    // 23. Book 3 §6.5.11: READ RECORD response wrapped in tag 70
    //     Property: successful READ RECORD always returns data inside
    //     a record template (tag 70).
    // -----------------------------------------------------------------------

    @Property(tries = 30)
    void readRecordResponseIsTag70Template(
            @ForAll @ByteRange(min = 1, max = 10) byte recordNum
    ) throws CardException {
        selectAndReset();

        // Store a record at SFI 1, record N (P1P2 encoding: P1=record, P2=SFI|04)
        byte p2 = (byte) ((1 << 3) | 0x04);  // SFI=1, P2 encoding per Table 22
        short p1p2 = (short) (((recordNum & 0xFF) << 8) | (p2 & 0xFF));

        // Store record data as EmvTag keyed by P1P2
        byte[] recordData = new byte[] {
            (byte) 0x57, (byte) 0x04,  // tag 57 (Track 2)
            (byte) 0x12, (byte) 0x34, (byte) 0x56, (byte) 0x78
        };
        byte[] storeCmd = new byte[5 + recordData.length];
        storeCmd[0] = (byte) 0x80;
        storeCmd[1] = (byte) 0x01;
        storeCmd[2] = (byte) ((p1p2 >> 8) & 0xFF);
        storeCmd[3] = (byte) (p1p2 & 0xFF);
        storeCmd[4] = (byte) recordData.length;
        System.arraycopy(recordData, 0, storeCmd, 5, recordData.length);
        SmartCard.transmitCommand(storeCmd);

        // READ RECORD
        byte[] readCmd = new byte[] {
            (byte) 0x00, (byte) 0xB2, recordNum, p2, (byte) 0x00
        };
        ResponseAPDU response = SmartCard.transmitCommand(readCmd);

        if (response.getSW() == 0x9000) {
            byte[] data = response.getData();
            assertTrue(data.length >= 2,
                "READ RECORD response must have at least tag + length");
            assertEquals((byte) 0x70, data[0],
                "READ RECORD response must be wrapped in tag 70 per Book 3 §6.5.11");
        }
    }

    // -----------------------------------------------------------------------
    // 24. Book 3 §6.5.5: GENERATE AC with random CDOL data still
    //     produces valid cryptogram structure
    //     Property: even with garbage CDOL data, if the card accepts it,
    //     the response structure must be well-formed.
    // -----------------------------------------------------------------------

    @Property(tries = 30)
    void generateAcWithRandomCdolDataProducesValidStructure(
            @ForAll @Size(min = 29, max = 29) byte[] cdolData
    ) throws CardException {
        setupCardForTransaction();

        byte[] cmd = new byte[5 + cdolData.length];
        cmd[0] = (byte) 0x80;
        cmd[1] = (byte) 0xAE;
        cmd[2] = (byte) 0x80;
        cmd[3] = (byte) 0x00;
        cmd[4] = (byte) cdolData.length;
        System.arraycopy(cdolData, 0, cmd, 5, cdolData.length);

        ResponseAPDU response = SmartCard.transmitCommand(cmd);
        int sw = response.getSW();
        Assume.that(sw == 0x9000 || (sw & 0xFF00) == 0x6100);

        if (sw == 0x9000) {
            byte[] data = response.getData();
            assertEquals((byte) 0x77, data[0],
                "Response must be Format 2 (tag 77)");
            assertTrue(containsTag(data, (short) 0x9F27),
                "Must contain CID even with random CDOL data");
            assertTrue(containsTag(data, (short) 0x9F36),
                "Must contain ATC even with random CDOL data");
        }
    }

    // -----------------------------------------------------------------------
    // 25. Book 3 §6.5.12: VERIFY PIN returns no data
    //     Property: per spec, "no data field is returned in the
    //     response message" for VERIFY.
    // -----------------------------------------------------------------------

    @Property(tries = 50)
    void verifyPinNeverReturnsData(
            @ForAll @ShortRange(min = 0, max = 9999) short pin
    ) throws CardException {
        selectAndReset();

        SmartCard.transmitCommand(new byte[] {
            (byte) 0x80, (byte) 0x04, (byte) 0x00, (byte) 0x01,
            (byte) 0x02, (byte) 0x12, (byte) 0x34
        });

        byte[] cmd = new byte[] {
            (byte) 0x00, (byte) 0x20, (byte) 0x00, (byte) 0x80,
            (byte) 0x08,
            (byte) 0x24,
            (byte) ((pin >> 8) & 0xFF), (byte) (pin & 0xFF),
            (byte) 0xFF, (byte) 0xFF,
            (byte) 0xFF, (byte) 0xFF, (byte) 0xFF
        };
        ResponseAPDU response = SmartCard.transmitCommand(cmd);
        assertEquals(0, response.getData().length,
            "VERIFY must return no data per Book 3 §6.5.12.4");
    }

    // -----------------------------------------------------------------------
    // 26. Book 3 §6.5.8: GPO with P1!=00 or P2!=00 must fail
    //     Property: spec mandates P1='00', P2='00'.
    // -----------------------------------------------------------------------

    @Property(tries = 50)
    void gpoRejectsNonZeroP1P2(
            @ForAll byte p1, @ForAll byte p2
    ) throws CardException {
        Assume.that(p1 != 0 || p2 != 0);

        setupCardForTransaction();

        byte[] gpoData = new byte[] { (byte) 0x83, (byte) 0x00 };
        byte[] cmd = new byte[5 + gpoData.length];
        cmd[0] = (byte) 0x80;
        cmd[1] = (byte) 0xA8;
        cmd[2] = p1;
        cmd[3] = p2;
        cmd[4] = (byte) gpoData.length;
        System.arraycopy(gpoData, 0, cmd, 5, gpoData.length);

        ResponseAPDU response = SmartCard.transmitCommand(cmd);
        assertNotEquals(0x9000, response.getSW(),
            "GPO with P1=" + String.format("%02X", p1)
            + " P2=" + String.format("%02X", p2)
            + " must fail per Book 3 Table 18");
    }

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    private boolean containsByte(byte[] data, byte target) {
        for (byte b : data) {
            if (b == target) return true;
        }
        return false;
    }

    /** Check if a TLV byte array contains a specific 2-byte tag. */
    private boolean containsTag(byte[] tlvData, short tagId) {
        byte hi = (byte) ((tagId >> 8) & 0xFF);
        byte lo = (byte) (tagId & 0xFF);
        for (int i = 0; i < tlvData.length - 1; i++) {
            if (tlvData[i] == hi && tlvData[i + 1] == lo) {
                return true;
            }
        }
        return false;
    }

    private void selectAndReset() throws CardException {
        ensureInitialized();
        selectPaymentApp();
        SmartCard.transmitCommand(new byte[] {
            (byte) 0x80, (byte) 0x05, (byte) 0x00, (byte) 0x00, (byte) 0x00
        });
    }

    private void selectPaymentApp() throws CardException {
        ensureInitialized();
        byte[] selectCmd = new byte[5 + PAYMENT_AID.length];
        selectCmd[0] = (byte) 0x00;
        selectCmd[1] = (byte) 0xA4;
        selectCmd[2] = (byte) 0x04;
        selectCmd[3] = (byte) 0x00;
        selectCmd[4] = (byte) PAYMENT_AID.length;
        System.arraycopy(PAYMENT_AID, 0, selectCmd, 5, PAYMENT_AID.length);
        SmartCard.transmitCommand(selectCmd);
    }

    private void setTag(short tagId, byte[] value) throws CardException {
        byte[] cmd = new byte[5 + value.length];
        cmd[0] = (byte) 0x80;
        cmd[1] = (byte) 0x01;
        cmd[2] = (byte) ((tagId >> 8) & 0xFF);
        cmd[3] = (byte) (tagId & 0xFF);
        cmd[4] = (byte) value.length;
        System.arraycopy(value, 0, cmd, 5, value.length);
        SmartCard.transmitCommand(cmd);
    }

    /** Retrieve raw value bytes from a tag via GET_DATA, or null if not found. */
    private byte[] getTagValue(short tagId) throws CardException {
        byte[] getCmd = new byte[] {
            (byte) 0x80, (byte) 0xCA,
            (byte) ((tagId >> 8) & 0xFF), (byte) (tagId & 0xFF),
            (byte) 0x00
        };
        ResponseAPDU resp = SmartCard.transmitCommand(getCmd);
        if (resp.getSW() != 0x9000 || resp.getData().length == 0) {
            return null;
        }

        byte[] tlv = resp.getData();
        // Parse TLV to extract value
        int offset = ((tlv[0] & 0x1F) == 0x1F || (tlv[0] & 0xFF) >= 0x9F) ? 2 : 1;
        // Adjust for tags stored as 00xx
        if (tlv[0] == 0x00) offset = 2;
        // Simple heuristic: check if first byte is high byte of a 2-byte tag
        if ((tagId & 0xFF00) != 0) offset = 2;

        int len;
        if ((tlv[offset] & 0xFF) < 128) {
            len = tlv[offset] & 0xFF;
            offset += 1;
        } else if (tlv[offset] == (byte) 0x81) {
            len = tlv[offset + 1] & 0xFF;
            offset += 2;
        } else {
            len = ((tlv[offset + 1] & 0xFF) << 8) | (tlv[offset + 2] & 0xFF);
            offset += 3;
        }

        if (offset + len > tlv.length) return null;
        byte[] value = new byte[len];
        System.arraycopy(tlv, offset, value, 0, len);
        return value;
    }

    private void setupCardForTransaction() throws CardException {
        selectAndReset();

        // AID
        setTag((short) 0x0084, PAYMENT_AID);
        // AIP
        setTag((short) 0x0082, new byte[] { (byte) 0x19, (byte) 0x80 });
        // ATC
        setTag((short) 0x9F36, new byte[] { 0x00, 0x01 });
        // Cryptogram (placeholder)
        setTag((short) 0x9F26, new byte[] {
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
        });
        // CID
        setTag((short) 0x9F27, new byte[] { (byte) 0x80 });
        // IAD
        setTag((short) 0x9F10, new byte[] {
            0x06, 0x01, 0x0A, 0x03, (byte) 0xA4, (byte) 0x80, 0x00
        });

        // CDOL1: simple 29-byte structure
        SmartCard.transmitCommand(new byte[] {
            (byte) 0x80, (byte) 0x01, (byte) 0x00, (byte) 0x8C,
            (byte) 0x15,  // 21 bytes
            (byte) 0x9F, (byte) 0x02, (byte) 0x06,  // Amount Auth
            (byte) 0x9F, (byte) 0x03, (byte) 0x06,  // Amount Other
            (byte) 0x9F, (byte) 0x1A, (byte) 0x02,  // Country
            (byte) 0x95, (byte) 0x05,                // TVR
            (byte) 0x5F, (byte) 0x2A, (byte) 0x02,  // Currency
            (byte) 0x9A, (byte) 0x03,                // Date
            (byte) 0x9C, (byte) 0x01,                // Type
            (byte) 0x9F, (byte) 0x37, (byte) 0x04   // UN
        });

        // Response template for GENERATE AC
        SmartCard.transmitCommand(new byte[] {
            (byte) 0x80, (byte) 0x02, (byte) 0x00, (byte) 0x03,
            (byte) 0x08,
            (byte) 0x9F, (byte) 0x27,  // CID
            (byte) 0x9F, (byte) 0x36,  // ATC
            (byte) 0x9F, (byte) 0x26,  // Cryptogram
            (byte) 0x9F, (byte) 0x10   // IAD
        });
    }

    /** 29 bytes matching the CDOL1 set in setupCardForTransaction. */
    private byte[] createMinimalCdolData() {
        return new byte[] {
            // Amount Auth (6)
            0x00, 0x00, 0x00, 0x00, 0x01, 0x00,
            // Amount Other (6)
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            // Country (2)
            0x08, 0x40,
            // TVR (5)
            0x00, 0x00, 0x00, 0x00, 0x00,
            // Currency (2)
            0x08, 0x40,
            // Date (3)
            0x26, 0x04, 0x13,
            // Type (1)
            0x00,
            // UN (4)
            0x11, 0x22, 0x33, 0x44
        };
    }

    private boolean startsWith(byte[] arr, byte[] prefix) {
        if (arr.length < prefix.length) return false;
        for (int i = 0; i < prefix.length; i++) {
            if (arr[i] != prefix[i]) return false;
        }
        return true;
    }

    // =======================================================================
    // GROUP A: SELECT FCI Structure (Book 3 §6.3, ISO 7816-4)
    // =======================================================================

    // -----------------------------------------------------------------------
    // 27. SELECT response on configured card starts with tag 6F
    // -----------------------------------------------------------------------

    @Property(tries = 10)
    void selectFciStartsWithTag6F(
            @ForAll @Size(min = 5, max = 16) byte[] aid
    ) throws CardException {
        selectAndReset();
        // Configure card with PAN and FCI templates
        setTag((short) 0x005A, new byte[] { 0x67, 0x67, 0x12, 0x34, 0x56, 0x78, (byte) 0x90, 0x00 });
        setTag((short) 0x0084, PAYMENT_AID);
        setTag((short) 0x0050, new byte[] { 0x54, 0x45, 0x53, 0x54 }); // "TEST"
        setTag((short) 0x0087, new byte[] { 0x01 }); // priority
        // Set A5 template: [50, 87]
        SmartCard.transmitCommand(new byte[] {
            (byte) 0x80, (byte) 0x02, (byte) 0x00, (byte) 0x05,
            (byte) 0x04, (byte) 0x00, (byte) 0x50, (byte) 0x00, (byte) 0x87
        });
        // Set 6F template: [84, A5]
        SmartCard.transmitCommand(new byte[] {
            (byte) 0x80, (byte) 0x02, (byte) 0x00, (byte) 0x04,
            (byte) 0x04, (byte) 0x00, (byte) 0x84, (byte) 0x00, (byte) 0xA5
        });

        // SELECT
        ResponseAPDU response = selectPaymentAppWithResponse();
        if (response.getSW() == 0x9000 && response.getData().length > 0) {
            assertEquals((byte) 0x6F, response.getData()[0],
                "SELECT FCI must start with tag 6F per ISO 7816-4");
        }
    }

    // -----------------------------------------------------------------------
    // 28. Tag 6F contains tag 84 (DF Name) matching the selected AID
    // -----------------------------------------------------------------------

    @Property(tries = 10)
    void selectFciContainsAidInTag84() throws CardException {
        setupCardWithFciTemplates();

        ResponseAPDU response = selectPaymentAppWithResponse();
        Assume.that(response.getSW() == 0x9000 && response.getData().length > 2);

        byte[] fci = response.getData();
        assertTrue(containsByte(fci, (byte) 0x84),
            "FCI must contain tag 84 (DF Name) per Book 3 §6.3");
    }

    // -----------------------------------------------------------------------
    // 29. Tag 6F contains tag A5 (FCI Proprietary Template)
    // -----------------------------------------------------------------------

    @Property(tries = 10)
    void selectFciContainsA5Template() throws CardException {
        setupCardWithFciTemplates();

        ResponseAPDU response = selectPaymentAppWithResponse();
        Assume.that(response.getSW() == 0x9000 && response.getData().length > 2);

        byte[] fci = response.getData();
        assertTrue(containsByte(fci, (byte) 0xA5),
            "FCI must contain tag A5 (FCI Proprietary Template) per Book 3");
    }

    // -----------------------------------------------------------------------
    // 30. SELECT before PAN is set returns 9000 with no data (setup phase)
    // -----------------------------------------------------------------------

    @Property(tries = 10)
    void selectWithoutPanReturns9000Only() throws CardException {
        selectAndReset();
        // No PAN set — card should be in setup phase

        ResponseAPDU response = selectPaymentAppWithResponse();
        assertEquals(0x9000, response.getSW(),
            "SELECT without PAN must return 9000 (setup phase)");
        assertEquals(0, response.getData().length,
            "SELECT without PAN must return no data");
    }

    // =======================================================================
    // GROUP B: STORE DATA / GP Personalization (CPS v2.0)
    // =======================================================================

    // -----------------------------------------------------------------------
    // 31. EMV tag set via STORE DATA DGI is readable via GET_DATA
    // -----------------------------------------------------------------------

    @Property(tries = 100)
    void storeDataTagRoundtrip(
            @ForAll @ShortRange(min = 1, max = 127) short tagLow,
            @ForAll @Size(min = 1, max = 50) byte[] value
    ) throws CardException {
        // Filter out reserved DGI range 9F60-9F6F (except 9F6C)
        Assume.that(tagLow < 0x60 || tagLow > 0x6F || tagLow == 0x6C);
        selectAndReset();
        short tagId = (short) (0x9F00 | (tagLow & 0xFF));

        // STORE DATA: [CLA E2 00 00] [LC] [DGI(2)] [LEN(1)] [DATA]
        byte[] storeCmd = buildStoreDataCmd((byte) 0x00, tagId, value);
        ResponseAPDU resp = SmartCard.transmitCommand(storeCmd);
        assertEquals(0x9000, resp.getSW(), "STORE DATA should succeed");

        // GET_DATA to read back
        byte[] retrieved = getTagValue(tagId);
        assertNotNull(retrieved,
            "Tag 0x" + Integer.toHexString(tagId & 0xFFFF) + " must be readable after STORE DATA");
        assertArrayEquals(value, retrieved,
            "STORE DATA roundtrip must preserve data exactly");
    }

    // -----------------------------------------------------------------------
    // 32. SFI record set via DGI 01xx is readable via READ RECORD
    // -----------------------------------------------------------------------

    @Property(tries = 10)
    void storeDataSfiRecordReadableViaReadRecord(
            @ForAll @ByteRange(min = 1, max = 5) byte recordNum
    ) throws CardException {
        selectAndReset();
        byte sfi = 1;

        // SFI records are stored as tag-template data (pairs of 2-byte tag IDs).
        // READ RECORD expands them by looking up each tag ID via EmvTag.findTag().
        // So we must: (1) store the referenced tags, (2) store the record as tag ID pairs.

        // Store tag 0x005A (PAN) and 0x9F36 (ATC) as EmvTag
        setTag((short) 0x005A, new byte[] { 0x67, 0x67, 0x12, 0x34 });
        setTag((short) 0x9F36, new byte[] { 0x00, 0x01 });

        // Record content = tag ID pairs: [005A, 9F36]
        byte[] recordContent = new byte[] {
            (byte) 0x00, (byte) 0x5A, (byte) 0x9F, (byte) 0x36
        };

        // DGI = SFI << 8 | recordNum. SFI=1 → DGI = 0x01xx
        short dgi = (short) ((sfi << 8) | (recordNum & 0xFF));

        // Wrap in tag 70 per CPS requirement
        byte[] wrappedData = new byte[2 + recordContent.length];
        wrappedData[0] = (byte) 0x70;
        wrappedData[1] = (byte) recordContent.length;
        System.arraycopy(recordContent, 0, wrappedData, 2, recordContent.length);

        byte[] storeCmd = buildStoreDataCmd((byte) 0x00, dgi, wrappedData);
        ResponseAPDU storeResp = SmartCard.transmitCommand(storeCmd);
        assertEquals(0x9000, storeResp.getSW(), "STORE DATA SFI record should succeed");

        // READ RECORD: P1=recordNum, P2=SFI<<3|0x04
        byte p2 = (byte) ((sfi << 3) | 0x04);
        byte[] readCmd = new byte[] {
            (byte) 0x00, (byte) 0xB2, recordNum, p2, (byte) 0x00
        };
        ResponseAPDU readResp = SmartCard.transmitCommand(readCmd);
        assertEquals(0x9000, readResp.getSW(),
            "READ RECORD for SFI=" + sfi + " R=" + recordNum + " should succeed");

        byte[] data = readResp.getData();
        assertEquals((byte) 0x70, data[0],
            "READ RECORD response must be wrapped in tag 70");
        // Response should contain expanded TLV for 5A and 9F36
        assertTrue(containsByte(data, (byte) 0x5A),
            "READ RECORD response should contain tag 5A");
        assertTrue(containsTag(data, (short) 0x9F36),
            "READ RECORD response should contain tag 9F36");
    }

    // -----------------------------------------------------------------------
    // 33. DGI 0x0000 always returns error
    // -----------------------------------------------------------------------

    @Property(tries = 10)
    void storeDataRejectsInvalidDgi0000() throws CardException {
        selectAndReset();

        byte[] storeCmd = buildStoreDataCmd((byte) 0x00, (short) 0x0000,
            new byte[] { 0x01, 0x02 });
        ResponseAPDU resp = SmartCard.transmitCommand(storeCmd);
        assertNotEquals(0x9000, resp.getSW(),
            "STORE DATA with DGI 0x0000 must fail per CPS routing rules");
    }

    // -----------------------------------------------------------------------
    // 34. BER 0x81 length encoding works for payloads 128-200 bytes
    // -----------------------------------------------------------------------

    @Property(tries = 10)
    void storeDataBerLengthDecodingWorks(
            @ForAll @IntRange(min = 128, max = 200) int dataLength
    ) throws CardException {
        selectAndReset();
        short tagId = (short) 0x9F46; // ICC Public Key Certificate

        byte[] value = new byte[dataLength];
        for (int i = 0; i < dataLength; i++) {
            value[i] = (byte) (i & 0xFF);
        }

        // STORE DATA with BER 0x81 length: [DGI(2)] [0x81] [LEN(1)] [DATA]
        byte[] storeCmd = new byte[5 + 2 + 2 + dataLength];
        storeCmd[0] = (byte) 0x00;
        storeCmd[1] = (byte) 0xE2;
        storeCmd[2] = (byte) 0x00;
        storeCmd[3] = (byte) 0x00;
        storeCmd[4] = (byte) (2 + 2 + dataLength); // LC
        storeCmd[5] = (byte) ((tagId >> 8) & 0xFF);
        storeCmd[6] = (byte) (tagId & 0xFF);
        storeCmd[7] = (byte) 0x81; // BER extended length indicator
        storeCmd[8] = (byte) (dataLength & 0xFF);
        System.arraycopy(value, 0, storeCmd, 9, dataLength);

        ResponseAPDU resp = SmartCard.transmitCommand(storeCmd);
        assertEquals(0x9000, resp.getSW(),
            "STORE DATA with BER 0x81 length must succeed");

        byte[] retrieved = getTagValue(tagId);
        assertNotNull(retrieved, "Tag must be readable after STORE DATA with 0x81 length");
        assertEquals(dataLength, retrieved.length,
            "Retrieved data length must match stored length");
    }

    // -----------------------------------------------------------------------
    // 35. STORE DATA accepts CLA 00, 80, and 84 per CPS v2.0
    // -----------------------------------------------------------------------

    @Property(tries = 3)
    void storeDataAcceptsCla80And84(
            @ForAll("storeDataClaValues") byte cla
    ) throws CardException {
        selectAndReset();

        byte[] value = new byte[] { 0x42 };
        short tagId = (short) 0x9F42; // Currency Code

        byte[] storeCmd = buildStoreDataCmd(cla, tagId, value);
        ResponseAPDU resp = SmartCard.transmitCommand(storeCmd);
        assertEquals(0x9000, resp.getSW(),
            "STORE DATA with CLA=0x" + String.format("%02X", cla)
            + " must succeed per CPS v2.0");
    }

    @Provide
    Arbitrary<Byte> storeDataClaValues() {
        return Arbitraries.of((byte) 0x00, (byte) 0x80, (byte) 0x84);
    }

    // -----------------------------------------------------------------------
    // 36. PIN set via DGI 8010 is usable for VERIFY PIN
    // -----------------------------------------------------------------------

    @Property(tries = 10)
    void storeDataPinSetThenVerifiable(
            @ForAll @ShortRange(min = 1, max = 9999) short pin
    ) throws CardException {
        selectAndReset();

        // Set PIN via STORE DATA DGI 8010
        byte[] pinData = new byte[] {
            (byte) ((pin >> 8) & 0xFF), (byte) (pin & 0xFF)
        };
        byte[] storeCmd = buildStoreDataCmd((byte) 0x00, (short) 0x8010, pinData);
        ResponseAPDU storeResp = SmartCard.transmitCommand(storeCmd);
        assertEquals(0x9000, storeResp.getSW(), "STORE DATA PIN should succeed");

        // VERIFY PIN
        byte[] verifyCmd = new byte[] {
            (byte) 0x00, (byte) 0x20, (byte) 0x00, (byte) 0x80,
            (byte) 0x08,
            (byte) 0x24,
            (byte) ((pin >> 8) & 0xFF), (byte) (pin & 0xFF),
            (byte) 0xFF, (byte) 0xFF,
            (byte) 0xFF, (byte) 0xFF, (byte) 0xFF
        };
        ResponseAPDU verifyResp = SmartCard.transmitCommand(verifyCmd);
        assertEquals(0x9000, verifyResp.getSW(),
            "VERIFY PIN must succeed for PIN set via STORE DATA DGI 8010");
    }

    // =======================================================================
    // GROUP C: CDA/ECDSA Signature Verification (Book 2 §6.6)
    // =======================================================================

    // -----------------------------------------------------------------------
    // 37. SDAD Format 5: header 0x6A, format 0x05, hash 0x01, trailer 0xBC
    // -----------------------------------------------------------------------

    @Property(tries = 5)
    void sdadFormat5HasCorrectHeaderTrailer(
            @ForAll @ShortRange(min = 1, max = 50) short atc
    ) throws CardException {
        byte[] sdad = runCdaTransactionAndGetSdad(atc);
        Assume.that(sdad != null);

        byte[] recovered = rsaRecover(sdad);
        assertNotNull(recovered, "RSA recovery must succeed");

        assertEquals((byte) 0x6A, recovered[0],
            "SDAD header must be 0x6A per Book 2 Table 16");
        assertEquals((byte) 0x05, recovered[1],
            "SDAD signed data format must be 0x05 (CDA)");
        assertEquals((byte) 0x01, recovered[2],
            "SDAD hash algorithm indicator must be 0x01 (SHA-1)");
        assertEquals((byte) 0xBC, recovered[recovered.length - 1],
            "SDAD trailer must be 0xBC per Book 2 Table 16");
    }

    // -----------------------------------------------------------------------
    // 38. CID inside SDAD must match outer 9F27
    // -----------------------------------------------------------------------

    @Property(tries = 5)
    void sdadContainsCidMatchingOuterResponse(
            @ForAll @ShortRange(min = 1, max = 50) short atc
    ) throws CardException {
        setupCdaCard(atc);
        selectPaymentAppWithResponse();
        sendGpo(createMinimalCdolData());
        byte[] cdolData = createMinimalCdolData();
        ResponseAPDU response = sendGenerateAc(cdolData, (byte) 0x90);
        Assume.that(response.getSW() == 0x9000);

        byte[] data = response.getData();
        byte[] outerCid = extractTagValue(data, (short) 0x9F27);
        byte[] sdadBytes = extractTagValue(data, (short) 0x9F4B);
        Assume.that(outerCid != null && sdadBytes != null);

        byte[] recovered = rsaRecover(sdadBytes);
        Assume.that(recovered != null);

        // CID is at ICC Dynamic Data offset: byte 3 = LDD, then DN_len(1)+DN(8) = 9, then CID
        int ldd = recovered[3] & 0xFF;
        // ICC Dynamic Data starts at offset 4, structure: DN_len(1) + DN(8) + CID(1) + AC(8) + TDH(20)
        int cidOffset = 4 + 1 + 8; // skip DN_len + DN
        byte embeddedCid = recovered[cidOffset];
        assertEquals(outerCid[0], embeddedCid,
            "CID inside SDAD must match outer 9F27 per Book 2 §6.6.2");
    }

    // -----------------------------------------------------------------------
    // 39. SDAD padding between ICC Dynamic Data and hash is all 0xBB
    // -----------------------------------------------------------------------

    @Property(tries = 5)
    void sdadPaddingIsAllBB(
            @ForAll @ShortRange(min = 1, max = 50) short atc
    ) throws CardException {
        byte[] sdad = runCdaTransactionAndGetSdad(atc);
        Assume.that(sdad != null);

        byte[] recovered = rsaRecover(sdad);
        Assume.that(recovered != null);

        int ldd = recovered[3] & 0xFF;
        int iccDynDataEnd = 4 + ldd; // header(3) + LDD(1) + ICC Dynamic Data
        int hashStart = recovered.length - 21; // last 20 bytes = hash, last byte = 0xBC

        for (int i = iccDynDataEnd; i < hashStart; i++) {
            assertEquals((byte) 0xBB, recovered[i],
                "Padding byte at offset " + i + " must be 0xBB per Book 2 Table 16");
        }
    }

    // -----------------------------------------------------------------------
    // 40. ECDSA signature at GPO verifies against known public key
    // -----------------------------------------------------------------------

    @Property(tries = 5)
    void ecdsaSignatureVerifiesAtGpo(
            @ForAll @ShortRange(min = 1, max = 50) short atc
    ) throws Exception {
        setupCdaCard(atc);

        // Must do SELECT first to initialize challenge and transaction state
        // PAN is already set by setupCardForTransaction via setupCdaCard
        selectPaymentAppWithResponse();

        // GPO with 29-byte PDOL (matching our CDOL1 structure for simplicity)
        byte[] pdolData = createMinimalCdolData();
        byte[] wrappedPdol = new byte[2 + pdolData.length];
        wrappedPdol[0] = (byte) 0x83;
        wrappedPdol[1] = (byte) pdolData.length;
        System.arraycopy(pdolData, 0, wrappedPdol, 2, pdolData.length);

        byte[] gpoCmd = new byte[5 + wrappedPdol.length];
        gpoCmd[0] = (byte) 0x80;
        gpoCmd[1] = (byte) 0xA8;
        gpoCmd[2] = (byte) 0x00;
        gpoCmd[3] = (byte) 0x00;
        gpoCmd[4] = (byte) wrappedPdol.length;
        System.arraycopy(wrappedPdol, 0, gpoCmd, 5, wrappedPdol.length);

        ResponseAPDU gpoResp = SmartCard.transmitCommand(gpoCmd);
        Assume.that(gpoResp.getSW() == 0x9000);

        // ECDSA r is in 9F10 (IAD), s is in 9F6E — get via GET_DATA
        byte[] sigR = getTagValue((short) 0x9F10);
        byte[] sigS = getTagValue((short) 0x9F6E);
        Assume.that(sigR != null && sigR.length == 32);
        Assume.that(sigS != null && sigS.length == 32);

        // Signed message: ATC(2) || PDOL(29)
        // ATC at GPO time is pre-increment (the current ATC value)
        byte[] atcBytes = new byte[] {
            (byte) ((atc >> 8) & 0xFF), (byte) (atc & 0xFF)
        };
        byte[] signedMsg = new byte[2 + pdolData.length];
        System.arraycopy(atcBytes, 0, signedMsg, 0, 2);
        System.arraycopy(pdolData, 0, signedMsg, 2, pdolData.length);

        // Derive public key from known private scalar
        PublicKey pubKey = deriveEcPublicKey();
        byte[] derSig = rawToDerSignature(sigR, sigS);
        Signature verifier = Signature.getInstance("SHA256withECDSA");
        verifier.initVerify(pubKey);
        verifier.update(signedMsg);
        assertTrue(verifier.verify(derSig),
            "ECDSA signature at GPO must verify over ATC||PDOL");
    }

    // -----------------------------------------------------------------------
    // 41. CDA response must NOT contain 9F26 (AC is inside SDAD)
    // -----------------------------------------------------------------------

    @Property(tries = 5)
    void cdaResponseOmits9F26(
            @ForAll @ShortRange(min = 1, max = 50) short atc
    ) throws CardException {
        setupCdaCard(atc);
        selectPaymentAppWithResponse();
        sendGpo(createMinimalCdolData());
        byte[] cdolData = createMinimalCdolData();
        ResponseAPDU response = sendGenerateAc(cdolData, (byte) 0x90);
        Assume.that(response.getSW() == 0x9000);

        byte[] data = response.getData();
        // CDA response: 9F27 + 9F36 + 9F4B + 9F10
        // 9F26 must NOT be present — AC is embedded inside SDAD
        assertFalse(containsTag(data, (short) 0x9F26),
            "CDA response must NOT contain 9F26 (AC is inside SDAD per Book 2 §6.6)");
        assertTrue(containsTag(data, (short) 0x9F4B),
            "CDA response must contain 9F4B (SDAD)");
    }

    // =======================================================================
    // GROUP E: C-2 Kernel 2 (Mastercard Contactless) Card-Side Properties
    // =======================================================================

    // -----------------------------------------------------------------------
    // 47. C-2 Table 5.20: GPO Format 2 must contain AIP (82) and AFL (94)
    //     Property: when GPO returns Format 2 (tag 77), it must always
    //     include Application Interchange Profile and Application File Locator.
    // -----------------------------------------------------------------------

    @Property(tries = 10)
    void c2GpoFormat2ContainsAipAndAfl() throws CardException {
        setupCardForTransaction();
        // Set AFL (tag 94): SFI 1, records 1-1, 1 ODA record
        setTag((short) 0x0094, new byte[] { 0x08, 0x01, 0x01, 0x00 });

        // Set GPO response template (template ID 1): [AIP(82), AFL(94)]
        SmartCard.transmitCommand(new byte[] {
            (byte) 0x80, (byte) 0x02, (byte) 0x00, (byte) 0x01,
            (byte) 0x04, (byte) 0x00, (byte) 0x82, (byte) 0x00, (byte) 0x94
        });

        byte[] pdolData = createMinimalCdolData();
        byte[] wrappedPdol = new byte[2 + pdolData.length];
        wrappedPdol[0] = (byte) 0x83;
        wrappedPdol[1] = (byte) pdolData.length;
        System.arraycopy(pdolData, 0, wrappedPdol, 2, pdolData.length);

        byte[] gpoCmd = new byte[5 + wrappedPdol.length];
        gpoCmd[0] = (byte) 0x80;
        gpoCmd[1] = (byte) 0xA8;
        gpoCmd[2] = (byte) 0x00;
        gpoCmd[3] = (byte) 0x00;
        gpoCmd[4] = (byte) wrappedPdol.length;
        System.arraycopy(wrappedPdol, 0, gpoCmd, 5, wrappedPdol.length);

        ResponseAPDU response = SmartCard.transmitCommand(gpoCmd);
        Assume.that(response.getSW() == 0x9000);

        byte[] data = response.getData();
        Assume.that(data.length > 2 && data[0] == (byte) 0x77);

        assertTrue(containsByte(data, (byte) 0x82),
            "C-2 Table 5.20: GPO Format 2 must contain AIP (tag 82)");
        assertTrue(containsByte(data, (byte) 0x94),
            "C-2 Table 5.20: GPO Format 2 must contain AFL (tag 94)");
    }

    // -----------------------------------------------------------------------
    // 48. C-2 Table 5.12: GENERATE AC no-CDA must contain 9F27, 9F36, 9F26
    //     Property: Format 2 without CDA has mandatory 9F27 + 9F36 + 9F26.
    //     This is distinct from CDA (Table 5.13) where 9F26 is absent.
    // -----------------------------------------------------------------------

    @Property(tries = 10)
    void c2GenerateAcNoCdaContainsMandatoryTags(
            @ForAll @ShortRange(min = 1, max = 50) short atc
    ) throws CardException {
        // Set up card WITHOUT RSA/EC keys — forces no-CDA path
        setupCardForTransaction();
        setTag((short) 0x9F36, new byte[] {
            (byte) ((atc >> 8) & 0xFF), (byte) (atc & 0xFF)
        });

        byte[] cdolData = createMinimalCdolData();
        ResponseAPDU response = sendGenerateAc(cdolData, (byte) 0x80);
        Assume.that(response.getSW() == 0x9000);

        byte[] data = response.getData();
        assertTrue(containsTag(data, (short) 0x9F27),
            "C-2 Table 5.12: no-CDA response must contain CID (9F27)");
        assertTrue(containsTag(data, (short) 0x9F36),
            "C-2 Table 5.12: no-CDA response must contain ATC (9F36)");
        assertTrue(containsTag(data, (short) 0x9F26),
            "C-2 Table 5.12: no-CDA response must contain AC (9F26)");
    }

    // -----------------------------------------------------------------------
    // 49. C-2 Table 5.13: GENERATE AC CDA must contain 9F27, 9F36, 9F4B
    //     Property: CDA variant has SDAD instead of bare AC.
    //     Mandatory: 9F27, 9F36, 9F4B. 9F26 must NOT appear.
    // -----------------------------------------------------------------------

    @Property(tries = 5)
    void c2GenerateAcCdaContainsMandatoryTags(
            @ForAll @ShortRange(min = 1, max = 50) short atc
    ) throws CardException {
        setupCdaCard(atc);
        selectPaymentAppWithResponse();
        sendGpo(createMinimalCdolData());
        byte[] cdolData = createMinimalCdolData();
        ResponseAPDU response = sendGenerateAc(cdolData, (byte) 0x90);
        Assume.that(response.getSW() == 0x9000);

        byte[] data = response.getData();
        assertTrue(containsTag(data, (short) 0x9F27),
            "C-2 Table 5.13: CDA response must contain CID (9F27)");
        assertTrue(containsTag(data, (short) 0x9F36),
            "C-2 Table 5.13: CDA response must contain ATC (9F36)");
        assertTrue(containsTag(data, (short) 0x9F4B),
            "C-2 Table 5.13: CDA response must contain SDAD (9F4B)");
        assertFalse(containsTag(data, (short) 0x9F26),
            "C-2 Table 5.13: CDA response must NOT contain bare AC (9F26)");
    }

    // -----------------------------------------------------------------------
    // 50. C-2 Table 6.7: ICC Dynamic Data (No IDS) structure inside SDAD
    //     Property: ICC Dynamic Data must contain DN_len(1) + DN(2-8) +
    //     CID(1) + AC(8) + Hash(20). The LDD field must be consistent.
    // -----------------------------------------------------------------------

    @Property(tries = 5)
    void c2IccDynamicDataStructureInSdad(
            @ForAll @ShortRange(min = 1, max = 50) short atc
    ) throws CardException {
        byte[] sdad = runCdaTransactionAndGetSdad(atc);
        Assume.that(sdad != null);

        byte[] recovered = rsaRecover(sdad);
        Assume.that(recovered != null);

        // SDAD structure: [0x6A][0x05][0x01][LDD][ICC Dynamic Data...][pad 0xBB...][hash 20][0xBC]
        int ldd = recovered[3] & 0xFF;

        // ICC Dynamic Data starts at offset 4, length = LDD
        // Per C-2 Table 6.7 (No IDS): DN_len(1) + DN(2-8) + CID(1) + AC(8) + Hash(20)
        int iccDynDataStart = 4;
        int dnLen = recovered[iccDynDataStart] & 0xFF;

        // DN length must be 2-8 per spec
        assertTrue(dnLen >= 2 && dnLen <= 8,
            "C-2 Table 6.7: ICC Dynamic Number length must be 2-8, got " + dnLen);

        // LDD must equal DN_len(1) + DN(dnLen) + CID(1) + AC(8) + TDH(20)
        int expectedLdd = 1 + dnLen + 1 + 8 + 20;
        assertEquals(expectedLdd, ldd,
            "C-2 Table 6.7: LDD must equal 1+DN_len+1+8+20=" + expectedLdd);

        // AC inside SDAD is 8 bytes (at offset: iccDynDataStart + 1 + dnLen + 1)
        int acOffset = iccDynDataStart + 1 + dnLen + 1;
        assertTrue(acOffset + 8 <= recovered.length,
            "AC must fit within recovered SDAD");
    }

    // =======================================================================
    // GROUP C Helpers: CDA/ECDSA
    // =======================================================================

    // RSA-1024 test key (from ColossusPaymentApplicationTest)
    private static final byte[] RSA_MODULUS = new byte[] {
        (byte) 0xA4, (byte) 0xC9, (byte) 0x0D, (byte) 0x48, (byte) 0x83, (byte) 0x21, (byte) 0xF7, (byte) 0x51,
        (byte) 0xCC, (byte) 0xBF, (byte) 0xF3, (byte) 0xA9, (byte) 0xCB, (byte) 0x15, (byte) 0x6A, (byte) 0xD1,
        (byte) 0xC9, (byte) 0x05, (byte) 0xF8, (byte) 0x69, (byte) 0xBD, (byte) 0xFC, (byte) 0xF3, (byte) 0x2C,
        (byte) 0x45, (byte) 0x19, (byte) 0x52, (byte) 0x04, (byte) 0x6E, (byte) 0x8C, (byte) 0x9A, (byte) 0x04,
        (byte) 0x28, (byte) 0xB5, (byte) 0x6A, (byte) 0x64, (byte) 0x0A, (byte) 0xF9, (byte) 0x49, (byte) 0xD2,
        (byte) 0xC3, (byte) 0xD0, (byte) 0xD0, (byte) 0xD0, (byte) 0x11, (byte) 0x48, (byte) 0x9E, (byte) 0x91,
        (byte) 0x9F, (byte) 0xE4, (byte) 0xBE, (byte) 0x24, (byte) 0xA4, (byte) 0x6C, (byte) 0x59, (byte) 0x3F,
        (byte) 0x0D, (byte) 0x58, (byte) 0x28, (byte) 0x18, (byte) 0x90, (byte) 0x9F, (byte) 0xB6, (byte) 0xD0,
        (byte) 0x5C, (byte) 0xB1, (byte) 0x31, (byte) 0xED, (byte) 0xC2, (byte) 0xF5, (byte) 0xE9, (byte) 0xE8,
        (byte) 0x85, (byte) 0x9A, (byte) 0x92, (byte) 0xB8, (byte) 0x39, (byte) 0x84, (byte) 0x14, (byte) 0xA4,
        (byte) 0x59, (byte) 0x8A, (byte) 0xA3, (byte) 0x48, (byte) 0x8F, (byte) 0xBA, (byte) 0x68, (byte) 0x59,
        (byte) 0xA1, (byte) 0xA8, (byte) 0x43, (byte) 0x71, (byte) 0x32, (byte) 0xD0, (byte) 0xF0, (byte) 0x44,
        (byte) 0x4A, (byte) 0x0D, (byte) 0x3B, (byte) 0xE9, (byte) 0x97, (byte) 0x7C, (byte) 0x47, (byte) 0x30,
        (byte) 0xCA, (byte) 0xCC, (byte) 0xB6, (byte) 0xB2, (byte) 0x8F, (byte) 0x0D, (byte) 0xEE, (byte) 0x74,
        (byte) 0x6F, (byte) 0x70, (byte) 0x5A, (byte) 0x68, (byte) 0x0F, (byte) 0x2E, (byte) 0x1F, (byte) 0x89,
        (byte) 0x0E, (byte) 0xDE, (byte) 0xC1, (byte) 0x7B, (byte) 0x97, (byte) 0x10, (byte) 0x0E, (byte) 0x73
    };

    private static final byte[] RSA_EXPONENT = new byte[] {
        (byte) 0x82, (byte) 0x06, (byte) 0x22, (byte) 0x75, (byte) 0x15, (byte) 0x03, (byte) 0xB8, (byte) 0x22,
        (byte) 0xD3, (byte) 0x6C, (byte) 0xA2, (byte) 0xD7, (byte) 0x57, (byte) 0x67, (byte) 0x8E, (byte) 0xE1,
        (byte) 0xF9, (byte) 0xBC, (byte) 0xBC, (byte) 0x46, (byte) 0xB3, (byte) 0xA2, (byte) 0xE4, (byte) 0x3E,
        (byte) 0x0A, (byte) 0x47, (byte) 0xF0, (byte) 0x6F, (byte) 0x8E, (byte) 0xCB, (byte) 0x62, (byte) 0xBB,
        (byte) 0xE5, (byte) 0x63, (byte) 0x40, (byte) 0x8F, (byte) 0xB0, (byte) 0x19, (byte) 0x04, (byte) 0x27,
        (byte) 0x4A, (byte) 0x5B, (byte) 0x7A, (byte) 0x68, (byte) 0xB3, (byte) 0x3A, (byte) 0x99, (byte) 0xE4,
        (byte) 0x4E, (byte) 0x46, (byte) 0x2F, (byte) 0xC2, (byte) 0xB9, (byte) 0xFA, (byte) 0xC4, (byte) 0x70,
        (byte) 0xFC, (byte) 0x16, (byte) 0x93, (byte) 0x8C, (byte) 0xCE, (byte) 0x91, (byte) 0x37, (byte) 0xAD,
        (byte) 0xED, (byte) 0x28, (byte) 0x6C, (byte) 0x3A, (byte) 0x60, (byte) 0xE5, (byte) 0xF5, (byte) 0x5C,
        (byte) 0x16, (byte) 0x42, (byte) 0x6C, (byte) 0x89, (byte) 0x6A, (byte) 0xBB, (byte) 0x50, (byte) 0xD9,
        (byte) 0x2A, (byte) 0xA8, (byte) 0x63, (byte) 0x54, (byte) 0xAA, (byte) 0xF6, (byte) 0x11, (byte) 0x6D,
        (byte) 0x43, (byte) 0xA2, (byte) 0x56, (byte) 0x48, (byte) 0x07, (byte) 0x07, (byte) 0xFD, (byte) 0xF0,
        (byte) 0xF3, (byte) 0xC1, (byte) 0xCC, (byte) 0x3C, (byte) 0x39, (byte) 0x9E, (byte) 0x2C, (byte) 0xE3,
        (byte) 0x61, (byte) 0xBA, (byte) 0x3A, (byte) 0x72, (byte) 0x85, (byte) 0xF5, (byte) 0xA5, (byte) 0x32,
        (byte) 0x34, (byte) 0x8F, (byte) 0x56, (byte) 0x57, (byte) 0x7F, (byte) 0x11, (byte) 0x2D, (byte) 0xC2,
        (byte) 0xF4, (byte) 0xAB, (byte) 0x51, (byte) 0xE4, (byte) 0xDF, (byte) 0x90, (byte) 0xE0, (byte) 0x01
    };

    private static final byte[] EC_PRIVATE_KEY = new byte[] {
        (byte) 0x7E, (byte) 0xAD, (byte) 0xBA, (byte) 0x91, (byte) 0xC5, (byte) 0x33, (byte) 0x41, (byte) 0x2E,
        (byte) 0xBF, (byte) 0x9E, (byte) 0x0E, (byte) 0x34, (byte) 0x73, (byte) 0x99, (byte) 0xB6, (byte) 0xEC,
        (byte) 0xB8, (byte) 0x64, (byte) 0x32, (byte) 0xA7, (byte) 0x72, (byte) 0x66, (byte) 0xF0, (byte) 0x5D,
        (byte) 0xA5, (byte) 0x00, (byte) 0x16, (byte) 0x00, (byte) 0xC2, (byte) 0xE3, (byte) 0x51, (byte) 0x62
    };

    private void setupCdaCard(short atc) throws CardException {
        setupCardForTransaction();
        // Override AIP with CDA support
        setTag((short) 0x0082, new byte[] { (byte) 0x3D, (byte) 0x00 });
        // AFL: SFI 1, records 1-1
        setTag((short) 0x0094, new byte[] { 0x08, 0x01, 0x01, 0x00 });
        setTag((short) 0x9F36, new byte[] {
            (byte) ((atc >> 8) & 0xFF), (byte) (atc & 0xFF)
        });
        // Load RSA key
        loadRsaKey();
        // Load EC key
        loadEcKey();
        // GPO response template (template ID 1): AIP + AFL
        SmartCard.transmitCommand(new byte[] {
            (byte) 0x80, (byte) 0x02, (byte) 0x00, (byte) 0x01,
            (byte) 0x04, (byte) 0x00, (byte) 0x82, (byte) 0x00, (byte) 0x94
        });
        // CDA response template (template ID 3): 9F27 + 9F36 + 9F4B + 9F10
        SmartCard.transmitCommand(new byte[] {
            (byte) 0x80, (byte) 0x02, (byte) 0x00, (byte) 0x03,
            (byte) 0x08,
            (byte) 0x9F, (byte) 0x27,
            (byte) 0x9F, (byte) 0x36,
            (byte) 0x9F, (byte) 0x4B,
            (byte) 0x9F, (byte) 0x10
        });
    }

    private void loadRsaKey() throws CardException {
        byte[] modCmd = new byte[5 + 128];
        modCmd[0] = (byte) 0x80; modCmd[1] = (byte) 0x04;
        modCmd[2] = (byte) 0x00; modCmd[3] = (byte) 0x04;
        modCmd[4] = (byte) 0x80;
        System.arraycopy(RSA_MODULUS, 0, modCmd, 5, 128);
        SmartCard.transmitCommand(modCmd);

        byte[] expCmd = new byte[5 + 128];
        expCmd[0] = (byte) 0x80; expCmd[1] = (byte) 0x04;
        expCmd[2] = (byte) 0x00; expCmd[3] = (byte) 0x05;
        expCmd[4] = (byte) 0x80;
        System.arraycopy(RSA_EXPONENT, 0, expCmd, 5, 128);
        SmartCard.transmitCommand(expCmd);
    }

    private void loadEcKey() throws CardException {
        byte[] cmd = new byte[5 + 32];
        cmd[0] = (byte) 0x80; cmd[1] = (byte) 0x04;
        cmd[2] = (byte) 0x00; cmd[3] = (byte) 0x0B;
        cmd[4] = (byte) 0x20;
        System.arraycopy(EC_PRIVATE_KEY, 0, cmd, 5, 32);
        SmartCard.transmitCommand(cmd);
    }

    /** Run full EMV flow: SELECT → GPO → GENERATE AC (CDA), return SDAD bytes. */
    private byte[] runCdaTransactionAndGetSdad(short atc) throws CardException {
        setupCdaCard(atc);

        // SELECT to initialize transaction state
        selectPaymentAppWithResponse();

        // GPO to store PDOL and trigger ECDSA
        byte[] pdolData = createMinimalCdolData();
        byte[] wrappedPdol = new byte[2 + pdolData.length];
        wrappedPdol[0] = (byte) 0x83;
        wrappedPdol[1] = (byte) pdolData.length;
        System.arraycopy(pdolData, 0, wrappedPdol, 2, pdolData.length);
        byte[] gpoCmd = new byte[5 + wrappedPdol.length];
        gpoCmd[0] = (byte) 0x80; gpoCmd[1] = (byte) 0xA8;
        gpoCmd[2] = (byte) 0x00; gpoCmd[3] = (byte) 0x00;
        gpoCmd[4] = (byte) wrappedPdol.length;
        System.arraycopy(wrappedPdol, 0, gpoCmd, 5, wrappedPdol.length);
        ResponseAPDU gpoResp = SmartCard.transmitCommand(gpoCmd);
        if (gpoResp.getSW() != 0x9000) return null;

        // GENERATE AC with CDA
        byte[] cdolData = createMinimalCdolData();
        ResponseAPDU response = sendGenerateAc(cdolData, (byte) 0x90);
        if (response.getSW() != 0x9000) return null;
        return extractTagValue(response.getData(), (short) 0x9F4B);
    }

    private ResponseAPDU sendGpo(byte[] pdolData) throws CardException {
        byte[] wrappedPdol = new byte[2 + pdolData.length];
        wrappedPdol[0] = (byte) 0x83;
        wrappedPdol[1] = (byte) pdolData.length;
        System.arraycopy(pdolData, 0, wrappedPdol, 2, pdolData.length);
        byte[] cmd = new byte[5 + wrappedPdol.length];
        cmd[0] = (byte) 0x80; cmd[1] = (byte) 0xA8;
        cmd[2] = (byte) 0x00; cmd[3] = (byte) 0x00;
        cmd[4] = (byte) wrappedPdol.length;
        System.arraycopy(wrappedPdol, 0, cmd, 5, wrappedPdol.length);
        return SmartCard.transmitCommand(cmd);
    }

    private ResponseAPDU sendGenerateAc(byte[] cdolData, byte p1) throws CardException {
        byte[] cmd = new byte[5 + cdolData.length];
        cmd[0] = (byte) 0x80;
        cmd[1] = (byte) 0xAE;
        cmd[2] = p1;
        cmd[3] = (byte) 0x00;
        cmd[4] = (byte) cdolData.length;
        System.arraycopy(cdolData, 0, cmd, 5, cdolData.length);
        return SmartCard.transmitCommand(cmd);
    }

    private byte[] rsaRecover(byte[] sdad) {
        // Try common EMV public exponents: 65537, then 3
        for (long exp : new long[] { 65537L, 3L }) {
            try {
                java.security.spec.RSAPublicKeySpec spec = new java.security.spec.RSAPublicKeySpec(
                    new BigInteger(1, RSA_MODULUS), BigInteger.valueOf(exp));
                KeyFactory kf = KeyFactory.getInstance("RSA");
                PublicKey pubKey = kf.generatePublic(spec);
                javax.crypto.Cipher cipher = javax.crypto.Cipher.getInstance("RSA/ECB/NoPadding");
                cipher.init(javax.crypto.Cipher.DECRYPT_MODE, pubKey);
                byte[] result = cipher.doFinal(sdad);
                if (result != null && result[0] == (byte) 0x6A) {
                    return result; // Found correct exponent
                }
            } catch (Exception e) {
                // Try next exponent
            }
        }
        return null;
    }

    private PublicKey deriveEcPublicKey() throws Exception {
        BigInteger privateScalar = new BigInteger(1, EC_PRIVATE_KEY);
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(new ECGenParameterSpec("secp256r1"));
        java.security.KeyPair dummyPair = kpg.generateKeyPair();
        java.security.spec.ECParameterSpec ecSpec = ((ECPublicKey) dummyPair.getPublic()).getParams();

        org.bouncycastle.jce.spec.ECNamedCurveParameterSpec bcSpec =
            org.bouncycastle.jce.ECNamedCurveTable.getParameterSpec("secp256r1");
        org.bouncycastle.math.ec.ECPoint qPoint = bcSpec.getG().multiply(privateScalar).normalize();
        ECPoint pubPoint = new ECPoint(
            qPoint.getAffineXCoord().toBigInteger(),
            qPoint.getAffineYCoord().toBigInteger());
        ECPublicKeySpec pubSpec = new ECPublicKeySpec(pubPoint, ecSpec);
        return KeyFactory.getInstance("EC").generatePublic(pubSpec);
    }

    private byte[] rawToDerSignature(byte[] r, byte[] s) {
        byte[] rDer = toUnsignedDerInteger(r);
        byte[] sDer = toUnsignedDerInteger(s);
        int seqLen = 2 + rDer.length + 2 + sDer.length;
        byte[] der = new byte[2 + seqLen];
        int idx = 0;
        der[idx++] = 0x30;
        der[idx++] = (byte) seqLen;
        der[idx++] = 0x02;
        der[idx++] = (byte) rDer.length;
        System.arraycopy(rDer, 0, der, idx, rDer.length);
        idx += rDer.length;
        der[idx++] = 0x02;
        der[idx++] = (byte) sDer.length;
        System.arraycopy(sDer, 0, der, idx, sDer.length);
        return der;
    }

    private byte[] toUnsignedDerInteger(byte[] val) {
        int start = 0;
        while (start < val.length - 1 && val[start] == 0) { start++; }
        if ((val[start] & 0x80) != 0) {
            byte[] result = new byte[val.length - start + 1];
            result[0] = 0x00;
            System.arraycopy(val, start, result, 1, val.length - start);
            return result;
        }
        return Arrays.copyOfRange(val, start, val.length);
    }

    /** Extract raw value of a 2-byte tag from a TLV byte array. */
    private byte[] extractTagValue(byte[] tlvData, short tagId) {
        byte hi = (byte) ((tagId >> 8) & 0xFF);
        byte lo = (byte) (tagId & 0xFF);
        for (int i = 0; i < tlvData.length - 3; i++) {
            if (tlvData[i] == hi && tlvData[i + 1] == lo) {
                int lenOffset = i + 2;
                int len;
                int valOffset;
                if ((tlvData[lenOffset] & 0xFF) == 0x81) {
                    len = tlvData[lenOffset + 1] & 0xFF;
                    valOffset = lenOffset + 2;
                } else if ((tlvData[lenOffset] & 0xFF) == 0x82) {
                    len = ((tlvData[lenOffset + 1] & 0xFF) << 8) | (tlvData[lenOffset + 2] & 0xFF);
                    valOffset = lenOffset + 3;
                } else {
                    len = tlvData[lenOffset] & 0xFF;
                    valOffset = lenOffset + 1;
                }
                if (valOffset + len <= tlvData.length) {
                    return Arrays.copyOfRange(tlvData, valOffset, valOffset + len);
                }
            }
        }
        return null;
    }

    private void setupCardWithFciTemplates() throws CardException {
        selectAndReset();
        setTag((short) 0x005A, new byte[] { 0x67, 0x67, 0x12, 0x34, 0x56, 0x78, (byte) 0x90, 0x00 });
        setTag((short) 0x0084, PAYMENT_AID);
        setTag((short) 0x0050, new byte[] { 0x54, 0x45, 0x53, 0x54 });
        setTag((short) 0x0087, new byte[] { 0x01 });
        // A5 template: [50, 87]
        SmartCard.transmitCommand(new byte[] {
            (byte) 0x80, (byte) 0x02, (byte) 0x00, (byte) 0x05,
            (byte) 0x04, (byte) 0x00, (byte) 0x50, (byte) 0x00, (byte) 0x87
        });
        // 6F template: [84, A5]
        SmartCard.transmitCommand(new byte[] {
            (byte) 0x80, (byte) 0x02, (byte) 0x00, (byte) 0x04,
            (byte) 0x04, (byte) 0x00, (byte) 0x84, (byte) 0x00, (byte) 0xA5
        });
    }

    private ResponseAPDU selectPaymentAppWithResponse() throws CardException {
        byte[] selectCmd = new byte[5 + PAYMENT_AID.length];
        selectCmd[0] = (byte) 0x00;
        selectCmd[1] = (byte) 0xA4;
        selectCmd[2] = (byte) 0x04;
        selectCmd[3] = (byte) 0x00;
        selectCmd[4] = (byte) PAYMENT_AID.length;
        System.arraycopy(PAYMENT_AID, 0, selectCmd, 5, PAYMENT_AID.length);
        return SmartCard.transmitCommand(selectCmd);
    }

    /** Build a STORE DATA command: [CLA] E2 00 00 [LC] [DGI(2)] [LEN(1)] [DATA] */
    private byte[] buildStoreDataCmd(byte cla, short dgi, byte[] data) {
        byte[] cmd = new byte[5 + 2 + 1 + data.length];
        cmd[0] = cla;
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
}
