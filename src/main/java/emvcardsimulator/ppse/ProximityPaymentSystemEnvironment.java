package emvcardsimulator.ppse;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;

import emvcardsimulator.BuildConfig;

/**
 * PPSE (Proximity Payment System Environment) for contactless EMV.
 * Responds to SELECT 2PAY.SYS.DDF01 and returns directory entries.
 *
 * <p>F-60 / CPS v2.0 §4.3.4: PPSE enforces the same personalization lifecycle
 * semantics as PSE and PaymentApplication (PERSO_PENDING → PERSO_DONE on last
 * STORE DATA with P1 bit 8). Post-commit writes return 6985. Supplements the
 * GP ISD secure-channel layer so that a card with compromised or default ISD
 * keys still can't have its directory entry rewritten to repoint at a
 * malicious AID once personalization is finalized.
 *
 * <p>Lifecycle state is inlined (not imported from emvcardsimulator.AppletLifecycle)
 * because PPSE lives in its own CAP package (emvcardsimulator.ppse) and the JC
 * converter would otherwise need a cross-package link to the
 * emvcardsimulator.exp export file. The state machine here is byte-identical
 * to AppletLifecycle: one persistent byte, PERSO_PENDING at install,
 * transitions once to PERSO_DONE on commit.
 */
public class ProximityPaymentSystemEnvironment extends Applet {

    // Inlined lifecycle state values (match emvcardsimulator.AppletLifecycle)
    private static final byte PERSO_PENDING = (byte) 0x01;
    private static final byte PERSO_DONE    = (byte) 0x07;
    private static final short SW_PERSO_DONE = (short) 0x6985;  // CPS §4.3.5.4

    // FCI response data storage
    private byte[] fciData;
    private short fciLength;

    // Directory entry storage
    private byte[] directoryEntry;
    private short directoryEntryLength;

    // Temp buffer
    private byte[] tmpBuffer;

    // Personalization lifecycle: single persistent byte, PERSO_PENDING after
    // install, PERSO_DONE after the last STORE DATA (P1 bit 8 = 1).
    private byte[] lifecycleState;


    public static void install(byte[] buffer, short offset, byte length) {
        (new ProximityPaymentSystemEnvironment()).register();
    }

    protected ProximityPaymentSystemEnvironment() {
        tmpBuffer = JCSystem.makeTransientByteArray((short) 256, JCSystem.CLEAR_ON_DESELECT);
        fciData = new byte[128];
        fciLength = 0;
        directoryEntry = new byte[64];
        directoryEntryLength = 0;
        lifecycleState = new byte[] { PERSO_PENDING };
    }

    /** Throws 6985 if personalization has already committed (CPS §4.3.5.4). */
    private void requirePersoPending() {
        if (lifecycleState[0] != PERSO_PENDING) {
            ISOException.throwIt(SW_PERSO_DONE);
        }
    }

    /** Atomically commit lifecycle to PERSO_DONE. */
    private void commitPersonalization() {
        JCSystem.beginTransaction();
        lifecycleState[0] = PERSO_DONE;
        JCSystem.commitTransaction();
    }

    /** Reset to PERSO_PENDING for dev/test via factory reset. */
    private void resetLifecycleForTesting() {
        JCSystem.beginTransaction();
        lifecycleState[0] = PERSO_PENDING;
        JCSystem.commitTransaction();
    }

    public void process(APDU apdu) {
        byte[] buf = apdu.getBuffer();

        if (selectingApplet()) {
            processSelect(apdu, buf);
            return;
        }

        byte ins = buf[ISO7816.OFFSET_INS];

        // Receive data for commands that have it
        if (ins == (byte)0x01 || ins == (byte)0x02 || ins == (byte)0xE2) {
            apdu.setIncomingAndReceive();
        }

        // STORE DATA (INS E2) — accept CLA 00, 80, or 84 per CPS v2.0
        if (buf[ISO7816.OFFSET_INS] == (byte) 0xE2) {
            processStoreDataPpse(apdu, buf);
            return;
        }

        short cmd = Util.getShort(buf, ISO7816.OFFSET_CLA);

        // Dev-only admin/personalization commands
        if (!BuildConfig.PRODUCTION) {
            switch (cmd) {
                case (short) 0x8001:  // SET_TAG - store directory entry
                    processSetDirectoryEntry(apdu, buf);
                    return;
                case (short) 0x8002:  // SET_FCI - store complete FCI
                    processSetFci(apdu, buf);
                    return;
                case (short) 0x8005:  // FACTORY_RESET
                    fciLength = 0;
                    directoryEntryLength = 0;
                    resetLifecycleForTesting();   // F-60: return to PERSO_PENDING
                    ISOException.throwIt(ISO7816.SW_NO_ERROR);
                    return;
                default:
                    break;
            }
        }

        ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
    }

    private void processSelect(APDU apdu, byte[] buf) {
        if (fciLength > 0) {
            // Return stored FCI
            Util.arrayCopy(fciData, (short) 0, buf, (short) 0, fciLength);
            apdu.setOutgoingAndSend((short) 0, fciLength);
        } else if (directoryEntryLength > 0) {
            // Build FCI from directory entry
            // 6F { 84 (AID), A5 { BF0C { 61 (directory entry) } } }
            short offset = 0;

            // PPSE AID: 2PAY.SYS.DDF01
            byte[] ppseAid = {
                (byte)0x32, (byte)0x50, (byte)0x41, (byte)0x59, (byte)0x2E,
                (byte)0x53, (byte)0x59, (byte)0x53, (byte)0x2E,
                (byte)0x44, (byte)0x44, (byte)0x46, (byte)0x30, (byte)0x31
            };

            // Build from inside out
            // 61 <len> <directory entry content>
            short dir61Len = directoryEntryLength;

            // BF0C <len> 61 <len> <content>
            short bf0cContentLen = (short)(2 + dir61Len);

            // A5 <len> BF0C ...
            // BF0C is 2-byte tag + 1-byte length + content = 3 + bf0cContentLen
            short a5ContentLen = (short)(3 + bf0cContentLen);
            if (bf0cContentLen > 127) a5ContentLen++;

            // 84 <len> <AID>
            short tag84Len = (short)(2 + ppseAid.length);

            // 6F <len> 84... A5...
            short fci6fContentLen = (short)(tag84Len + 2 + a5ContentLen);
            if (a5ContentLen > 127) fci6fContentLen++;

            // Build response
            tmpBuffer[offset++] = (byte) 0x6F;
            if (fci6fContentLen > 127) {
                tmpBuffer[offset++] = (byte) 0x81;
            }
            tmpBuffer[offset++] = (byte) fci6fContentLen;

            // 84 (DF Name)
            tmpBuffer[offset++] = (byte) 0x84;
            tmpBuffer[offset++] = (byte) ppseAid.length;
            Util.arrayCopy(ppseAid, (short) 0, tmpBuffer, offset, (short) ppseAid.length);
            offset += ppseAid.length;

            // A5 (FCI Proprietary)
            tmpBuffer[offset++] = (byte) 0xA5;
            if (a5ContentLen > 127) {
                tmpBuffer[offset++] = (byte) 0x81;
            }
            tmpBuffer[offset++] = (byte) a5ContentLen;

            // BF0C (FCI Issuer Discretionary Data)
            tmpBuffer[offset++] = (byte) 0xBF;
            tmpBuffer[offset++] = (byte) 0x0C;
            if (bf0cContentLen > 127) {
                tmpBuffer[offset++] = (byte) 0x81;
            }
            tmpBuffer[offset++] = (byte) bf0cContentLen;

            // 61 (Directory Entry)
            tmpBuffer[offset++] = (byte) 0x61;
            tmpBuffer[offset++] = (byte) directoryEntryLength;
            Util.arrayCopy(directoryEntry, (short) 0, tmpBuffer, offset, directoryEntryLength);
            offset += directoryEntryLength;

            Util.arrayCopy(tmpBuffer, (short) 0, buf, (short) 0, offset);
            apdu.setOutgoingAndSend((short) 0, offset);
        } else {
            // No data configured — return 9000 so STORE DATA can be sent for personalization
            ISOException.throwIt(ISO7816.SW_NO_ERROR);
        }
    }

    /**
     * Store directory entry content (inner content of tag 61).
     * Command: 80 01 00 61 LC <4F AID, 50 label, 87 priority>
     */
    private void processSetDirectoryEntry(APDU apdu, byte[] buf) {
        requirePersoPending();   // F-60: reject post-commit writes (6985)

        short p1p2 = Util.getShort(buf, ISO7816.OFFSET_P1);
        if (p1p2 != (short) 0x0061) {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }

        short len = (short) (buf[ISO7816.OFFSET_LC] & 0xFF);
        if (len > 64) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        Util.arrayCopy(buf, ISO7816.OFFSET_CDATA, directoryEntry, (short) 0, len);
        directoryEntryLength = len;

        ISOException.throwIt(ISO7816.SW_NO_ERROR);
    }

    /**
     * Store complete FCI response.
     * Command: 80 02 00 00 LC <6F ...>
     */
    private void processSetFci(APDU apdu, byte[] buf) {
        requirePersoPending();   // F-60: reject post-commit writes (6985)

        short len = (short) (buf[ISO7816.OFFSET_LC] & 0xFF);
        if (len > 128) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        Util.arrayCopy(buf, ISO7816.OFFSET_CDATA, fciData, (short) 0, len);
        fciLength = len;

        ISOException.throwIt(ISO7816.SW_NO_ERROR);
    }

    /**
     * Process GP STORE DATA (INS 0xE2) for PPSE personalization.
     * DGI D001 = directory entry, DGI D002 = complete FCI.
     * F-60: lifecycle-gated — after the last STORE DATA (P1 bit 8 = 1, CPS
     * §4.3.4 Table 4-9) the applet transitions to PERSO_DONE and subsequent
     * STORE DATAs return 6985 per CPS §4.3.5.4.
     */
    private void processStoreDataPpse(APDU apdu, byte[] buf) {
        requirePersoPending();
        boolean isLast = (buf[ISO7816.OFFSET_P1] & 0x80) != 0;

        short dataOffset = ISO7816.OFFSET_CDATA;
        short dataLen = (short) (buf[ISO7816.OFFSET_LC] & 0x00FF);

        if (dataLen < 3) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        // Parse DGI (2 bytes)
        short dgi = Util.getShort(buf, dataOffset);
        short dgiDataOffset = (short) (dataOffset + 2);

        // Parse length (1 byte)
        short dgiDataLen = (short) (buf[dgiDataOffset] & 0x00FF);
        dgiDataOffset = (short) (dgiDataOffset + 1);

        switch (dgi) {
            case (short) 0xD001:  // Directory entry
                if (dgiDataLen > 64) {
                    ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
                }
                Util.arrayCopy(buf, dgiDataOffset, directoryEntry, (short) 0, dgiDataLen);
                directoryEntryLength = dgiDataLen;
                break;
            case (short) 0xD002:  // Complete FCI
                if (dgiDataLen > 128) {
                    ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
                }
                Util.arrayCopy(buf, dgiDataOffset, fciData, (short) 0, dgiDataLen);
                fciLength = dgiDataLen;
                break;
            case (short) 0x7FFF:  // CPS §4.3.5.2 integrity MAC placeholder — accept as no-op
                break;
            default:
                ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }

        if (isLast) {
            commitPersonalization();
        }

        ISOException.throwIt(ISO7816.SW_NO_ERROR);
    }
}
