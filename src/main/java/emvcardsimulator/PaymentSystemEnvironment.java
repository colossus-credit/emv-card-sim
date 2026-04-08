package emvcardsimulator;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.Util;

public class PaymentSystemEnvironment extends EmvApplet {

    private static final byte[] SELECT_RESPONSE = {
        (byte) 0x6F, (byte) 0x2C, (byte) 0x84, (byte) 0x0E, (byte) 0x31, (byte) 0x50, (byte) 0x41, (byte) 0x59, (byte) 0x2E, (byte) 0x53, (byte) 0x59, (byte) 0x53, (byte) 0x2E, (byte) 0x44, (byte) 0x44, (byte) 0x46, (byte) 0x30, (byte) 0x31, (byte) 0xA5, (byte) 0x1A, (byte) 0x88, (byte) 0x01, (byte) 0x01,  (byte) 0x5F, (byte) 0x2D, (byte) 0x02, (byte) 0x65, (byte) 0x6E,  (byte) 0x9F, (byte) 0x11, (byte) 0x01, (byte) 0x01,  (byte) 0xBF, (byte) 0x0C, (byte) 0x0B,  (byte) 0xDF, (byte) 0x02, (byte) 0x02, (byte) 0x02, (byte) 0x46,  (byte) 0xDF, (byte) 0x47, (byte) 0x03, (byte) 0x80, (byte) 0x01, (byte) 0x01
    };
    private static final byte[] READ_RECORDS_1 = {
        (byte) 0x70, (byte) 0x30, (byte) 0x61, (byte) 0x2E,  (byte) 0x4F, (byte) 0x07, (byte) 0xAF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,  (byte) 0xFF, (byte) 0x12, (byte) 0x34, (byte) 0x50, (byte) 0x0D, (byte) 0x56, (byte) 0x45, (byte) 0x53, (byte) 0x41, (byte) 0x20, (byte) 0x45, (byte) 0x4C, (byte) 0x45, (byte) 0x43, (byte) 0x54, (byte) 0x52,  (byte) 0x4F, (byte) 0x4E,  (byte) 0x9F, (byte) 0x12, (byte) 0x10, (byte) 0x56, (byte) 0x45, (byte) 0x53, (byte) 0x41, (byte) 0x20, (byte) 0x20, (byte) 0x20, (byte) 0x20, (byte) 0x20, (byte) 0x20, (byte) 0x20, (byte) 0x20, (byte) 0x20, (byte) 0x20, (byte) 0x20, (byte) 0x20, (byte) 0x87, (byte) 0x01, (byte) 0x01
    };

    public static void install(byte[] buffer, short offset, byte length) {
        (new PaymentSystemEnvironment()).register();
    }

    private void processSetSettings(APDU apdu, byte[] buf) {
        short settingsId = Util.getShort(buf, ISO7816.OFFSET_P1);

        // Use APDU methods for correct offset and length
        short dataOffset = apdu.getOffsetCdata();
        short dataLength = apdu.getIncomingLength();
        // Fallback for platforms where getIncomingLength returns 0
        if (dataLength == 0) {
            dataLength = (short) (buf[ISO7816.OFFSET_LC] & 0x00FF);
            dataOffset = ISO7816.OFFSET_CDATA;
        }

        switch (settingsId) {
            // FALLBACK READ RECORD
            case 0x0006:
                defaultReadRecord = null;
                defaultReadRecord = new byte[dataLength];
                Util.arrayCopy(buf, dataOffset, defaultReadRecord, (short) 0, dataLength);
                break;
            default:
                ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }

        ISOException.throwIt(ISO7816.SW_NO_ERROR);
    }

    public PaymentSystemEnvironment() {
        super();
    }

    private void processSelect(APDU apdu, byte[] buf) {
        // Clear old logs at start of new transaction (rolling logs)
        ApduLog.clear();
        
        // Check if AID (tag 84) exists in the ICC
        if (EmvTag.findTag((short) 0x84) != null) {
            if (tagBf0cFci != null) {
                short length = tagBf0cFci.expandTlvToArray(tmpBuffer, (short) 0);
                EmvTag.setTag((short) 0xBF0C, tmpBuffer, (short) 0, (byte) length);
            }

            if (tagA5Fci != null) {
                short length = tagA5Fci.expandTlvToArray(tmpBuffer, (short) 0);
                EmvTag.setTag((short) 0xA5, tmpBuffer, (short) 0, (byte) length);
            }

            if (tag6fFci != null) {
                short length = tag6fFci.expandTlvToArray(tmpBuffer, (short) 0);
                EmvTag.setTag((short) 0x6F, tmpBuffer, (short) 0, (byte) length);
                sendResponse(apdu, buf, (short) 0x6F);
            } else {
                EmvApplet.logAndThrow(ISO7816.SW_APPLET_SELECT_FAILED);
            }

        } else {
            // NO PAN, we're probably in the setup phase
            EmvApplet.logAndThrow(ISO7816.SW_NO_ERROR);
        }
    }

    protected void processReadRecord(APDU apdu, byte[] buf) {
        short p1p2 = Util.getShort(buf, ISO7816.OFFSET_P1);
        byte p1 = buf[ISO7816.OFFSET_P1];  // Record number
        byte p2 = buf[ISO7816.OFFSET_P2];  // SFI encoding

        // Check if this is SFI=1 with proper encoding: (P2 & 0x07) == 0x04
        // SFI = (P2 & 0xF8) >> 3
        byte sfi = (byte) ((p2 & 0xF8) >> 3);
        boolean isSfi1Properly = (sfi == (byte) 1) && ((p2 & 0x07) == 0x04);

        // PSE SFI=1 special handling: record 2 returns empty 70 00
        if (isSfi1Properly && p1 == (byte) 2) {
            // Return empty record template: 70 00
            tmpBuffer[0] = (byte) 0x70;
            tmpBuffer[1] = (byte) 0x00;
            apdu.setOutgoing();
            apdu.setOutgoingLength((short) 2);
            apdu.sendBytesLong(tmpBuffer, (short) 0, (short) 2);
            return;
        }

        // Record data stored as EmvTag entry keyed by P1P2
        EmvTag recordTag = EmvTag.findTag(p1p2);
        if (recordTag == null) {
            EmvApplet.logAndThrow(ISO7816.SW_RECORD_NOT_FOUND);
        }

        // Copy raw record data and wrap in tag 70
        short recordLen = recordTag.copyDataToArray(tmpBuffer, (short) 0);
        EmvTag.setTag((short) 0x0070, tmpBuffer, (short) 0, recordLen);
        sendResponse(apdu, buf, (short) 0x0070);
    }

    /**
     * Process PSE application selection and read records.
     */
    public void process(APDU apdu) {
        byte[] buf = apdu.getBuffer();

        // Determine if this command has incoming data
        byte ins = buf[ISO7816.OFFSET_INS];
        boolean hasCommandData;
        switch (ins) {
            case (byte)0xA4:  // SELECT
            case (byte)0x01:  // SET_EMV_TAG
            case (byte)0x02:  // SET_TAG_TEMPLATE
            case (byte)0x03:  // SET_READ_RECORD_TEMPLATE
            case (byte)0x04:  // SET_SETTINGS
            case (byte)0x06:  // SET_EMV_TAG_FUZZ
            case (byte)0xE2:  // STORE DATA (GP personalization)
                hasCommandData = true;
                break;
            default:
                hasCommandData = false;
                break;
        }

        if (hasCommandData) {
            // Receive incoming data
            short bytesReceived = apdu.setIncomingAndReceive();
            short actualLc = apdu.getIncomingLength();

            // For large data, receive remaining bytes
            while (bytesReceived < actualLc) {
                short more = apdu.receiveBytes((short)(apdu.getOffsetCdata() + bytesReceived));
                if (more <= 0) break;
                bytesReceived += more;
            }
        }

        // Log the APDU
        short logLen = hasCommandData ? (short)(5 + apdu.getIncomingLength()) : (short)5;
        if (logLen > 255) logLen = 255;
        ApduLog.addLogEntry(buf, (short) 0, (byte) logLen);

        // STORE DATA (INS E2) — accept CLA 00, 80, or 84 per CPS v2.0
        if (buf[ISO7816.OFFSET_INS] == (byte) 0xE2) {
            processStoreData(apdu, buf);
            return;
        }

        short cmd = Util.getShort(buf, ISO7816.OFFSET_CLA);

        switch (cmd) {
            case CMD_SELECT:
                processSelect(apdu, buf);
                return;
            default:
                break;
        }

        // Dev-only admin/personalization commands
        if (!BuildConfig.PRODUCTION) {
            switch (cmd) {
                case CMD_SET_SETTINGS:
                    processSetSettings(apdu, buf);
                    return;
                case CMD_SET_EMV_TAG:
                    processSetEmvTag(apdu, buf);
                    return;
                case CMD_SET_EMV_TAG_FUZZ:
                    processSetEmvTagFuzz(apdu, buf);
                    return;
                case CMD_SET_TAG_TEMPLATE:
                    processSetTagTemplate(apdu, buf);
                    return;
                case CMD_SET_READ_RECORD_TEMPLATE:
                    processSetReadRecordTemplate(apdu, buf);
                    return;
                case CMD_FACTORY_RESET:
                    factoryReset(apdu, buf);
                    return;
                case CMD_FUZZ_RESET:
                    fuzzReset(apdu, buf);
                    return;
                case CMD_LOG_CONSUME:
                    consumeLogs(apdu, buf);
                    return;
                default:
                    break;
            }
        }

        if (selectingApplet()) {
            return;
        }

        // EMV runtime commands — always available
        switch (cmd) {
            case CMD_READ_RECORD:
                processReadRecord(apdu, buf);
                break;
            default:
                EmvApplet.logAndThrow(ISO7816.SW_INS_NOT_SUPPORTED);
        }
    }
}
