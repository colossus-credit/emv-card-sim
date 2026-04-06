package emvcardsimulator;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacardx.apdu.ExtendedLength;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.KeyBuilder;
import javacard.security.MessageDigest;
import javacard.security.RSAPrivateKey;
import javacard.security.RSAPublicKey;
import javacard.security.RandomData;
import javacardx.crypto.Cipher;

public abstract class EmvApplet extends Applet implements ExtendedLength {
    /*// for dev "debugging"
    static void printAsHex(String type, byte[] buf) {
        printAsHex(type, buf, 0, buf.length);
    }

    static void printAsHex(String type, byte[] buf, int offset, int length) {
        System.out.println(String.format("%s [%02X] %s", type, length, toHexString(buf, offset, length)));
    }

    static String toHexString(byte[] buf, int offset, int length) {
        String result = "[";
        for (int i = offset; i < offset + length - 1; i++) {
            result += String.format("%02X, ", buf[i]);
        }
        result += String.format("%02X]", buf[offset + length - 1]);

        return result;
    }

    static void printEmvTags() {
        for (EmvTag iter = EmvTag.getHead(); iter != null; iter = iter.getNext()) {
            printAsHex(toHexString(iter.getTag(), 0, 2), iter.getData(), 0, (iter.getLength() & 0x00FF));
        }
    }
    */

    protected static final short CMD_SET_SETTINGS              = (short) 0x8004;
    protected static final short CMD_SET_EMV_TAG               = (short) 0x8001;
    protected static final short CMD_SET_EMV_TAG_FUZZ          = (short) 0x8011;
    protected static final short CMD_SET_TAG_TEMPLATE          = (short) 0x8002;
    protected static final short CMD_SET_READ_RECORD_TEMPLATE  = (short) 0x8003;
    protected static final short CMD_FACTORY_RESET             = (short) 0x8005;
    protected static final short CMD_LOG_CONSUME               = (short) 0x8006;
    protected static final short CMD_FUZZ_RESET                = (short) 0x8007;
    protected static final short CMD_LIST_TAGS                 = (short) 0x8008;
    protected static final short CMD_SET_EMV_TAG_CHUNKED       = (short) 0x8009;
    protected static final short CMD_SET_SETTINGS_CHUNKED      = (short) 0x800A;
    protected static final short CMD_DIAGNOSTIC_61XX           = (short) 0x800B;
    protected static final short CMD_SELECT = (short) 0x00A4;
    protected static final short CMD_READ_RECORD = (short) 0x00B2;
    protected static final short CMD_DDA = (short) 0x0088;
    protected static final short CMD_VERIFY_PIN = (short) 0x0020;
    protected static final short CMD_GET_CHALLENGE = (short) 0x0084;
    protected static final short CMD_GET_DATA = (short) 0x80CA;
    protected static final short CMD_GET_PROCESSING_OPTIONS = (short) 0x80A8;
    protected static final short CMD_GENERATE_AC = (short) 0x80AE;
    protected static final short CMD_EXTERNAL_AUTHENTICATE = (short) 0x0082;
    protected static final short CMD_GET_RESPONSE = (short) 0x00C0;
    protected static final short CMD_STORE_DATA = (short) 0x00E2;

    // DGI ranges for STORE DATA
    protected static final short DGI_TAG_TEMPLATE_BASE = (short) 0xB001;
    protected static final short DGI_READ_RECORD_BASE  = (short) 0xC001;

    protected static RandomData randomData;
    protected static byte[] tmpBuffer;

    // For GET RESPONSE chaining of large responses
    protected static short pendingResponseOffset = 0;
    protected static short pendingResponseLength = 0;

    // For chunked tag transfer (T=0 cards that don't support extended APDUs)
    protected static byte[] chunkBuffer;
    protected static short chunkTagId = 0;
    protected static short chunkExpectedLength = 0;
    protected static short chunkAccumulatedLength = 0;

    protected static void logAndThrow(short responseTrailer) {
        ApduLog.addLogEntry(responseTrailer);
        ISOException.throwIt(responseTrailer);
    }


    protected EmvTag emvTags;
    protected ReadRecord readRecords;

    protected TagTemplate responseTemplateGetProcessingOptions;
    protected TagTemplate responseTemplateDda;
    protected TagTemplate responseTemplateGenerateAc;
    protected TagTemplate tag6fFci;
    protected TagTemplate tagA5Fci;
    protected TagTemplate tagBf0cFci;

    protected byte[] defaultReadRecord;


    protected short responseTemplateTag;
    protected boolean randomResponseSuffixData;

    protected void factoryReset(APDU apdu, byte[] buf) {
        if (Util.getShort(buf, ISO7816.OFFSET_P1) != 0x0000) {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }

        factoryReset();

        ISOException.throwIt(ISO7816.SW_NO_ERROR);
    }

    protected void factoryReset() {
        JCSystem.beginTransaction();

        responseTemplateTag = (short) 0x0077;
        randomResponseSuffixData = false;

        JCSystem.commitTransaction();

        ApduLog.clear();
        ReadRecord.clear();
        EmvTag.clear();
    }

    protected void fuzzReset(APDU apdu, byte[] buf) {
        if (Util.getShort(buf, ISO7816.OFFSET_P1) != 0x0000) {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }

        fuzzReset();

        ISOException.throwIt(ISO7816.SW_NO_ERROR);
    }

    protected void fuzzReset() {
        JCSystem.beginTransaction();

        randomResponseSuffixData = false;
        defaultReadRecord = null;

        JCSystem.commitTransaction();

        EmvTag.clearFuzz();
    }

    protected void consumeLogs(APDU apdu, byte[] buf) {
        short p1p2 = Util.getShort(buf, ISO7816.OFFSET_P1);
        switch (p1p2) {
            case (short) 0x0000:
                ApduLog logEntry = ApduLog.getHead();

                if (logEntry != null) {
                    // hack to omit AID SELECT for reading the logs
                    if (logEntry.next == ApduLog.tail && Util.getShort(logEntry.getData(), (short) 0) == 0x00A4) {
                        ApduLog.clear();
                        ISOException.throwIt(ISO7816.SW_RECORD_NOT_FOUND);
                    }

                    Util.arrayCopy(logEntry.getData(), (short) 0, buf, (short) 0, (short) (logEntry.getLength() & 0x00FF));
                    ApduLog.removeLog(logEntry);
                    apdu.setOutgoingAndSend((short) 0, (short) (logEntry.getLength() & 0x00FF));
                } else {
                    ISOException.throwIt(ISO7816.SW_RECORD_NOT_FOUND);
                }

                break;
            case (short) 0x0100:
                ApduLog.clear();
                ISOException.throwIt(ISO7816.SW_NO_ERROR);
                break;
            default:
                ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
                break;
        }
    }

    protected void processSetEmvTag(APDU apdu, byte[] buf) {
        short tagId = Util.getShort(buf, ISO7816.OFFSET_P1);
        if (tagId == 0x0000) {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }

        // Determine data length and offset
        // Check for extended APDU: LC byte is 0, followed by 2-byte length
        short lcByte = (short) (buf[ISO7816.OFFSET_LC] & 0x00FF);
        short dataLen;
        short dataOffset;

        if (lcByte == 0) {
            // Extended APDU format: LC=0x00, then 2-byte length at offset 5-6, data at offset 7
            dataLen = Util.getShort(buf, (short)(ISO7816.OFFSET_LC + 1));
            dataOffset = (short) 7;  // Extended APDU data starts at offset 7
        } else {
            // Short APDU format: LC at offset 4, data at offset 5
            dataLen = lcByte;
            dataOffset = ISO7816.OFFSET_CDATA;  // = 5
        }

        JCSystem.beginTransaction();
        EmvTag tag = EmvTag.setTag(tagId, buf, dataOffset, dataLen);
        JCSystem.commitTransaction();

        ISOException.throwIt(ISO7816.SW_NO_ERROR);
    }

    /**
     * Process chunked EMV tag data for T=0 cards that don't support extended APDUs.
     * Command: 80 09 P1 P2 LC data
     * P1P2 = tag ID
     * First chunk: data[0..1] = total length (big-endian), data[2..] = first chunk data
     * Subsequent chunks: data = chunk data (appended to buffer)
     * When accumulated length == expected length, tag is finalized.
     */
    protected void processSetEmvTagChunked(APDU apdu, byte[] buf) {
        short tagId = Util.getShort(buf, ISO7816.OFFSET_P1);
        if (tagId == 0x0000) {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }

        // Get data length and offset (short APDU only for chunked transfer)
        short lcByte = (short) (buf[ISO7816.OFFSET_LC] & 0x00FF);
        short dataLen = lcByte;
        short dataOffset = ISO7816.OFFSET_CDATA;

        // Check if this is a new tag or continuation of existing
        if (chunkTagId != tagId || chunkAccumulatedLength == 0) {
            // New chunked transfer - first 2 bytes are total length
            if (dataLen < 2) {
                ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
            }

            // Reset chunking state
            chunkTagId = tagId;
            chunkExpectedLength = Util.getShort(buf, dataOffset);
            chunkAccumulatedLength = 0;

            // Validate expected length fits in buffer
            if (chunkExpectedLength > (short) 512 || chunkExpectedLength <= 0) {
                chunkTagId = 0;
                ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
            }

            // Copy first chunk data (after the 2-byte length header)
            short chunkDataLen = (short) (dataLen - 2);
            if (chunkDataLen > 0) {
                Util.arrayCopy(buf, (short) (dataOffset + 2), chunkBuffer, (short) 0, chunkDataLen);
                chunkAccumulatedLength = chunkDataLen;
            }
        } else {
            // Continuation of existing chunked transfer
            // Validate we won't overflow
            if ((short) (chunkAccumulatedLength + dataLen) > chunkExpectedLength) {
                // Too much data - abort
                chunkTagId = 0;
                chunkAccumulatedLength = 0;
                ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
            }

            // Append chunk data
            Util.arrayCopy(buf, dataOffset, chunkBuffer, chunkAccumulatedLength, dataLen);
            chunkAccumulatedLength += dataLen;
        }

        // Check if transfer is complete
        if (chunkAccumulatedLength == chunkExpectedLength) {
            // Finalize - store the tag
            JCSystem.beginTransaction();
            EmvTag.setTag(chunkTagId, chunkBuffer, (short) 0, chunkExpectedLength);
            JCSystem.commitTransaction();

            // Reset chunking state
            chunkTagId = 0;
            chunkAccumulatedLength = 0;
            chunkExpectedLength = 0;
        }

        ISOException.throwIt(ISO7816.SW_NO_ERROR);
    }

    protected void processSetEmvTagFuzz(APDU apdu, byte[] buf) {
        short tagId = Util.getShort(buf, ISO7816.OFFSET_P1);

        EmvTag tag = EmvTag.findTag(tagId);
        if (tag == null) {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }

        // Use correct data offset (works for both short and extended APDUs)
        short dataOffset = apdu.getOffsetCdata();

        tag.fuzzOffset     = buf[dataOffset];
        tag.fuzzLength     = buf[(short) (dataOffset + 1)];
        tag.fuzzFlags      = buf[(short) (dataOffset + 2)];
        tag.fuzzOccurrence = buf[(short) (dataOffset + 3)];

        ISOException.throwIt(ISO7816.SW_NO_ERROR);
    }

    protected void processSetTagTemplate(APDU apdu, byte[] buf) {
        TagTemplate template = null;

        short templateId = Util.getShort(buf, ISO7816.OFFSET_P1);

        switch (templateId) {
            case 0x0001:
                template = responseTemplateGetProcessingOptions;
                break;
            case 0x0002:
                template = responseTemplateDda;
                break;
            case 0x0003:
                template = responseTemplateGenerateAc;
                break;
            case 0x0004:
                template = tag6fFci;
                break;
            case 0x0005:
                template = tagA5Fci;
                break;
            case 0x0006:
                template = tagBf0cFci;
                break;
            default:
                ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }

        if (template == null) {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }

        // Use APDU methods for correct offset and length (works for both short and extended APDUs)
        short dataOffset = apdu.getOffsetCdata();
        short dataLen = apdu.getIncomingLength();
        // Fallback for platforms where getIncomingLength returns 0
        if (dataLen == 0) {
            dataLen = (short) (buf[ISO7816.OFFSET_LC] & 0x00FF);
            dataOffset = ISO7816.OFFSET_CDATA;
        }

        JCSystem.beginTransaction();
        template.setData(buf, dataOffset, (byte) dataLen);
        JCSystem.commitTransaction();

        ISOException.throwIt(ISO7816.SW_NO_ERROR);
    }

    protected void processSetReadRecordTemplate(APDU apdu, byte[] buf) {
        short readRecordId = Util.getShort(buf, ISO7816.OFFSET_P1);

        if (readRecordId == 0x0000) {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }

        // Use APDU methods for correct offset and length (works for both short and extended APDUs)
        short dataOffset = apdu.getOffsetCdata();
        short dataLen = apdu.getIncomingLength();
        // Fallback for platforms where getIncomingLength returns 0
        if (dataLen == 0) {
            dataLen = (short) (buf[ISO7816.OFFSET_LC] & 0x00FF);
            dataOffset = ISO7816.OFFSET_CDATA;
        }

        JCSystem.beginTransaction();
        ReadRecord.setRecord(readRecordId, buf, dataOffset, (byte) dataLen);
        JCSystem.commitTransaction();

        ISOException.throwIt(ISO7816.SW_NO_ERROR);
    }

    /**
     * Process GP STORE DATA (INS 0xE2) per CPS v2.0.
     * Supports multiple DGIs per command. Data format per DGI:
     *   [DGI (2 bytes)] [Length (1-3 bytes BER)] [Data...]
     *
     * CPS DGI routing:
     *   0x0101-0x1Exx = SFI-based record (first byte=SFI, second=record#). Data starts with tag 70.
     *   0x8000       = Block cipher keys (RSA/EC) — subclass handles
     *   0x8010       = Offline PIN block — subclass handles
     *   0x9010       = PIN related data — subclass handles
     *   0xB001-0xB006 = Tag template (app-specific, low byte = template ID)
     *   0xA0xx       = App-specific settings — subclass handles (legacy, non-CPS)
     *   Other        = EMV tag (DGI = tag ID)
     */
    protected void processStoreData(APDU apdu, byte[] buf) {
        short dataOffset = apdu.getOffsetCdata();
        short totalLen = apdu.getIncomingLength();
        if (totalLen == 0) {
            totalLen = (short) (buf[ISO7816.OFFSET_LC] & 0x00FF);
            dataOffset = ISO7816.OFFSET_CDATA;
        }

        if (totalLen < 3) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        short endOffset = (short) (dataOffset + totalLen);

        // Process multiple DGIs per command (CPS v2.0 Section 2.4)
        while (dataOffset < endOffset) {
            // Parse DGI (2 bytes)
            short dgi = Util.getShort(buf, dataOffset);
            dataOffset += 2;

            // Parse length (1 or 3 bytes BER)
            short dgiDataLen;
            if ((buf[dataOffset] & 0xFF) == 0x81) {
                dgiDataLen = (short) (buf[(short) (dataOffset + 1)] & 0x00FF);
                dataOffset += 2;
            } else if ((buf[dataOffset] & 0xFF) == 0x82) {
                dgiDataLen = Util.getShort(buf, (short) (dataOffset + 1));
                dataOffset += 3;
            } else {
                dgiDataLen = (short) (buf[dataOffset] & 0x00FF);
                dataOffset += 1;
            }

            // Route this DGI
            processOneDgi(dgi, buf, dataOffset, dgiDataLen);

            // Advance to next DGI
            dataOffset += dgiDataLen;
        }

        ISOException.throwIt(ISO7816.SW_NO_ERROR);
    }

    /**
     * Route a single DGI to the appropriate storage handler.
     */
    protected void processOneDgi(short dgi, byte[] buf, short offset, short length) {
        short dgiHigh = (short) ((dgi >> 8) & 0x00FF);
        short dgiLow = (short) (dgi & 0x00FF);

        if (dgiHigh >= 0x01 && dgiHigh <= 0x1E) {
            // CPS SFI-based record: DGI high byte = SFI, low byte = record number
            // Per CPS requirement 5: data in DGIs 01xx-0Axx starts with tag 70 + length
            // Strip the 70 wrapper if present, store the inner content
            short recordId = (short) ((dgiLow << 8) | ((dgiHigh << 3) | 0x04));
            short dataOffset = offset;
            short dataLen = length;

            // Check for and strip tag 70 wrapper
            if (length >= 2 && buf[offset] == (byte) 0x70) {
                short innerLen;
                if ((buf[(short)(offset + 1)] & 0xFF) == 0x81) {
                    innerLen = (short)(buf[(short)(offset + 2)] & 0x00FF);
                    dataOffset = (short)(offset + 3);
                } else {
                    innerLen = (short)(buf[(short)(offset + 1)] & 0x00FF);
                    dataOffset = (short)(offset + 2);
                }
                dataLen = innerLen;
            }

            JCSystem.beginTransaction();
            ReadRecord.setRecord(recordId, buf, dataOffset, (byte) dataLen);
            JCSystem.commitTransaction();
        } else if (dgi == (short) 0x8000 || dgi == (short) 0x8010 || dgi == (short) 0x9010
                   || dgi == (short) 0x8201 || dgi == (short) 0x8202 || dgi == (short) 0x8203) {
            // CPS standard: 8000 = symmetric keys, 8010 = PIN, 9010 = PIN data
            // App-specific: 8201 = RSA modulus, 8202 = RSA exponent, 8203 = EC scalar
            processStoreDataSettings(dgi, buf, offset, length);
        } else if (dgi == (short) 0x9000) {
            // CPS DGI 9000: Key Check Values — acknowledged but not verified
            // Real implementation would verify KCVs against loaded keys
        } else if (dgiHigh == (short) 0x00B0 && dgiLow >= 0x01 && dgiLow <= 0x06) {
            // App-specific: tag templates B001-B006, low byte = template ID
            TagTemplate template = getTagTemplate(dgiLow);
            if (template == null) {
                ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
            }
            JCSystem.beginTransaction();
            template.setData(buf, offset, (byte) length);
            JCSystem.commitTransaction();
        } else if (dgiHigh == (short) 0x00A0) {
            // App-specific settings: A002 (response template), A003 (flags), A006 (fallback record)
            processStoreDataSettings(dgi, buf, offset, length);
        } else if (dgi == (short) 0x0062) {
            // CPS DGI 0062: file structure creation — acknowledged but no-op
            // Our applet auto-creates records without explicit EF creation
        } else if (dgiHigh == (short) 0x009F && dgiLow >= 0x60 && dgiLow <= 0x6F) {
            // CPS reserved: 9F60-9F6F are for payment system proprietary data
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        } else if (dgi != (short) 0x0000) {
            // Everything else (non-zero) = EMV tag: DGI is the tag ID
            JCSystem.beginTransaction();
            EmvTag.setTag(dgi, buf, offset, length);
            JCSystem.commitTransaction();
        } else {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }
    }

    /**
     * Override in subclasses to handle applet-specific STORE DATA DGIs.
     * CPS standard: 8000 (keys), 8010 (PIN), 9010 (PIN data).
     * Legacy: A0xx (app-specific settings).
     */
    protected void processStoreDataSettings(short dgi, byte[] buf, short offset, short length) {
        ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
    }

    /**
     * Get tag template by ID (1-6). Used by STORE DATA and processSetTagTemplate.
     */
    protected TagTemplate getTagTemplate(short templateId) {
        switch (templateId) {
            case 0x0001: return responseTemplateGetProcessingOptions;
            case 0x0002: return responseTemplateDda;
            case 0x0003: return responseTemplateGenerateAc;
            case 0x0004: return tag6fFci;
            case 0x0005: return tagA5Fci;
            case 0x0006: return tagBf0cFci;
            default: return null;
        }
    }

    protected void sendResponseTemplate(APDU apdu, byte[] buf, TagTemplate template) {
        short templateTagLength = (short) 0;

        if (responseTemplateTag == (short) 0x0077) {
            // Template 2, tag 77
            templateTagLength = template.expandTlvToArray(tmpBuffer, (short) 0);
            // expandTlvToArray completed
        } else if (responseTemplateTag == (short) 0x0080) {
            // Template 1, tag 80
            templateTagLength = template.expandTagDataToArray(tmpBuffer, (short) 0);
        } else {
            EmvApplet.logAndThrow(ISO7816.SW_DATA_INVALID);
        }

        // Set template tag with full length (supports > 255 bytes for CDA)
        EmvTag.setTag(responseTemplateTag, tmpBuffer, (short) 0, templateTagLength);
        sendResponse(apdu, buf, responseTemplateTag);
    }

    protected void sendResponse(APDU apdu, byte[] buf, short tagId) {
        EmvTag tag = EmvTag.findTag(tagId);
        if (tag == null) {
            EmvApplet.logAndThrow(ISO7816.SW_DATA_INVALID);
        }

        // Copy tag TLV to tmpBuffer for consistent handling
        short dataLength = tag.copyToArray(tmpBuffer, (short) 0);

        // For responses <= 256 bytes, use simple approach
        if (dataLength <= (short) 256) {
            Util.arrayCopy(tmpBuffer, (short) 0, buf, (short) ISO7816.OFFSET_CDATA, dataLength);
            ApduLog.addLogEntry(buf, (short) ISO7816.OFFSET_CDATA, (byte) (dataLength & 0xFF));
            apdu.setOutgoingAndSend((short) ISO7816.OFFSET_CDATA, dataLength);
        } else {
            // For large responses, use GET RESPONSE chaining
            short firstChunk = (short) 256;
            pendingResponseLength = (short) (dataLength - firstChunk);

            // Copy remaining bytes to chunkBuffer for GET RESPONSE
            Util.arrayCopy(tmpBuffer, firstChunk, chunkBuffer, (short) 0, pendingResponseLength);

            // Send first 256 bytes
            apdu.setOutgoing();
            apdu.setOutgoingLength(firstChunk);
            apdu.sendBytesLong(tmpBuffer, (short) 0, firstChunk);

            // Signal more data available
            short remaining = pendingResponseLength;
            if (remaining > (short) 255) {
                remaining = (short) 255;
            }
            ISOException.throwIt((short) (0x6100 | remaining));
        }
    }

    protected void sendResponse(APDU apdu, byte[] buf, byte[] data, short dataOffset, short length) {
        if (data != buf) {
            Util.arrayCopy(data, dataOffset, buf, (short) ISO7816.OFFSET_CDATA, length);
        }

        ApduLog.addLogEntry(buf, (short) ISO7816.OFFSET_CDATA, (byte) length);

        apdu.setOutgoingAndSend((short) ISO7816.OFFSET_CDATA, length);
    }

    protected void processReadRecord(APDU apdu, byte[] buf) {
        short p1p2 = Util.getShort(buf, ISO7816.OFFSET_P1);

        ReadRecord readRecord = ReadRecord.findRecord(p1p2);
        if (readRecord == null) {
            if (defaultReadRecord != null) {
                short p1p2Fallback = Util.getShort(defaultReadRecord, (short) 0);
                readRecord = ReadRecord.findRecord(p1p2Fallback);
            }

            if (readRecord == null) {
                EmvApplet.logAndThrow(ISO7816.SW_RECORD_NOT_FOUND);
            }
        }

        short tag70Length = readRecord.expandTlvToArray(tmpBuffer, (short) 0);

        EmvTag tag = EmvTag.setTag((short) 0x0070, tmpBuffer, (short) 0, tag70Length);

        if (buf[ISO7816.OFFSET_LC] != (byte) 0x00 && buf[ISO7816.OFFSET_LC] != tag.getLength()) {
            EmvApplet.logAndThrow(ISO7816.SW_WRONG_LENGTH);
        }

        sendResponse(apdu, buf, (short) 0x0070);
    }

    protected EmvApplet() {
        tmpBuffer = JCSystem.makeTransientByteArray((short) 512, JCSystem.CLEAR_ON_DESELECT);
        chunkBuffer = new byte[512];  // Persistent buffer for chunked transfers

        factoryReset();

        responseTemplateGetProcessingOptions = new TagTemplate();
        responseTemplateDda = new TagTemplate();
        responseTemplateGenerateAc = new TagTemplate();
        tag6fFci = new TagTemplate();
        tagA5Fci = new TagTemplate();
        tagBf0cFci = new TagTemplate();

        //emvTags = EmvTag.setTag((short) 0x00, tmpBuffer, (short) 0, (byte) 0);

        //readRecords = ReadRecord.setRecord((short) 0x00, tmpBuffer, (short) 0, (byte) 0);

        randomData = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
    }
}
