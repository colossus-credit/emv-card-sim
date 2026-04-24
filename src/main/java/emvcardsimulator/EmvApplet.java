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

    public static void logAndThrow(short responseTrailer) {
        ApduLog.addLogEntry(responseTrailer);
        ISOException.throwIt(responseTrailer);
    }


    /**
     * Personalization lifecycle (CPS v2.0). Tracks PERSO_PENDING vs PERSO_DONE.
     * Each applet instance gets its own lifecycle so PSE / PaymentApp / PPSE
     * can be personalized independently.
     */
    protected AppletLifecycle lifecycle;

    protected TagTemplate responseTemplateGetProcessingOptions;
    protected TagTemplate responseTemplateDda;
    protected TagTemplate responseTemplateGenerateAc;
    protected TagTemplate tag6fFci;
    protected TagTemplate tagA5Fci;
    protected TagTemplate tagBf0cFci;

    protected byte[] defaultReadRecord;

    /** Scratch array for building RecordTemplate refs at STORE DATA time. */
    protected static EmvTag[] tmpTagRefs;


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
        EmvTag.clear();
        RecordTemplate.clearAll();

        // Reset tag templates (B001–B006) so a previous personalization's
        // tag list doesn't leak across factory-reset boundaries and cause
        // SW_DATA_INVALID (0x6984) in expandTlvToArray when a referenced tag
        // is no longer present in the EmvTag store.
        if (responseTemplateGetProcessingOptions != null) {
            responseTemplateGetProcessingOptions.clear();
        }
        if (responseTemplateDda != null) {
            responseTemplateDda.clear();
        }
        if (responseTemplateGenerateAc != null) {
            responseTemplateGenerateAc.clear();
        }
        if (tag6fFci != null) {
            tag6fFci.clear();
        }
        if (tagA5Fci != null) {
            tagA5Fci.clear();
        }
        if (tagBf0cFci != null) {
            tagBf0cFci.clear();
        }

        if (lifecycle != null) {
            lifecycle.resetForTesting();
        }
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

        // Canonicalize: strip the low 3 bits of P2 (reference control bits)
        // so that the key matches processReadRecord's canonical lookup.
        // P1 = record number, P2 = (SFI << 3) | ref_control.
        // Python sends P2 = (SFI << 3) | 0x04; we store at (SFI << 3).
        short canonicalKey = (short) (readRecordId & (short) 0xFFF8);

        // Use APDU methods for correct offset and length (works for both short and extended APDUs)
        short dataOffset = apdu.getOffsetCdata();
        short dataLen = apdu.getIncomingLength();
        // Fallback for platforms where getIncomingLength returns 0
        if (dataLen == 0) {
            dataLen = (short) (buf[ISO7816.OFFSET_LC] & 0x00FF);
            dataOffset = ISO7816.OFFSET_CDATA;
        }

        // Parse the incoming tag-ID list: pairs of 2-byte tag IDs (single-byte
        // tags are 00-padded, e.g., [00 57 00 5A 5F 24 9F 07]).
        // Resolve each to a direct EmvTag reference for O(k) READ RECORD.
        short refCount = (short) 0;
        for (short i = (short) 0; i < dataLen; i += (short) 2) {
            short tagId = Util.getShort(buf, (short) (dataOffset + i));
            EmvTag ref = EmvTag.findTag(tagId);
            if (ref == null) {
                // Tag will be populated later via set_emv_tag (dev command 0x8001).
                // Create an empty placeholder to hold the reference.
                ref = new EmvTag(tagId, buf, (short) 0, (short) 0);
            }
            tmpTagRefs[refCount] = ref;
            refCount++;
        }

        RecordTemplate.setTemplate(canonicalKey, tmpTagRefs, refCount);

        ISOException.throwIt(ISO7816.SW_NO_ERROR);
    }

    /**
     * Process GP STORE DATA (INS 0xE2) per CPS v2.0.
     * Supports multiple DGIs per command. Data format per DGI:
     *   [DGI (2 bytes)] [Length (1-3 bytes BER)] [Data...]
     *
     * CPS DGI routing:
     *   0x0062       = File structure creation (CPS Annex A.5) — accepted as no-op
     *   0x0101-0x1Exx = SFI-based record (first byte=SFI, second=record#). Data may have tag 70 wrapper.
     *   0x7FFF       = Integrity MAC of the personalization data (CPS §4.3.5.2) — accepted as no-op
     *   0x8000       = Block cipher keys (RSA/EC) — subclass handles
     *   0x8010       = Offline PIN block — subclass handles
     *   0x9010       = PIN related data — subclass handles
     *   0xB001-0xB006 = Tag template (app-specific, low byte = template ID)
     *   0xA0xx       = App-specific settings — subclass handles (legacy, non-CPS)
     *   Other        = EMV tag (DGI = tag ID)
     *
     * Lifecycle:
     *   - Rejects with 6985 if personalization has already completed (CPS §4.3.5.4)
     *   - Commits the lifecycle to PERSO_DONE if P1 bit 8 is set (last STORE DATA,
     *     CPS §4.3.4 Table 4-9 and §4.3.5.1). No further STORE DATAs accepted after.
     */
    protected void processStoreData(APDU apdu, byte[] buf) {
        lifecycle.requirePersoPending();

        // CPS §4.3.4 Table 4-9: P1 bit 8 = 1 indicates the last STORE DATA command.
        boolean isLastStoreData = (buf[ISO7816.OFFSET_P1] & 0x80) != 0;

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
            dataOffset = (short) (dataOffset + 2);

            // Parse length (1 or 3 bytes BER)
            short dgiDataLen;
            if ((buf[dataOffset] & 0xFF) == 0x81) {
                dgiDataLen = (short) (buf[(short) (dataOffset + 1)] & 0x00FF);
                dataOffset = (short) (dataOffset + 2);
            } else if ((buf[dataOffset] & 0xFF) == 0x82) {
                dgiDataLen = Util.getShort(buf, (short) (dataOffset + 1));
                dataOffset = (short) (dataOffset + 3);
            } else {
                dgiDataLen = (short) (buf[dataOffset] & 0x00FF);
                dataOffset = (short) (dataOffset + 1);
            }

            // Route this DGI
            processOneDgi(dgi, buf, dataOffset, dgiDataLen);

            // Advance to next DGI
            dataOffset += dgiDataLen;
        }

        // If this is the last STORE DATA command, transition to PERSO_DONE.
        // CPS §4.3.5.1: the transition may be rejected if the applet detects
        // missing data, in which case 6A86 should be returned. We don't enforce
        // a required-data set yet (that's applet-specific), so we always commit.
        if (isLastStoreData) {
            lifecycle.commitPersonalization();
        }

        ISOException.throwIt(ISO7816.SW_NO_ERROR);
    }

    /**
     * Route a single DGI to the appropriate storage handler.
     */
    protected void processOneDgi(short dgi, byte[] buf, short offset, short length) {
        short dgiHigh = (short) ((dgi >> 8) & 0x00FF);
        short dgiLow = (short) (dgi & 0x00FF);

        if (dgiHigh >= 0x01 && dgiHigh <= 0x1E && dgiLow >= 0x01) {
            // CPS SFI-based record: DGI high byte = SFI, low byte = record number.
            // Data may be wrapped in a tag-70 TLV per CPS Annex A.5 / EMV Book 3
            // §6.5.11. Strip the wrapper if present, then store raw record body.
            byte sfi = (byte) dgiHigh;
            byte recordNo = (byte) dgiLow;

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

            // Parse inner TLV: store each tag's value in EmvTag, and collect
            // direct EmvTag references into tmpTagRefs for the RecordTemplate.
            // At READ RECORD time the template resolves each tag's CURRENT
            // value via the stored reference — no linked-list walk needed.
            // Dynamic tags (e.g., 9F6E updated at GPO) work because setData()
            // modifies the EmvTag node in place; the reference stays valid.
            short refCount = (short) 0;
            short pos = dataOffset;
            short endPos = (short) (dataOffset + dataLen);
            while (pos < endPos) {
                // Read tag (1 or 2 bytes)
                short tagId;
                if ((buf[pos] & (byte) 0x1F) == (byte) 0x1F) {
                    tagId = Util.getShort(buf, pos);
                    pos += (short) 2;
                } else {
                    tagId = (short) (buf[pos] & 0x00FF);
                    pos += (short) 1;
                }

                // Read BER length
                short tLen;
                if ((buf[pos] & 0xFF) == 0x82) {
                    pos += (short) 1;
                    tLen = Util.getShort(buf, pos);
                    pos += (short) 2;
                } else if ((buf[pos] & 0xFF) == 0x81) {
                    pos += (short) 1;
                    tLen = (short) (buf[pos] & 0x00FF);
                    pos += (short) 1;
                } else {
                    tLen = (short) (buf[pos] & 0x00FF);
                    pos += (short) 1;
                }

                // Store tag value and capture the direct reference
                EmvTag ref = EmvTag.setTag(tagId, buf, pos, tLen);
                tmpTagRefs[refCount] = ref;
                refCount++;

                pos += tLen;
            }

            // Build RecordTemplate with direct EmvTag references — O(k) READ RECORD
            short recordKey = (short) ((recordNo << 8) | (sfi << 3));
            RecordTemplate.setTemplate(recordKey, tmpTagRefs, refCount);
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
            // CPS DGI 0062: file structure creation (Annex A.5 Table A-27).
            // The applet simulates files via EmvTag template expansion (CPS
            // §5.3), so we don't allocate actual EFs. But we validate the FCP
            // structure so bureau edge-case tests get correct 6A80 responses
            // for malformed data.
            validateDgi0062(buf, offset, length);
        } else if (dgi == (short) 0x7FFF) {
            // CPS §4.3.5.2: DGI 7FFF carries the integrity MAC over the
            // personalization data. It must be accepted on the last STORE DATA
            // command. We don't verify the MAC (no MAC key plumbed yet) but we
            // accept it as a no-op so real perso bureau scripts don't fail.
        } else if (dgi >= (short) 0x7FF0 && dgi <= (short) 0x7FFE) {
            // CPS §3.2 bullet 10: reserved for application-independent processing
            ISOException.throwIt(PersoSw.SW_UNRECOGNIZED_DGI);
        } else if (isAcceptedTagDgi(dgi)) {
            // CPS §3.2 bullet 7: DGI value == EMV tag → store directly.
            // Only tags the applet actually uses are accepted; everything
            // else is rejected per CPS §5.4.2.3.
            EmvTag.setTag(dgi, buf, offset, length);
        } else {
            // CPS §5.4.2.3: unrecognised DGI
            ISOException.throwIt(PersoSw.SW_UNRECOGNIZED_DGI);
        }
    }

    /**
     * Whitelist of standalone tag DGIs accepted per CPS §3.2 bullet 7.
     * These are tags NOT contained in any record but needed by the applet
     * at transaction time (FCI SELECT, GPO, GenAC) or during perso.
     */
    private static final short[] ACCEPTED_TAG_DGIS = {
        // FCI SELECT response tags
        (short) 0x0050, // Application Label
        (short) 0x0082, // Application Interchange Profile (AIP)
        (short) 0x0084, // DF Name (AID)
        (short) 0x0087, // Application Priority Indicator
        (short) 0x0088, // SFI of Directory EF (PSE)
        (short) 0x008E, // CVM List (PSE)
        (short) 0x5F2D, // Language Preference
        (short) 0x9F11, // Issuer Code Table Index
        (short) 0x9F12, // Application Preferred Name (contactless)
        (short) 0x9F38, // PDOL (contactless)
        // GPO / GenAC response tags
        (short) 0x0094, // Application File Locator (AFL)
        (short) 0x9F10, // Issuer Application Data (IAD)
        (short) 0x9F36, // Application Transaction Counter (ATC)
        (short) 0x9F6C, // Card Transaction Qualifiers (CTQ, contactless)
        // Internal / other
        (short) 0x9F1F, // Track 1 Discretionary Data
    };

    private static boolean isAcceptedTagDgi(short dgi) {
        for (short i = 0; i < ACCEPTED_TAG_DGIS.length; i++) {
            if (ACCEPTED_TAG_DGIS[i] == dgi) {
                return true;
            }
        }
        return false;
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
     * Validate DGI 0062 FCP structure per CPS v2.0 Annex A.5 Table A-27.
     * Checks that mandatory tags (80, 82, 88) are present and SFI is in
     * range 01-1E. Throws 6A80 on validation failure. Does NOT allocate
     * file structures — the applet simulates files via EmvTag templates.
     */
    protected void validateDgi0062(byte[] buf, short offset, short length) {
        short pos = offset;
        short end = (short) (offset + length);

        // DGI 0062 contains one or more FCP TLVs (tag 62)
        while (pos < end) {
            // Expect tag 62 (FCP template)
            if (buf[pos] != (byte) 0x62) {
                ISOException.throwIt(PersoSw.SW_INCORRECT_DATA);
            }
            pos++;

            // Read FCP length (single byte — FCP is always < 128 bytes)
            if (pos >= end) {
                ISOException.throwIt(PersoSw.SW_INCORRECT_DATA);
            }
            short fcpLen = (short) (buf[pos] & 0x00FF);
            pos++;

            short fcpEnd = (short) (pos + fcpLen);
            if (fcpEnd > end) {
                ISOException.throwIt(PersoSw.SW_INCORRECT_DATA);
            }

            // Walk inner TLVs, check for mandatory tags 80, 82, 88
            boolean has80 = false;
            boolean has82 = false;
            boolean has88 = false;
            short sfi = (short) 0;

            while (pos < fcpEnd) {
                if (pos >= fcpEnd) {
                    ISOException.throwIt(PersoSw.SW_INCORRECT_DATA);
                }
                byte tag = buf[pos];
                pos++;

                if (pos >= fcpEnd) {
                    ISOException.throwIt(PersoSw.SW_INCORRECT_DATA);
                }
                short tLen = (short) (buf[pos] & 0x00FF);
                pos++;

                if ((short) (pos + tLen) > fcpEnd) {
                    ISOException.throwIt(PersoSw.SW_INCORRECT_DATA);
                }

                switch (tag) {
                    case (byte) 0x80:
                        has80 = true;
                        break;
                    case (byte) 0x82:
                        has82 = true;
                        break;
                    case (byte) 0x88:
                        has88 = true;
                        if (tLen != (short) 1) {
                            ISOException.throwIt(PersoSw.SW_INCORRECT_DATA);
                        }
                        sfi = (short) (buf[pos] & 0x00FF);
                        break;
                    case (byte) 0x8C:
                        // Optional security attributes — accepted, ignored
                        break;
                    default:
                        // Unknown tag in FCP — reject
                        ISOException.throwIt(PersoSw.SW_INCORRECT_DATA);
                }

                pos += tLen;
            }

            // All three mandatory tags must be present
            if (!has80 || !has82 || !has88) {
                ISOException.throwIt(PersoSw.SW_INCORRECT_DATA);
            }

            // SFI must be in range 01-1E per Table A-27
            if (sfi < (short) 0x01 || sfi > (short) 0x1E) {
                ISOException.throwIt(PersoSw.SW_INCORRECT_DATA);
            }
        }
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

        // Canonicalize the lookup key: strip the low 3 bits of P2.
        // P2 is (SFI << 3) | reference_control. Terminals send 0x04 ("by SFI")
        // in the low 3 bits, but the AFL byte has 0x00. Both must resolve to the
        // same record. We store records keyed by (recordNo << 8) | (SFI << 3),
        // so stripping the low 3 bits gives a consistent lookup.
        short recordKey = (short) (p1p2 & (short) 0xFFF8);

        // Look up the pre-built record template. Both CPS STORE DATA records
        // and legacy dev 0x8003 records store direct EmvTag references that
        // are expanded at READ time via copyToArray — O(k) where k = number
        // of tags in the record. Dynamic tags (e.g., 9F6E written at GPO time)
        // are automatically resolved to their current value because setData()
        // modifies the EmvTag node in place; the stored reference stays valid.
        RecordTemplate template = RecordTemplate.findTemplate(recordKey);
        if (template == null) {
            EmvApplet.logAndThrow(ISO7816.SW_RECORD_NOT_FOUND);
        }

        // Expand all tag values into tmpBuffer — O(k) direct reference access
        short contentLen = template.expandToArray(tmpBuffer, (short) 0);

        // Build tag 70 wrapper in chunkBuffer and send via sendBytesLong.
        // This matches the proven-working pattern from feat/applet-hardening:
        // chunkBuffer is a persistent byte[] allocated at install time, and
        // sendBytesLong is the standard JavaCard send path for non-APDU
        // buffer data. Using the APDU buffer + setOutgoingAndSend was
        // attempted as an optimization but doesn't improve NFC reliability.
        short respLen = (short) 0;
        chunkBuffer[respLen++] = (byte) 0x70;
        if (contentLen >= (short) 128) {
            chunkBuffer[respLen++] = (byte) 0x81;
            chunkBuffer[respLen++] = (byte) (contentLen & 0xFF);
        } else {
            chunkBuffer[respLen++] = (byte) contentLen;
        }
        Util.arrayCopy(tmpBuffer, (short) 0, chunkBuffer, respLen, contentLen);
        respLen += contentLen;

        apdu.setOutgoing();
        apdu.setOutgoingLength(respLen);
        apdu.sendBytesLong(chunkBuffer, (short) 0, respLen);
    }

    protected EmvApplet() {
        tmpBuffer = JCSystem.makeTransientByteArray((short) 512, JCSystem.CLEAR_ON_DESELECT);
        chunkBuffer = new byte[512];  // Persistent buffer for chunked transfers
        // Max tags per record is ~30 (typical EMV record has 4-8 tags).
        tmpTagRefs = new EmvTag[30];

        // Instantiate lifecycle BEFORE factoryReset() so it can clear it safely.
        lifecycle = new AppletLifecycle();

        factoryReset();

        responseTemplateGetProcessingOptions = new TagTemplate();
        responseTemplateDda = new TagTemplate();
        responseTemplateGenerateAc = new TagTemplate();
        tag6fFci = new TagTemplate();
        tagA5Fci = new TagTemplate();
        tagBf0cFci = new TagTemplate();

        randomData = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
    }
}
