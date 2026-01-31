package emvcardsimulator;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.CryptoException;
import javacard.security.KeyBuilder;
import javacard.security.MessageDigest;
import javacard.security.RSAPrivateKey;
import javacard.security.RSAPublicKey;
import javacard.security.RandomData;
import javacardx.crypto.Cipher;

public class PaymentApplication extends EmvApplet {

    public static void install(byte[] buffer, short offset, byte length) {
        (new PaymentApplication(buffer, offset, length)).register();
    }

    private Cipher rsaCipher;
    private MessageDigest shaMessageDigest;
    private byte[] challenge;
    private byte[] tag9f4cDynamicNumber;

    private RSAPrivateKey rsaPrivateKey = null;
    private short rsaPrivateKeyByteSize = 0;
    private byte[] pinCode = null;
    private boolean useRandom = true;

    // Storage for CDOL1 data from first GENERATE AC (needed for second GENERATE AC's Transaction Data Hash)
    private byte[] storedCdol1Data = null;
    private short storedCdol1Length = 0;

    // Storage for PDOL data from GPO (needed for CDA Transaction Data Hash)
    private byte[] storedPdolData = null;
    private short storedPdolLength = 0;

    // DEBUG: Storage for Transaction Data Hash input and output
    private byte[] debugHashInput = null;
    private short debugHashInputLength = 0;
    private byte[] debugHashOutput = null;

    // DEBUG: Storage for SDAD hash input and output
    private byte[] debugSdadHashInput = null;
    private short debugSdadHashInputLength = 0;
    private byte[] debugSdadHashOutput = null;

    // Chunked settings transfer state (for RSA key on T=0 cards)
    private byte[] settingsChunkBuffer = null;
    private short settingsChunkSettingId = 0;
    private short settingsChunkExpectedLength = 0;
    private short settingsChunkAccumulatedLength = 0;

    /**
     * Process chunked settings data for T=0 cards that don't support extended APDUs.
     * Command: 80 0A P1 P2 LC data
     * P1P2 = setting ID (0004 for modulus, 0005 for exponent)
     * First chunk: data[0..1] = total length (big-endian), data[2..] = first chunk data
     * Subsequent chunks: data = chunk data (appended to buffer)
     * When accumulated length == expected length, setting is applied.
     */
    private void processSetSettingsChunked(APDU apdu, byte[] buf) {
        short settingId = Util.getShort(buf, ISO7816.OFFSET_P1);

        // Only support RSA modulus (0004) and exponent (0005)
        if (settingId != (short) 0x0004 && settingId != (short) 0x0005) {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }

        // Get data length and offset (short APDU only for chunked transfer)
        short lcByte = (short) (buf[ISO7816.OFFSET_LC] & 0x00FF);
        short dataLen = lcByte;
        short dataOffset = ISO7816.OFFSET_CDATA;

        // Check if this is a new setting or continuation
        if (settingsChunkSettingId != settingId || settingsChunkAccumulatedLength == 0) {
            // New chunked transfer - first 2 bytes are total length
            if (dataLen < 2) {
                ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
            }

            // Reset chunking state
            settingsChunkSettingId = settingId;
            settingsChunkExpectedLength = Util.getShort(buf, dataOffset);
            settingsChunkAccumulatedLength = 0;

            // Validate expected length fits in buffer
            if (settingsChunkExpectedLength > (short) 512 || settingsChunkExpectedLength <= 0) {
                settingsChunkSettingId = 0;
                ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
            }

            // Copy first chunk data (after the 2-byte length header)
            short chunkDataLen = (short) (dataLen - 2);
            if (chunkDataLen > 0) {
                Util.arrayCopy(buf, (short) (dataOffset + 2), settingsChunkBuffer, (short) 0, chunkDataLen);
                settingsChunkAccumulatedLength = chunkDataLen;
            }
        } else {
            // Continuation of existing chunked transfer
            if ((short) (settingsChunkAccumulatedLength + dataLen) > settingsChunkExpectedLength) {
                settingsChunkSettingId = 0;
                settingsChunkAccumulatedLength = 0;
                ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
            }

            Util.arrayCopy(buf, dataOffset, settingsChunkBuffer, settingsChunkAccumulatedLength, dataLen);
            settingsChunkAccumulatedLength += dataLen;
        }

        // Check if transfer is complete
        if (settingsChunkAccumulatedLength == settingsChunkExpectedLength) {
            // Apply the setting
            if (settingId == (short) 0x0004) {
                // RSA modulus
                rsaPrivateKeyByteSize = settingsChunkExpectedLength;
                short keyLength = (short) (rsaPrivateKeyByteSize * 8);
                switch (keyLength) {
                    case (short) 1024: keyLength = KeyBuilder.LENGTH_RSA_1024; break;
                    case (short) 1280: keyLength = KeyBuilder.LENGTH_RSA_1280; break;
                    case (short) 1536: keyLength = KeyBuilder.LENGTH_RSA_1536; break;
                    case (short) 1984: keyLength = KeyBuilder.LENGTH_RSA_1984; break;
                    case (short) 2048: keyLength = KeyBuilder.LENGTH_RSA_2048; break;
                    default:
                        settingsChunkSettingId = 0;
                        settingsChunkAccumulatedLength = 0;
                        ISOException.throwIt((short) 0x6A80);
                }
                try {
                    rsaPrivateKey = (RSAPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PRIVATE, keyLength, false);
                    rsaPrivateKey.clearKey();
                    rsaPrivateKey.setModulus(settingsChunkBuffer, (short) 0, rsaPrivateKeyByteSize);
                } catch (CryptoException e) {
                    rsaPrivateKey = null;
                    rsaPrivateKeyByteSize = 0;
                    settingsChunkSettingId = 0;
                    settingsChunkAccumulatedLength = 0;
                    ISOException.throwIt((short) 0x6A81);
                }
            } else if (settingId == (short) 0x0005) {
                // RSA exponent
                if (rsaPrivateKey == null) {
                    settingsChunkSettingId = 0;
                    settingsChunkAccumulatedLength = 0;
                    ISOException.throwIt((short) 0x6985);
                }
                try {
                    rsaPrivateKey.setExponent(settingsChunkBuffer, (short) 0, settingsChunkExpectedLength);
                } catch (CryptoException e) {
                    rsaPrivateKey = null;
                    rsaPrivateKeyByteSize = 0;
                    settingsChunkSettingId = 0;
                    settingsChunkAccumulatedLength = 0;
                    ISOException.throwIt((short) 0x6A81);
                }
            }

            // Reset chunking state
            settingsChunkSettingId = 0;
            settingsChunkAccumulatedLength = 0;
            settingsChunkExpectedLength = 0;
        }

        ISOException.throwIt(ISO7816.SW_NO_ERROR);
    }

    private void processSetSettings(APDU apdu, byte[] buf) {
        short settingsId = Util.getShort(buf, ISO7816.OFFSET_P1);
        switch (settingsId) {
            // PIN CODE
            case 0x0001:
                Util.arrayCopy(buf, (short) ISO7816.OFFSET_CDATA, pinCode, (short) 0, (short) (buf[ISO7816.OFFSET_LC] & 0x00FF));
                break;
            // RESPONSE TEMPLATE
            case 0x0002:
                responseTemplateTag = Util.getShort(buf, ISO7816.OFFSET_CDATA);
                break;
            // FLAGS
            case 0x0003:
                short flags = Util.getShort(buf, ISO7816.OFFSET_CDATA);
                useRandom = ((flags & (1 << 0)) != 0);
                break;
            // ICC RSA KEY MODULUS
            case 0x0004:
                // Get actual data length (works for both short and extended APDUs)
                short modulusLen = apdu.getIncomingLength();
                // Fallback: if getIncomingLength returns 0, try LC byte (0 means 256 for short APDU)
                if (modulusLen == 0) {
                    short lcByte = (short) (buf[ISO7816.OFFSET_LC] & 0x00FF);
                    modulusLen = (lcByte == 0) ? (short) 256 : lcByte;
                }
                rsaPrivateKeyByteSize = modulusLen;
                short keyLength = (short) (rsaPrivateKeyByteSize * 8);
                switch (keyLength) {
                    case (short) 1024:
                        keyLength = KeyBuilder.LENGTH_RSA_1024;
                        break;
                    case (short) 1280:
                        keyLength = KeyBuilder.LENGTH_RSA_1280;
                        break;
                    case (short) 1536:
                        keyLength = KeyBuilder.LENGTH_RSA_1536;
                        break;
                    case (short) 1768:
                        // Non-standard EMV size (221 bytes) - keep raw value
                        break;
                    case (short) 1984:
                        keyLength = KeyBuilder.LENGTH_RSA_1984;
                        break;
                    case (short) 2048:
                        keyLength = KeyBuilder.LENGTH_RSA_2048;
                        break;
                    default:
                        // Return 6A80 (Incorrect data field) for unsupported key size
                        ISOException.throwIt((short) 0x6A80);
                }

                // Use try-catch to detect if card doesn't support requested key size
                try {
                    // Use false for transient (RAM) storage - some cards don't support persistent RSA-1984
                    rsaPrivateKey = (RSAPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PRIVATE, keyLength, false);
                    rsaPrivateKey.clearKey();
                    // Get the actual data offset (may differ for extended APDU)
                    short dataOffset = apdu.getOffsetCdata();
                    rsaPrivateKey.setModulus(buf, dataOffset, rsaPrivateKeyByteSize);
                } catch (CryptoException e) {
                    rsaPrivateKey = null;
                    rsaPrivateKeyByteSize = 0;
                    // Return 6A81 (Function not supported) if key type not available
                    ISOException.throwIt((short) 0x6A81);
                }
                break;
            // ICC RSA KEY PRIVATE EXPONENT
            case 0x0005:
                if (rsaPrivateKey == null) {
                    // Modulus must be set first (case 0x0004)
                    ISOException.throwIt((short) 0x6985); // Conditions not satisfied
                }
                try {
                    // Get actual data length (works for both short and extended APDUs)
                    short expLen = apdu.getIncomingLength();
                    if (expLen == 0) {
                        short lcByte = (short) (buf[ISO7816.OFFSET_LC] & 0x00FF);
                        expLen = (lcByte == 0) ? (short) 256 : lcByte;
                    }
                    short dataOffset = apdu.getOffsetCdata();
                    rsaPrivateKey.setExponent(buf, dataOffset, expLen);
                } catch (CryptoException e) {
                    rsaPrivateKey = null;
                    rsaPrivateKeyByteSize = 0;
                    ISOException.throwIt((short) 0x6A81); // Function not supported
                }
                break;
            // FALLBACK READ RECORD
            case 0x0006:
                short dataLength = (short) (buf[ISO7816.OFFSET_LC] & 0x00FF);
                defaultReadRecord = null;
                defaultReadRecord = new byte[dataLength];
                Util.arrayCopy(buf, (short) ISO7816.OFFSET_CDATA, defaultReadRecord, (short) 0, dataLength);
                break;
            // DIAGNOSTIC: Get RSA key state
            case 0x0007:
                // Return: [key_present, key_size_hi, key_size_lo, key_initialized]
                buf[0] = (rsaPrivateKey != null) ? (byte) 0x01 : (byte) 0x00;
                buf[1] = (byte) ((rsaPrivateKeyByteSize >> 8) & 0xFF);
                buf[2] = (byte) (rsaPrivateKeyByteSize & 0xFF);
                buf[3] = (rsaPrivateKey != null && rsaPrivateKey.isInitialized()) ? (byte) 0x01 : (byte) 0x00;
                apdu.setOutgoingAndSend((short) 0, (short) 4);
                return;
            // DIAGNOSTIC: Get Transaction Data Hash input and output
            case 0x0008:
                // Return: [hash_input_len_hi, hash_input_len_lo, hash_output(32), hash_input(up to 200)]
                buf[0] = (byte) ((debugHashInputLength >> 8) & 0xFF);
                buf[1] = (byte) (debugHashInputLength & 0xFF);
                Util.arrayCopy(debugHashOutput, (short) 0, buf, (short) 2, (short) 32);
                short copyLen = (debugHashInputLength > (short) 200) ? (short) 200 : debugHashInputLength;
                Util.arrayCopy(debugHashInput, (short) 0, buf, (short) 34, copyLen);
                apdu.setOutgoingAndSend((short) 0, (short) (34 + copyLen));
                return;
            // DIAGNOSTIC: Get CDA decision variables
            case 0x0009:
                // Return: [canPerformCda, cdaSupportedInAip, aipTagFound, aipByte1, aipLen]
                boolean diagCanCda = (rsaPrivateKey != null && rsaPrivateKeyByteSize > 0);
                boolean diagCdaInAip = false;
                boolean diagAipFound = false;
                byte diagAipByte1 = 0;
                byte diagAipLen = 0;
                EmvTag diagAipTag = EmvTag.findTag((short) 0x0082);
                if (diagAipTag != null) {
                    diagAipFound = true;
                    diagAipLen = (byte) diagAipTag.getLength();
                    if (diagAipLen >= 1) {
                        diagAipByte1 = diagAipTag.getData()[0];
                        diagCdaInAip = ((diagAipByte1 & (byte) 0x01) != 0);
                    }
                }
                buf[0] = diagCanCda ? (byte) 0x01 : (byte) 0x00;
                buf[1] = diagCdaInAip ? (byte) 0x01 : (byte) 0x00;
                buf[2] = diagAipFound ? (byte) 0x01 : (byte) 0x00;
                buf[3] = diagAipByte1;
                buf[4] = diagAipLen;
                apdu.setOutgoingAndSend((short) 0, (short) 5);
                return;
            // DIAGNOSTIC: Test 61xx - just throws 0x6128 directly
            case 0x000A:
                // Store some dummy data for GET RESPONSE
                tmpBuffer[0] = (byte) 0xAA;
                tmpBuffer[1] = (byte) 0xBB;
                tmpBuffer[2] = (byte) 0xCC;
                pendingResponseOffset = (short) 0;
                pendingResponseLength = (short) 3;
                // Throw 61xx directly - should return SW=6103 if JCRE works correctly
                ISOException.throwIt((short) 0x6103);
                return; // Never reached but prevents fall-through warning
            // DIAGNOSTIC: Get SDAD hash input and output
            case 0x000B:
                // Return: [input_len_hi, input_len_lo, hash_output(32), hash_input(up to 98)]
                buf[0] = (byte) ((debugSdadHashInputLength >> 8) & 0xFF);
                buf[1] = (byte) (debugSdadHashInputLength & 0xFF);
                Util.arrayCopy(debugSdadHashOutput, (short) 0, buf, (short) 2, (short) 32);
                short sdadCopyLen = (debugSdadHashInputLength > (short) 98) ? (short) 98 : debugSdadHashInputLength;
                Util.arrayCopy(debugSdadHashInput, (short) 0, buf, (short) 34, sdadCopyLen);
                apdu.setOutgoingAndSend((short) 0, (short) (34 + sdadCopyLen));
                return;
            default:
                ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }

        ISOException.throwIt(ISO7816.SW_NO_ERROR);
    }

    protected PaymentApplication(byte[] buffer, short offset, byte length) {
        super();

        pinCode = new byte[] { (byte) 0x00, (byte) 0x00 };

        challenge = JCSystem.makeTransientByteArray((short) 8, JCSystem.CLEAR_ON_DESELECT);

        tag9f4cDynamicNumber = JCSystem.makeTransientByteArray((short) 3, JCSystem.CLEAR_ON_DESELECT);

        // Storage for CDOL1 data - transient so it's cleared on deselect
        storedCdol1Data = JCSystem.makeTransientByteArray((short) 64, JCSystem.CLEAR_ON_DESELECT);
        storedCdol1Length = 0;

        // Storage for PDOL data - transient so it's cleared on deselect
        storedPdolData = JCSystem.makeTransientByteArray((short) 64, JCSystem.CLEAR_ON_DESELECT);
        storedPdolLength = 0;

        // DEBUG: Storage for hash input (256 bytes should be enough) and output (32 bytes for SHA-256)
        debugHashInput = JCSystem.makeTransientByteArray((short) 256, JCSystem.CLEAR_ON_DESELECT);
        debugHashInputLength = 0;
        debugHashOutput = JCSystem.makeTransientByteArray((short) 32, JCSystem.CLEAR_ON_DESELECT);

        // DEBUG: Storage for SDAD hash input (100 bytes: 94 bytes SDAD data + 4 bytes UN + margin) and output
        // Use PERSISTENT storage so data survives app deselect/reselect for debugging
        debugSdadHashInput = new byte[100];
        debugSdadHashInputLength = 0;
        debugSdadHashOutput = new byte[32];

        // Chunked settings buffer for RSA key on T=0 cards (persistent)
        settingsChunkBuffer = new byte[512];

        rsaCipher = Cipher.getInstance(Cipher.ALG_RSA_NOPAD, false);

        shaMessageDigest = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);
    }

    private void processSelect(APDU apdu, byte[] buf) {
        // Reset stored data for new transaction
        storedCdol1Length = 0;
        storedPdolLength = 0;

        // Don't clear logs here - it prevents reading logs via opensc-tool
        // The rolling log limit (maxCount=10) handles old logs

        // Check if PAN (tag A5) exists in the ICC
        if (EmvTag.findTag((short) 0x5A) != null) {
            arrayRandomFill(challenge);

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

    private void incrementApplicationTransactionCounter() {
        short applicationTransactionCounterTagId = (short) 0x9F36;
        EmvTag atcTag = EmvTag.findTag(applicationTransactionCounterTagId);
        if (atcTag != null) {
            short applicationTransactionCounter = Util.getShort(atcTag.getData(), (short) 0);
            applicationTransactionCounter += (short) 1;

            Util.setShort(tmpBuffer, (short) 0, applicationTransactionCounter);
            atcTag.setData(tmpBuffer, (short) 0, (byte) 2);
        }
    }

    private void processGenerateAc(APDU apdu, byte[] buf) {
        byte referenceControlParameter = buf[ISO7816.OFFSET_P1];
        byte requestCryptogramType = (byte) ((short) (referenceControlParameter >> ((byte) 6)) << ((byte) 6));
        // Check if CDA is requested (P1 bit 4 = 0x10)
        boolean cdaRequested = ((referenceControlParameter & (byte) 0x10) != 0);

        byte responseCryptogramType = (byte) 0x40;
        switch (requestCryptogramType) {
            case (byte) 0x40: // TC
                responseCryptogramType = requestCryptogramType;
                break;
            case (byte) 0x80: // ARQC
                responseCryptogramType = requestCryptogramType;
                break;
            case (byte) 0x00: // AAC
                responseCryptogramType = (byte) 0x00;
                break;
            default:
                EmvApplet.logAndThrow(ISO7816.SW_INCORRECT_P1P2);
                break;
        }

        // Check if CDA can be performed
        boolean canPerformCda = (rsaPrivateKey != null && rsaPrivateKeyByteSize > 0);

        // Check if CDA is supported in AIP (byte 1 bit 0 = 0x01)
        // Some kernels expect CDA based on AIP, not explicit P1 request
        boolean cdaSupportedInAip = false;
        EmvTag aipTag = EmvTag.findTag((short) 0x0082);
        if (aipTag != null && aipTag.getLength() >= 1) {
            byte aipByte1 = aipTag.getData()[0];
            cdaSupportedInAip = ((aipByte1 & (byte) 0x01) != 0);
        }

        // Perform CDA only if explicitly requested AND we can do it
        boolean shouldPerformCda = cdaRequested && canPerformCda;

        // Set Cryptogram Information Data (9F27)
        // CID bits 7-6 indicate cryptogram type: 00=AAC, 01=TC, 10=ARQC
        // CDA success is indicated by valid SDAD in response, not by CID bits
        byte cid = responseCryptogramType;
        tmpBuffer[0] = cid;
        EmvTag.setTag((short) 0x9F27, tmpBuffer, (short) 0, (byte) 1);

        incrementApplicationTransactionCounter();

        // Generate Application Cryptogram (9F26)
        short cdolLen = (short) (buf[ISO7816.OFFSET_LC] & 0x00FF);
        generateApplicationCryptogram(buf, ISO7816.OFFSET_CDATA, cdolLen);

        // If CDA should be performed (requested OR AIP advertises it) and we have ICC private key
        if (shouldPerformCda && canPerformCda) {
            generateSdad(buf, cid, cdolLen);
            // CDA performed - use full template with 9F4B
            sendResponseTemplate(apdu, buf, responseTemplateGenerateAc);
        } else if (cdaRequested && !canPerformCda) {
            // CDA explicitly requested but key not available
            // Return 6985 (Conditions of use not satisfied) for CDA failure
            EmvApplet.logAndThrow((short) 0x6985);
        } else {
            // CDA not applicable - build response without 9F4B
            // Response contains: 9F27 (CID), 9F36 (ATC), 9F26 (AC), 9F10 (IAD)
            sendGenerateAcResponseNoCda(apdu, buf);
        }
    }

    /**
     * Send GENERATE AC response without CDA (no 9F4B).
     * Response contains: 9F27 (CID), 9F36 (ATC), 9F26 (AC), 9F10 (IAD) in tag 77 template.
     */
    private void sendGenerateAcResponseNoCda(APDU apdu, byte[] buf) {
        short offset = (short) 0;

        // Build response content in tmpBuffer
        // 9F27 (CID) - 1 byte
        EmvTag cidTag = EmvTag.findTag((short) 0x9F27);
        if (cidTag != null) {
            offset = cidTag.copyToArray(tmpBuffer, offset);
        }

        // 9F36 (ATC) - 2 bytes
        EmvTag atcTag = EmvTag.findTag((short) 0x9F36);
        if (atcTag != null) {
            offset = atcTag.copyToArray(tmpBuffer, offset);
        }

        // 9F26 (AC) - 8 bytes
        EmvTag acTag = EmvTag.findTag((short) 0x9F26);
        if (acTag != null) {
            offset = acTag.copyToArray(tmpBuffer, offset);
        }

        // 9F10 (IAD) - variable length
        EmvTag iadTag = EmvTag.findTag((short) 0x9F10);
        if (iadTag != null) {
            offset = iadTag.copyToArray(tmpBuffer, offset);
        }

        // Build tag 77 template wrapper
        short contentLen = offset;
        short responseOffset = (short) 0;

        // Response goes in buf starting at OFFSET_CDATA
        buf[ISO7816.OFFSET_CDATA] = (byte) 0x77;
        responseOffset = (short) (ISO7816.OFFSET_CDATA + 1);

        // Length encoding
        if (contentLen > (short) 127) {
            buf[responseOffset++] = (byte) 0x81;
            buf[responseOffset++] = (byte) (contentLen & 0xFF);
        } else {
            buf[responseOffset++] = (byte) contentLen;
        }

        // Copy content
        Util.arrayCopy(tmpBuffer, (short) 0, buf, responseOffset, contentLen);
        responseOffset += contentLen;

        short totalLen = (short) (responseOffset - ISO7816.OFFSET_CDATA);
        ApduLog.addLogEntry(buf, ISO7816.OFFSET_CDATA, (byte) (totalLen & 0xFF));
        apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, totalLen);
    }

    /**
     * Generate Application Cryptogram (9F26).
     * For simulation, we create a pseudo-cryptogram based on transaction data.
     * Real implementation would use 3DES MAC with derived session key.
     */
    private void generateApplicationCryptogram(byte[] buf, short cdolOffset, short cdolLen) {
        shaMessageDigest.reset();

        // Include ATC in hash
        EmvTag atcTag = EmvTag.findTag((short) 0x9F36);
        if (atcTag != null) {
            shaMessageDigest.update(atcTag.getData(), (short) 0, (short) 2);
        }

        // Include PAN in hash for uniqueness
        EmvTag panTag = EmvTag.findTag((short) 0x5A);
        if (panTag != null) {
            shaMessageDigest.update(panTag.getData(), (short) 0, (short) (panTag.getLength() & 0xFF));
        }

        // Include CDOL data in hash
        if (cdolLen > 0) {
            shaMessageDigest.update(buf, cdolOffset, cdolLen);
        }

        // Finalize hash - result goes to tmpBuffer temporarily
        shaMessageDigest.doFinal(tmpBuffer, (short) 0, (short) 0, tmpBuffer, (short) 200);

        // Take first 8 bytes as Application Cryptogram
        EmvTag.setTag((short) 0x9F26, tmpBuffer, (short) 200, (byte) 8);
    }

    /**
     * Generate Signed Dynamic Application Data (SDAD) for CDA.
     * Per EMV Book 2, Table 16.
     */
    private void generateSdad(byte[] buf, byte cryptogramInfoData, short cdolLen) {
        short signedDataSize = rsaPrivateKeyByteSize;

        // Fill with padding (0xBB)
        Util.arrayFillNonAtomic(tmpBuffer, (short) 0, signedDataSize, (byte) 0xBB);

        // Build SDAD structure per EMV Book 2 Table 16
        tmpBuffer[0] = (byte) 0x6A;  // Header
        tmpBuffer[1] = (byte) 0x05;  // Signed Data Format for CDA
        tmpBuffer[2] = (byte) 0x02;  // Hash Algorithm Indicator (SHA-256)

        // ICC Dynamic Data for CDA Format 05:
        // - ICC Dynamic Number Length (1 byte)
        // - ICC Dynamic Number (LDD bytes, we use 8)
        // - Cryptogram Information Data (1 byte)
        // - Application Cryptogram (8 bytes)
        // - Transaction Data Hash Code (32 bytes) - hash over CDOL data
        // Total: 1 + 8 + 1 + 8 + 32 = 50 bytes

        byte iccDynNumLen = (byte) 8;
        byte iccDynamicDataLength = (byte) (1 + iccDynNumLen + 1 + 8 + 32); // len + DN + CID + AC + TDH
        tmpBuffer[3] = iccDynamicDataLength;

        short offset = 4;

        // ICC Dynamic Number Length
        tmpBuffer[offset++] = iccDynNumLen;

        // ICC Dynamic Number (8 bytes) - generate fresh random value
        randomData.generateData(tmpBuffer, offset, (short) iccDynNumLen);
        if (!useRandom) {
            // For testing, use predictable value
            Util.arrayFillNonAtomic(tmpBuffer, offset, (short) iccDynNumLen, (byte) 0xAB);
        }
        // Store ICC Dynamic Number in tag 9F4C for reference
        EmvTag.setTag((short) 0x9F4C, tmpBuffer, offset, iccDynNumLen);
        offset += iccDynNumLen;

        // Cryptogram Information Data (1 byte)
        tmpBuffer[offset++] = cryptogramInfoData;

        // Application Cryptogram (8 bytes) - get from tag 9F26
        EmvTag acTag = EmvTag.findTag((short) 0x9F26);
        if (acTag != null) {
            Util.arrayCopy(acTag.getData(), (short) 0, tmpBuffer, offset, (short) 8);
        }
        offset += 8;

        // Transaction Data Hash Code (20 bytes)
        // Per EMV Book 2, this hash is over:
        // PDOL data + CDOL1 data + [CDOL2 data] + separator byte + TLV of response tags
        shaMessageDigest.reset();

        // DEBUG: Clear and prepare to record hash input
        debugHashInputLength = 0;

        // 1. Include PDOL data first (stored from GPO)
        // Use the defined PDOL length (33 bytes for this card config), not the received length
        // PDOL: 9F66(4)+9F02(6)+9F03(6)+9F1A(2)+95(5)+5F2A(2)+9A(3)+9C(1)+9F37(4) = 33
        short pdolDefinedLength = 33;
        if (storedPdolLength > 0) {
            short pdolHashLen = (storedPdolLength < pdolDefinedLength) ? storedPdolLength : pdolDefinedLength;
            shaMessageDigest.update(storedPdolData, (short) 0, pdolHashLen);
            // DEBUG: Record PDOL data
            if ((short)(debugHashInputLength + pdolHashLen) <= (short) 256) {
                Util.arrayCopy(storedPdolData, (short) 0, debugHashInput, debugHashInputLength, pdolHashLen);
                debugHashInputLength = (short)(debugHashInputLength + pdolHashLen);
            }
        }

        // Detect if this is CDOL2 (second GENERATE AC) by length = 60 bytes
        boolean isSecondGenerateAc = (cdolLen == (short) 60);
        short cdol1ExpectedLen = 58;

        if (isSecondGenerateAc) {
            // Second GENERATE AC: Include stored CDOL1 first, then CDOL2
            // 2a. Include stored CDOL1 data (padded to 58 bytes)
            if (storedCdol1Length > 0) {
                shaMessageDigest.update(storedCdol1Data, (short) 0, storedCdol1Length);
                // DEBUG
                if ((short)(debugHashInputLength + storedCdol1Length) <= (short) 256) {
                    Util.arrayCopy(storedCdol1Data, (short) 0, debugHashInput, debugHashInputLength, storedCdol1Length);
                    debugHashInputLength = (short)(debugHashInputLength + storedCdol1Length);
                }
            }
            // Pad CDOL1 if needed
            if (storedCdol1Length < cdol1ExpectedLen) {
                short padLen = (short)(cdol1ExpectedLen - storedCdol1Length);
                Util.arrayFillNonAtomic(tmpBuffer, (short) 400, padLen, (byte) 0x00);
                shaMessageDigest.update(tmpBuffer, (short) 400, padLen);
                // DEBUG
                if ((short)(debugHashInputLength + padLen) <= (short) 256) {
                    Util.arrayCopy(tmpBuffer, (short) 400, debugHashInput, debugHashInputLength, padLen);
                    debugHashInputLength = (short)(debugHashInputLength + padLen);
                }
            }
            // 2b. Include current CDOL2 data (60 bytes, no padding needed)
            if (cdolLen > 0) {
                shaMessageDigest.update(buf, ISO7816.OFFSET_CDATA, cdolLen);
                // DEBUG
                if ((short)(debugHashInputLength + cdolLen) <= (short) 256) {
                    Util.arrayCopy(buf, ISO7816.OFFSET_CDATA, debugHashInput, debugHashInputLength, cdolLen);
                    debugHashInputLength = (short)(debugHashInputLength + cdolLen);
                }
            }
        } else {
            // First GENERATE AC: Store CDOL1 data for later use
            if (cdolLen > 0 && cdolLen <= (short) 64) {
                Util.arrayCopy(buf, ISO7816.OFFSET_CDATA, storedCdol1Data, (short) 0, cdolLen);
                storedCdol1Length = cdolLen;
            }
            // 2. Include CDOL1 data (capped to expected length, similar to PDOL)
            // Terminal may send more bytes than expected (e.g., 61 vs 58), use min
            if (cdolLen > 0) {
                short cdolHashLen = (cdolLen < cdol1ExpectedLen) ? cdolLen : cdol1ExpectedLen;
                shaMessageDigest.update(buf, ISO7816.OFFSET_CDATA, cdolHashLen);
                // DEBUG
                if ((short)(debugHashInputLength + cdolHashLen) <= (short) 256) {
                    Util.arrayCopy(buf, ISO7816.OFFSET_CDATA, debugHashInput, debugHashInputLength, cdolHashLen);
                    debugHashInputLength = (short)(debugHashInputLength + cdolHashLen);
                }
            }
            // Pad with zeros if CDOL data is less than expected
            if (cdolLen < cdol1ExpectedLen) {
                short padLen = (short)(cdol1ExpectedLen - cdolLen);
                Util.arrayFillNonAtomic(tmpBuffer, (short) 400, padLen, (byte) 0x00);
                shaMessageDigest.update(tmpBuffer, (short) 400, padLen);
                // DEBUG
                if ((short)(debugHashInputLength + padLen) <= (short) 256) {
                    Util.arrayCopy(tmpBuffer, (short) 400, debugHashInput, debugHashInputLength, padLen);
                    debugHashInputLength = (short)(debugHashInputLength + padLen);
                }
            }
        }

        // 3. Include low byte of response template (77) length BEFORE TLV tags
        // The terminal parses tag 77 with response_data[3..] which includes this byte
        // when length >= 256 (encoded as 77 82 XX YY, [3..] gives YY followed by TLV data)
        // Calculate total response content length:
        // 9F27(4) + 9F36(5) + 9F26(11) + 9F10(3+iadLen) + 9F4B(2+lengthBytes+rsaKeySize)
        EmvTag iadTagForLen = EmvTag.findTag((short) 0x9F10);
        short iadLenForCalc = (iadTagForLen != null) ? (short) (iadTagForLen.getLength() & 0xFF) : 0;
        short sdadLengthBytes = (rsaPrivateKeyByteSize >= (short) 256) ? (short) 3 : (short) 2;
        short responseContentLen = (short) (4 + 5 + 11 + 3 + iadLenForCalc + 2 + sdadLengthBytes + rsaPrivateKeyByteSize);
        // Only include low byte if length requires 82 XX YY encoding (>= 256)
        if (responseContentLen >= (short) 256) {
            tmpBuffer[400] = (byte) (responseContentLen & 0xFF);
            shaMessageDigest.update(tmpBuffer, (short) 400, (short) 1);
            // DEBUG: Record length byte
            if (debugHashInputLength < (short) 256) {
                debugHashInput[debugHashInputLength] = (byte) (responseContentLen & 0xFF);
                debugHashInputLength = (short)(debugHashInputLength + 1);
            }
        }

        // 4. Include response TLV tags (EMV Book 2 Section 6.5.1.4)
        // 9F27 (CID) - 1 byte value
        tmpBuffer[400] = (byte) 0x9F;
        tmpBuffer[401] = (byte) 0x27;
        tmpBuffer[402] = (byte) 0x01;
        tmpBuffer[403] = cryptogramInfoData;
        shaMessageDigest.update(tmpBuffer, (short) 400, (short) 4);
        // DEBUG: Record 9F27
        if ((short)(debugHashInputLength + 4) <= (short) 256) {
            Util.arrayCopy(tmpBuffer, (short) 400, debugHashInput, debugHashInputLength, (short) 4);
            debugHashInputLength = (short)(debugHashInputLength + 4);
        }

        // 9F36 (ATC) - 2 byte value
        EmvTag atcTag = EmvTag.findTag((short) 0x9F36);
        tmpBuffer[400] = (byte) 0x9F;
        tmpBuffer[401] = (byte) 0x36;
        tmpBuffer[402] = (byte) 0x02;
        if (atcTag != null) {
            Util.arrayCopy(atcTag.getData(), (short) 0, tmpBuffer, (short) 403, (short) 2);
        }
        shaMessageDigest.update(tmpBuffer, (short) 400, (short) 5);
        // DEBUG: Record 9F36
        if ((short)(debugHashInputLength + 5) <= (short) 256) {
            Util.arrayCopy(tmpBuffer, (short) 400, debugHashInput, debugHashInputLength, (short) 5);
            debugHashInputLength = (short)(debugHashInputLength + 5);
        }

        // 9F26 (AC) - 8 byte value
        tmpBuffer[400] = (byte) 0x9F;
        tmpBuffer[401] = (byte) 0x26;
        tmpBuffer[402] = (byte) 0x08;
        if (acTag != null) {
            Util.arrayCopy(acTag.getData(), (short) 0, tmpBuffer, (short) 403, (short) 8);
        }
        shaMessageDigest.update(tmpBuffer, (short) 400, (short) 11);
        // DEBUG: Record 9F26
        if ((short)(debugHashInputLength + 11) <= (short) 256) {
            Util.arrayCopy(tmpBuffer, (short) 400, debugHashInput, debugHashInputLength, (short) 11);
            debugHashInputLength = (short)(debugHashInputLength + 11);
        }

        // 9F10 (IAD) - 7 byte value
        EmvTag iadTag = EmvTag.findTag((short) 0x9F10);
        tmpBuffer[400] = (byte) 0x9F;
        tmpBuffer[401] = (byte) 0x10;
        short iadLen = 0;
        if (iadTag != null) {
            iadLen = (short) (iadTag.getLength() & 0xFF);
            tmpBuffer[402] = (byte) iadLen;
            Util.arrayCopy(iadTag.getData(), (short) 0, tmpBuffer, (short) 403, iadLen);
            shaMessageDigest.update(tmpBuffer, (short) 400, (short) (3 + iadLen));
            // DEBUG: Record 9F10
            if ((short)(debugHashInputLength + 3 + iadLen) <= (short) 256) {
                Util.arrayCopy(tmpBuffer, (short) 400, debugHashInput, debugHashInputLength, (short) (3 + iadLen));
                debugHashInputLength = (short)(debugHashInputLength + 3 + iadLen);
            }
        }

        // 5. Include 9F4B tag bytes (but not length or value)
        // The terminal includes the 9F4B tag because it subtracts only 6 hex chars (3 bytes)
        // for what it thinks is the header, but the actual header is 5 bytes (9F4B + 82 01 00)
        tmpBuffer[400] = (byte) 0x9F;
        tmpBuffer[401] = (byte) 0x4B;
        shaMessageDigest.update(tmpBuffer, (short) 400, (short) 2);
        // DEBUG: Record 9F4B tag
        if ((short)(debugHashInputLength + 2) <= (short) 256) {
            Util.arrayCopy(tmpBuffer, (short) 400, debugHashInput, debugHashInputLength, (short) 2);
            debugHashInputLength = (short)(debugHashInputLength + 2);
        }

        shaMessageDigest.doFinal(tmpBuffer, (short) 0, (short) 0, tmpBuffer, offset);
        // DEBUG: Store the Transaction Data Hash output
        Util.arrayCopy(tmpBuffer, offset, debugHashOutput, (short) 0, (short) 32);
        offset += 32;

        // Trailer at end
        tmpBuffer[(short) (signedDataSize - 1)] = (byte) 0xBC;

        // Compute SDAD hash (SHA-256)
        // Hash input: bytes 1 through (signedDataSize - 34) = format through padding
        //             + Unpredictable Number (9F37)
        short checksumStartIndex = (short) (signedDataSize - 33);

        // DEBUG: Clear and prepare to record SDAD hash input
        debugSdadHashInputLength = 0;

        shaMessageDigest.reset();
        // Hash: Format through Pad Pattern (bytes 1 to checksumStartIndex-1)
        short sdadDataLen = (short) (checksumStartIndex - 1);
        shaMessageDigest.update(tmpBuffer, (short) 1, sdadDataLen);

        // DEBUG: Record SDAD data portion (first 94 bytes or less)
        short copyLen = (sdadDataLen > (short) 94) ? (short) 94 : sdadDataLen;
        Util.arrayCopy(tmpBuffer, (short) 1, debugSdadHashInput, (short) 0, copyLen);
        debugSdadHashInputLength = copyLen;

        // Include Unpredictable Number from CDOL data
        // CDOL1: 9F02(6)+9F03(6)+9F1A(2)+95(5)+5F2A(2)+9A(3)+9C(1)+9F37(4)... UN at offset 25
        // CDOL2: 8A(2)+9F02(6)+9F03(6)+9F1A(2)+95(5)+5F2A(2)+9A(3)+9C(1)+9F37(4)... UN at offset 27
        // Determine UN offset based on CDOL length: CDOL2 (60 bytes) vs CDOL1 (43-58 bytes)
        short unOffset = (cdolLen == (short) 60) ? (short) 27 : (short) 25;
        if (cdolLen >= (short) (unOffset + 4)) {
            shaMessageDigest.update(buf, (short) (ISO7816.OFFSET_CDATA + unOffset), (short) 4);
            // DEBUG: Record UN
            if ((short)(debugSdadHashInputLength + 4) <= (short) 100) {
                Util.arrayCopy(buf, (short) (ISO7816.OFFSET_CDATA + unOffset), debugSdadHashInput, debugSdadHashInputLength, (short) 4);
                debugSdadHashInputLength = (short)(debugSdadHashInputLength + 4);
            }
        }

        shaMessageDigest.doFinal(tmpBuffer, (short) 0, (short) 0, tmpBuffer, checksumStartIndex);

        // DEBUG: Store the SDAD hash output
        Util.arrayCopy(tmpBuffer, checksumStartIndex, debugSdadHashOutput, (short) 0, (short) 32);

        // RSA sign (encrypt with private key)
        // Use tmpBuffer[256..] for output to avoid overwriting APDU buffer header
        rsaCipher.init(rsaPrivateKey, Cipher.MODE_DECRYPT);
        rsaCipher.doFinal(tmpBuffer, (short) 0, signedDataSize, tmpBuffer, (short) 256);

        // Store SDAD in tag 9F4B
        EmvTag.setTag((short) 0x9F4B, tmpBuffer, (short) 256, signedDataSize);
    }

    private void externalAuthenticate(APDU apdu, byte[] buf) {
        if (Util.getShort(buf, ISO7816.OFFSET_P1) != (short) 0x00) {
            EmvApplet.logAndThrow(ISO7816.SW_INCORRECT_P1P2);
        }

        byte length = buf[ISO7816.OFFSET_LC];
        if (length < (byte) 8 || length > (byte) 16) {
            EmvApplet.logAndThrow(ISO7816.SW_DATA_INVALID);
        }

        // 6300 = Issuer authentication failed

        EmvApplet.logAndThrow(ISO7816.SW_NO_ERROR);
    }

    /**
     * TEST: Send 291 bytes of zeroes to isolate T=0 chaining issue.
     * Sends first 256 bytes, stores remaining 35 in chunkBuffer, throws 6123.
     */
    private void testSend291Zeroes(APDU apdu, byte[] buf) {
        // Fill tmpBuffer with test pattern (0xAA for visibility)
        short totalLen = (short) 291;
        for (short i = 0; i < totalLen; i++) {
            tmpBuffer[i] = (byte) 0xAA;
        }

        // First chunk: 256 bytes
        short firstChunk = (short) 256;
        short remaining = (short) (totalLen - firstChunk);  // 35 bytes

        // Copy remaining bytes to chunkBuffer for GET RESPONSE
        Util.arrayCopy(tmpBuffer, firstChunk, chunkBuffer, (short) 0, remaining);
        pendingResponseLength = remaining;

        // Send first 256 bytes
        apdu.setOutgoing();
        apdu.setOutgoingLength(firstChunk);
        apdu.sendBytesLong(tmpBuffer, (short) 0, firstChunk);

        // Throw 61xx to signal more data (35 = 0x23)
        ISOException.throwIt((short) (0x6100 | remaining));
    }

    private void processGetResponse(APDU apdu, byte[] buf) {
        // Check if there's pending response data
        if (pendingResponseLength <= 0) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }

        // Use setOutgoing to get Le and set up outgoing mode
        short le = apdu.setOutgoing();
        if (le == 0) {
            le = 256;
        }

        // Calculate how much to send (min of Le and remaining)
        short send = (le < pendingResponseLength) ? le : pendingResponseLength;

        // Set the outgoing length and send from chunkBuffer
        apdu.setOutgoingLength(send);
        apdu.sendBytesLong(chunkBuffer, (short) 0, send);

        // Clear pending state (all done)
        pendingResponseOffset = 0;
        pendingResponseLength = 0;
    }

    private void processGetData(APDU apdu, byte[] buf) {
        // Standard EMV GET DATA: P1P2 = tag ID, no command data required
        short tagId = Util.getShort(buf, ISO7816.OFFSET_P1);
        sendResponse(apdu, buf, tagId);
    }

    private void listStoredTags(APDU apdu, byte[] buf) {
        // Debug command: returns list of all stored tag IDs (2 bytes each)
        short offset = (short) 0;
        for (EmvTag iter = EmvTag.getHead(); iter != null; iter = iter.getNext()) {
            byte[] tagBytes = iter.getTag();
            tmpBuffer[offset] = tagBytes[0];
            tmpBuffer[(short)(offset + 1)] = tagBytes[1];
            offset += (short) 2;
            if (offset >= (short) 250) break; // Prevent buffer overflow
        }
        Util.arrayCopy(tmpBuffer, (short) 0, buf, ISO7816.OFFSET_CDATA, offset);
        apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, offset);
    }

    private void processGetProcessingOptions(APDU apdu, byte[] buf) {
        if (Util.getShort(buf, ISO7816.OFFSET_P1) != (short) 0x00) {
            EmvApplet.logAndThrow(ISO7816.SW_INCORRECT_P1P2);
        }

        short lc = (short) (buf[ISO7816.OFFSET_LC] & 0x00FF);

        // Must have at least tag 83 + length byte
        if (lc < (short) 2) {
            EmvApplet.logAndThrow(ISO7816.SW_DATA_INVALID);
        }

        // Command template must be tag 83
        if (buf[ISO7816.OFFSET_CDATA] != (byte) 0x83) {
            EmvApplet.logAndThrow(ISO7816.SW_DATA_INVALID);
        }

        // Get PDOL data length
        short pdolLen = (short) (buf[ISO7816.OFFSET_CDATA + 1] & 0x00FF);

        // Validate LC matches: tag(1) + len(1) + pdolLen
        if (lc != (short) (2 + pdolLen)) {
            EmvApplet.logAndThrow(ISO7816.SW_WRONG_LENGTH);
        }

        // PDOL data is at ISO7816.OFFSET_CDATA + 2, length pdolLen
        // Store PDOL data for CDA Transaction Data Hash calculation
        if (pdolLen > 0 && pdolLen <= (short) 64) {
            Util.arrayCopy(buf, (short) (ISO7816.OFFSET_CDATA + 2), storedPdolData, (short) 0, pdolLen);
            storedPdolLength = pdolLen;
        } else {
            storedPdolLength = 0;
        }

        sendResponseTemplate(apdu, buf, responseTemplateGetProcessingOptions);
    }

    private void processDynamicDataAuthentication(APDU apdu, byte[] buf) {
        if (Util.getShort(buf, ISO7816.OFFSET_P1) != (short) 0x0000) {
            EmvApplet.logAndThrow(ISO7816.SW_INCORRECT_P1P2);
        }

        short signedDataSize = rsaPrivateKeyByteSize;

        // Build data to-be-encrypted

        Util.arrayFillNonAtomic(tmpBuffer, (short) 0, signedDataSize, (byte) 0xBB);

        tmpBuffer[0] = (byte) 0x6A;
        tmpBuffer[1] = (byte) 0x05;
        tmpBuffer[2] = (byte) 0x02; // SHA-256 hash algo
        tmpBuffer[(short) (signedDataSize - 1)] = (byte) 0xBC;

        tmpBuffer[3] = (byte) tag9f4cDynamicNumber.length;
        arrayRandomFill(tag9f4cDynamicNumber);

        Util.arrayCopy(tag9f4cDynamicNumber, (short) 0, tmpBuffer, (short) 4, (short) tmpBuffer[3]);

        short checksumStartIndex = (short) (signedDataSize - 33);
        shaMessageDigest.reset();
        shaMessageDigest.update(tmpBuffer, (short) 1, (short) (checksumStartIndex - 1));        
        shaMessageDigest.doFinal(buf, (short) ISO7816.OFFSET_CDATA, (short) (buf[ISO7816.OFFSET_LC] & 0x00FF), tmpBuffer, checksumStartIndex);

        // Build Template
        // Use tmpBuffer[256..] for output to avoid overwriting APDU buffer header
        rsaCipher.init(rsaPrivateKey, Cipher.MODE_DECRYPT);
        rsaCipher.doFinal(tmpBuffer, (short) 0, signedDataSize, tmpBuffer, (short) 256);

        EmvTag.setTag((short) 0x9F4B, tmpBuffer, (short) 256, signedDataSize);

        sendResponseTemplate(apdu, buf, responseTemplateDda);
    }
    
    void comparePin(byte[] pinData, short offset) {
        // Cheapo pin compare for four(4) number pin

        if (pinCode.length != 2) {
            EmvApplet.logAndThrow(ISO7816.SW_DATA_INVALID);
        }

        short actualPin = Util.getShort(pinCode, (short) 0);
        short givenPin = Util.getShort(pinData, offset);
        short givenPinEnd = Util.getShort(pinData, (short) (offset + pinCode.length));

        final short swVerifyFail = (short) 0x63C3; // C3 = 3 tries left

        if (givenPinEnd != (short) 0xFFFF) {
            EmvApplet.logAndThrow(swVerifyFail);
        }

        if (actualPin != givenPin) {
            EmvApplet.logAndThrow(swVerifyFail);
        }
    }

    private void processVerifyPin(APDU apdu, byte[] buf) {
        short p1p2 = Util.getShort(buf, ISO7816.OFFSET_P1);
        if (p1p2 == (short) 0x0080) {
            if (buf[ISO7816.OFFSET_LC] != (byte) 0x08) {
                EmvApplet.logAndThrow(ISO7816.SW_DATA_INVALID);
            }

            comparePin(buf, (short) (ISO7816.OFFSET_CDATA + 1));
        } else if (p1p2 == (short) 0x0088) {
            short length = (short) (buf[ISO7816.OFFSET_LC] & 0x00FF);
            if ((byte) length != (byte) 0x80) {
                EmvApplet.logAndThrow(ISO7816.SW_DATA_INVALID);
            }

            rsaCipher.init(rsaPrivateKey, Cipher.MODE_DECRYPT);
            rsaCipher.doFinal(buf, ISO7816.OFFSET_CDATA, length, tmpBuffer, (short) 0);

            if (tmpBuffer[0] != (byte) 0x7F) {
                EmvApplet.logAndThrow(ISO7816.SW_DATA_INVALID);
            }

            if (Util.arrayCompare(challenge, (short) 0, tmpBuffer, (short) 9, (short) challenge.length) != (byte) 0x00) {
                EmvApplet.logAndThrow(ISO7816.SW_DATA_INVALID);
            }

            comparePin(tmpBuffer, (short) 2);
        } else {
            EmvApplet.logAndThrow(ISO7816.SW_INCORRECT_P1P2);
        }

        EmvApplet.logAndThrow(ISO7816.SW_NO_ERROR);
    }

    private void arrayRandomFill(byte[] dst) {
        randomData.generateData(dst, (short) 0, (short) dst.length);
        if (!useRandom) {
            Util.arrayFillNonAtomic(dst, (short) 0, (short) dst.length, (byte) 0xAB);
        }
    }

    private void processGetChallenge(APDU apdu, byte[] buf) {
        if (Util.getShort(buf, ISO7816.OFFSET_P1) != (short) 0x00) {
            EmvApplet.logAndThrow(ISO7816.SW_INCORRECT_P1P2);
        }

        short outputLength = (short) challenge.length;

        if (buf[ISO7816.OFFSET_LC] != (byte) 0x00 && buf[ISO7816.OFFSET_LC] != (byte) outputLength) {
            EmvApplet.logAndThrow(ISO7816.SW_WRONG_LENGTH);
        }

        arrayRandomFill(challenge);

        sendResponse(apdu, buf, challenge, (short) 0, outputLength);
    }

    /**
     * Process PSE application selection and read records.
     */
    public void process(APDU apdu) {
        byte[] buf = apdu.getBuffer();

        // Determine if this command has incoming data by checking LC byte
        // For ISO case 1 (no data, no Le) and case 2 (no data, Le only), LC position contains Le, not Lc
        // For ISO case 3 (data, no Le) and case 4 (data, Le), LC position contains actual Lc
        //
        // Commands that have command data (case 3/4):
        //   SELECT (A4), VERIFY (20), GET PROCESSING OPTIONS (A8), GENERATE AC (AE),
        //   INTERNAL AUTHENTICATE (88), SET_SETTINGS (04), SET_EMV_TAG (01),
        //   SET_EMV_TAG_FUZZ (06), SET_TAG_TEMPLATE (02), SET_READ_RECORD_TEMPLATE (03)
        //
        // Commands that have NO command data (case 1/2):
        //   READ RECORD (B2), GET RESPONSE (C0), GET CHALLENGE (84), GET DATA (CA),
        //   FACTORY_RESET (05), FUZZ_RESET (07), LOG_CONSUME (08), LIST_TAGS (09)

        byte ins = buf[ISO7816.OFFSET_INS];
        short bytesReceived = 0;

        // Only try to receive data for commands that actually have command data
        // This avoids the bug where reading "LC" on a case 2 command gives garbage
        boolean hasCommandData;
        switch (ins) {
            case (byte)0xA4:  // SELECT
            case (byte)0x20:  // VERIFY
            case (byte)0xA8:  // GET PROCESSING OPTIONS
            case (byte)0xAE:  // GENERATE AC
            case (byte)0x88:  // INTERNAL AUTHENTICATE
            case (byte)0x01:  // SET_EMV_TAG
            case (byte)0x02:  // SET_TAG_TEMPLATE
            case (byte)0x03:  // SET_READ_RECORD_TEMPLATE
            case (byte)0x04:  // SET_SETTINGS
            case (byte)0x06:  // SET_EMV_TAG_FUZZ
            case (byte)0x09:  // SET_EMV_TAG_CHUNKED
            case (byte)0x0A:  // SET_SETTINGS_CHUNKED
                hasCommandData = true;
                break;
            default:
                hasCommandData = false;
                break;
        }

        if (hasCommandData) {
            // Determine data length and offset
            // Check for extended APDU: LC byte is 0, followed by 2-byte length
            short lcByte = (short) (buf[ISO7816.OFFSET_LC] & 0x00FF);
            short expectedLen;
            short dataOffset;

            if (lcByte == 0) {
                // Extended APDU format: LC=0x00, then 2-byte length at offset 5-6, data at offset 7
                expectedLen = Util.getShort(buf, (short)(ISO7816.OFFSET_LC + 1));
                dataOffset = (short) 7;
            } else {
                // Short APDU format: LC at offset 4, data at offset 5
                expectedLen = lcByte;
                dataOffset = ISO7816.OFFSET_CDATA;  // = 5
            }

            // Receive incoming data
            bytesReceived = apdu.setIncomingAndReceive();

            // For large data (extended APDUs or protocol chunking), receive remaining bytes
            while (bytesReceived < expectedLen) {
                short more = apdu.receiveBytes((short)(dataOffset + bytesReceived));
                if (more <= 0) break;
                bytesReceived += more;
            }
        }

        // Log the APDU (use getIncomingLength for proper length in all cases)
        short logLen = hasCommandData ? (short)(5 + apdu.getIncomingLength()) : (short)5;
        if (logLen > 255) logLen = 255;
        ApduLog.addLogEntry(buf, (short) 0, (byte) logLen);

        // Get CLA+INS as command, but mask out the chaining bit (0x10) from CLA
        // This allows chained commands (CLA=0x90) to be recognized as regular commands (CLA=0x80)
        short cmd = (short)(((buf[ISO7816.OFFSET_CLA] & 0xEF) << 8) | (buf[ISO7816.OFFSET_INS] & 0xFF));

        switch (cmd) {
            case CMD_SELECT:
                processSelect(apdu, buf);
                return;
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
            case CMD_SET_EMV_TAG_CHUNKED:
                processSetEmvTagChunked(apdu, buf);
                return;
            case CMD_SET_SETTINGS_CHUNKED:
                processSetSettingsChunked(apdu, buf);
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
            case CMD_LIST_TAGS:
                listStoredTags(apdu, buf);
                return;
            case CMD_DIAGNOSTIC_61XX:
                // DIAGNOSTIC: Test if JCRE passes 61xx through correctly
                // No data needed - just throw 61xx directly
                // Store some dummy data for GET RESPONSE
                tmpBuffer[0] = (byte) 0xAA;
                tmpBuffer[1] = (byte) 0xBB;
                tmpBuffer[2] = (byte) 0xCC;
                pendingResponseOffset = (short) 0;
                pendingResponseLength = (short) 3;
                // Throw 61xx - should return SW=6103 if JCRE works correctly
                ISOException.throwIt((short) 0x6103);
                return;
            default:
                break;
        }

        if (selectingApplet()) {
            return;
        }

        switch (cmd) {
            case CMD_READ_RECORD:
                processReadRecord(apdu, buf);
                break;
            case CMD_DDA:
                processDynamicDataAuthentication(apdu, buf);
                break;
            case CMD_VERIFY_PIN:
                processVerifyPin(apdu, buf);
                break;
            case CMD_GET_CHALLENGE:
                processGetChallenge(apdu, buf);
                break;
            case CMD_GET_DATA:
                processGetData(apdu, buf);
                break;
            case CMD_GET_PROCESSING_OPTIONS:
                processGetProcessingOptions(apdu, buf);
                break;
            case CMD_GENERATE_AC:
                processGenerateAc(apdu, buf);
                break;
            case CMD_EXTERNAL_AUTHENTICATE:
                externalAuthenticate(apdu, buf);
                break;
            case CMD_GET_RESPONSE:
                processGetResponse(apdu, buf);
                break;
            default:
                EmvApplet.logAndThrow(ISO7816.SW_INS_NOT_SUPPORTED);
        }

    }
}
