package emvcardsimulator;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.CryptoException;
import javacard.security.ECPrivateKey;
import javacard.security.KeyBuilder;
import javacard.security.MessageDigest;
import javacard.security.RSAPrivateKey;
import javacard.security.RSAPublicKey;
import javacard.security.RandomData;
import javacard.security.Signature;
import javacardx.crypto.Cipher;

public class PaymentApplication extends EmvApplet {

    public static void install(byte[] buffer, short offset, byte length) {
        (new PaymentApplication(buffer, offset, length)).register();
    }

    private Cipher rsaCipher;
    private MessageDigest shaMessageDigest;
    private byte[] challenge;
    private byte[] tag9f4cDynamicNumber;
    private byte[] tag9f69CardAuthData;  // fDDA: version(1) + card UN(4) + CTQ(2) = 7 bytes
    private byte[] ecdsaSigBuffer;       // ECDSA DER signature buffer (max 72 bytes)
    private byte[] ecdsaRawSig;          // ECDSA raw r||s (64 bytes) for contactless

    private RSAPrivateKey rsaPrivateKey = null;
    private short rsaPrivateKeyByteSize = 0;
    private ECPrivateKey ecPrivateKey = null;
    private boolean ecPrivateKeyLoaded = false;
    private Signature ecdsaSignature = null;
    private byte[] pinCode = null;
    private boolean useRandom = true;

    // P-256 (secp256r1) domain parameters
    private static final byte[] EC_P256_P = {
        (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF, (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x01,
        (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00, (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,
        (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00, (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,
        (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF, (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF
    };
    private static final byte[] EC_P256_A = {
        (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF, (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x01,
        (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00, (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,
        (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00, (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,
        (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF, (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFC
    };
    private static final byte[] EC_P256_B = {
        (byte)0x5A,(byte)0xC6,(byte)0x35,(byte)0xD8, (byte)0xAA,(byte)0x3A,(byte)0x93,(byte)0xE7,
        (byte)0xB3,(byte)0xEB,(byte)0xBD,(byte)0x55, (byte)0x76,(byte)0x98,(byte)0x86,(byte)0xBC,
        (byte)0x65,(byte)0x1D,(byte)0x06,(byte)0xB0, (byte)0xCC,(byte)0x53,(byte)0xB0,(byte)0xF6,
        (byte)0x3B,(byte)0xCE,(byte)0x3C,(byte)0x3E, (byte)0x27,(byte)0xD2,(byte)0x60,(byte)0x4B
    };
    private static final byte[] EC_P256_G = {
        (byte)0x04,
        (byte)0x6B,(byte)0x17,(byte)0xD1,(byte)0xF2, (byte)0xE1,(byte)0x2C,(byte)0x42,(byte)0x47,
        (byte)0xF8,(byte)0xBC,(byte)0xE6,(byte)0xE5, (byte)0x63,(byte)0xA4,(byte)0x40,(byte)0xF2,
        (byte)0x77,(byte)0x03,(byte)0x7D,(byte)0x81, (byte)0x2D,(byte)0xEB,(byte)0x33,(byte)0xA0,
        (byte)0xF4,(byte)0xA1,(byte)0x39,(byte)0x45, (byte)0xD8,(byte)0x98,(byte)0xC2,(byte)0x96,
        (byte)0x4F,(byte)0xE3,(byte)0x42,(byte)0xE2, (byte)0xFE,(byte)0x1A,(byte)0x7F,(byte)0x9B,
        (byte)0x8E,(byte)0xE7,(byte)0xEB,(byte)0x4A, (byte)0x7C,(byte)0x0F,(byte)0x9E,(byte)0x16,
        (byte)0x2B,(byte)0xCE,(byte)0x33,(byte)0x57, (byte)0x6B,(byte)0x31,(byte)0x5E,(byte)0xCE,
        (byte)0xCB,(byte)0xB6,(byte)0x40,(byte)0x68, (byte)0x37,(byte)0xBF,(byte)0x51,(byte)0xF5
    };
    private static final byte[] EC_P256_N = {
        (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF, (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,
        (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF, (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,
        (byte)0xBC,(byte)0xE6,(byte)0xFA,(byte)0xAD, (byte)0xA7,(byte)0x17,(byte)0x9E,(byte)0x84,
        (byte)0xF3,(byte)0xB9,(byte)0xCA,(byte)0xC2, (byte)0xFC,(byte)0x63,(byte)0x25,(byte)0x51
    };

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
                    case (short) 1408: keyLength = (short) 1408; break;
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
                    case (short) 1408:
                        keyLength = (short) 1408;
                        break;
                    case (short) 1536:
                        keyLength = KeyBuilder.LENGTH_RSA_1536;
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
            // ICC EC PRIVATE KEY SCALAR (P-256, 32 bytes)
            case 0x000B:
                if (ecPrivateKey == null) {
                    ISOException.throwIt((short) 0x6985); // Conditions not satisfied
                }
                try {
                    short ecDataOffset = apdu.getOffsetCdata();
                    short ecLen = apdu.getIncomingLength();
                    if (ecLen == 0) {
                        short lcByte = (short) (buf[ISO7816.OFFSET_LC] & 0x00FF);
                        ecLen = (lcByte == 0) ? (short) 256 : lcByte;
                    }
                    ecPrivateKey.setS(buf, ecDataOffset, ecLen);
                    ecPrivateKeyLoaded = true;
                } catch (CryptoException e) {
                    ISOException.throwIt((short) 0x6A81); // Function not supported
                }
                break;
            default:
                ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }

        ISOException.throwIt(ISO7816.SW_NO_ERROR);
    }

    /**
     * Handle applet-specific STORE DATA settings (DGI 0xA0xx range).
     * Maps DGI low byte to the same settings IDs used by processSetSettings.
     */
    protected void processStoreDataSettings(short dgi, byte[] buf, short offset, short length) {
        switch (dgi) {
            // CPS 8000: Block cipher keys (RSA modulus/exponent, EC scalar)
            // First 8000 with RSA-sized data = modulus; second 8000 = exponent
            // 8000 with 32 bytes = EC P-256 private key scalar
            case (short) 0x8000:
                if (length == 32 && ecPrivateKey != null && rsaPrivateKeyByteSize == 0) {
                    // 32 bytes with no pending RSA modulus = EC key scalar
                    try {
                        ecPrivateKey.setS(buf, offset, length);
                        ecPrivateKeyLoaded = true;
                    } catch (CryptoException e) {
                        ISOException.throwIt((short) 0x6A81);
                    }
                } else if (rsaPrivateKeyByteSize == 0) {
                    // No modulus set yet = RSA modulus
                    rsaPrivateKeyByteSize = length;
                    short keyLength = (short) (rsaPrivateKeyByteSize * 8);
                    switch (keyLength) {
                        case (short) 1024: keyLength = KeyBuilder.LENGTH_RSA_1024; break;
                        case (short) 1280: keyLength = KeyBuilder.LENGTH_RSA_1280; break;
                        case (short) 1536: keyLength = KeyBuilder.LENGTH_RSA_1536; break;
                        case (short) 1984: keyLength = KeyBuilder.LENGTH_RSA_1984; break;
                        case (short) 2048: keyLength = KeyBuilder.LENGTH_RSA_2048; break;
                        default: ISOException.throwIt((short) 0x6A80);
                    }
                    try {
                        rsaPrivateKey = (RSAPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PRIVATE, keyLength, false);
                        rsaPrivateKey.clearKey();
                        rsaPrivateKey.setModulus(buf, offset, rsaPrivateKeyByteSize);
                    } catch (CryptoException e) {
                        rsaPrivateKey = null;
                        rsaPrivateKeyByteSize = 0;
                        ISOException.throwIt((short) 0x6A81);
                    }
                } else if (rsaPrivateKey != null && rsaPrivateKeyByteSize > 0) {
                    // Modulus already set — this is the RSA exponent
                    try {
                        rsaPrivateKey.setExponent(buf, offset, length);
                    } catch (CryptoException e) {
                        rsaPrivateKey = null;
                        rsaPrivateKeyByteSize = 0;
                        ISOException.throwIt((short) 0x6A81);
                    }
                }
                break;

            // CPS 8010: Offline PIN block
            case (short) 0x8010:
                Util.arrayCopy(buf, offset, pinCode, (short) 0, length);
                break;

            // App-specific 8201: RSA private key modulus
            case (short) 0x8201:
                rsaPrivateKeyByteSize = length;
                short rsaKeyLen = (short) (rsaPrivateKeyByteSize * 8);
                switch (rsaKeyLen) {
                    case (short) 1024: rsaKeyLen = KeyBuilder.LENGTH_RSA_1024; break;
                    case (short) 1280: rsaKeyLen = KeyBuilder.LENGTH_RSA_1280; break;
                    case (short) 1408: rsaKeyLen = (short) 1408; break;
                    case (short) 1536: rsaKeyLen = KeyBuilder.LENGTH_RSA_1536; break;
                    case (short) 1984: rsaKeyLen = KeyBuilder.LENGTH_RSA_1984; break;
                    case (short) 2048: rsaKeyLen = KeyBuilder.LENGTH_RSA_2048; break;
                    default: ISOException.throwIt((short) 0x6A80);
                }
                try {
                    rsaPrivateKey = (RSAPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PRIVATE, rsaKeyLen, false);
                    rsaPrivateKey.clearKey();
                    rsaPrivateKey.setModulus(buf, offset, rsaPrivateKeyByteSize);
                } catch (CryptoException e) {
                    rsaPrivateKey = null;
                    rsaPrivateKeyByteSize = 0;
                    ISOException.throwIt((short) 0x6A81);
                }
                break;

            // App-specific 8202: RSA private key exponent
            case (short) 0x8202:
                if (rsaPrivateKey == null || rsaPrivateKeyByteSize == 0) {
                    ISOException.throwIt((short) 0x6985);
                }
                try {
                    rsaPrivateKey.setExponent(buf, offset, length);
                } catch (CryptoException e) {
                    rsaPrivateKey = null;
                    rsaPrivateKeyByteSize = 0;
                    ISOException.throwIt((short) 0x6A81);
                }
                break;

            // App-specific 8203: EC P-256 private key scalar
            case (short) 0x8203:
                if (ecPrivateKey == null) {
                    ISOException.throwIt((short) 0x6985);
                }
                try {
                    ecPrivateKey.setS(buf, offset, length);
                    ecPrivateKeyLoaded = true;
                } catch (CryptoException e) {
                    ISOException.throwIt((short) 0x6A81);
                }
                break;

            // App-specific: response template tag (0x0077 or 0x0080)
            case (short) 0xA002:
                responseTemplateTag = Util.getShort(buf, offset);
                break;

            // App-specific: flags (bit 0 = randomness)
            case (short) 0xA003:
                short flags = Util.getShort(buf, offset);
                useRandom = ((flags & (1 << 0)) != 0);
                break;

            // App-specific: fallback read record
            case (short) 0xA006:
                defaultReadRecord = new byte[length];
                Util.arrayCopy(buf, offset, defaultReadRecord, (short) 0, length);
                break;

            default:
                ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }
    }

    protected PaymentApplication(byte[] buffer, short offset, byte length) {
        super();

        pinCode = new byte[] { (byte) 0x00, (byte) 0x00 };

        challenge = JCSystem.makeTransientByteArray((short) 8, JCSystem.CLEAR_ON_DESELECT);

        tag9f4cDynamicNumber = JCSystem.makeTransientByteArray((short) 3, JCSystem.CLEAR_ON_DESELECT);
        tag9f69CardAuthData = JCSystem.makeTransientByteArray((short) 7, JCSystem.CLEAR_ON_DESELECT);
        ecdsaSigBuffer = JCSystem.makeTransientByteArray((short) 72, JCSystem.CLEAR_ON_DESELECT);
        ecdsaRawSig = JCSystem.makeTransientByteArray((short) 64, JCSystem.CLEAR_ON_DESELECT);

        // Storage for CDOL1 data - transient so it's cleared on deselect
        storedCdol1Data = JCSystem.makeTransientByteArray((short) 64, JCSystem.CLEAR_ON_DESELECT);
        storedCdol1Length = 0;

        // Storage for PDOL data - transient so it's cleared on deselect
        storedPdolData = JCSystem.makeTransientByteArray((short) 64, JCSystem.CLEAR_ON_DESELECT);
        storedPdolLength = 0;

        // DEBUG: Storage for hash input (256 bytes should be enough) and output (32 bytes for SHA-256)
        debugHashInput = JCSystem.makeTransientByteArray((short) 256, JCSystem.CLEAR_ON_DESELECT);
        debugHashInputLength = 0;
        debugHashOutput = JCSystem.makeTransientByteArray((short) 20, JCSystem.CLEAR_ON_DESELECT);

        // Chunked settings buffer for RSA key on T=0 cards (persistent)
        settingsChunkBuffer = new byte[512];

        rsaCipher = Cipher.getInstance(Cipher.ALG_RSA_NOPAD, false);

        shaMessageDigest = MessageDigest.getInstance(MessageDigest.ALG_SHA, false);

        // ECDSA P-256 key and signature objects
        ecPrivateKey = (ECPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE, KeyBuilder.LENGTH_EC_FP_256, false);
        ecPrivateKey.setFieldFP(EC_P256_P, (short) 0, (short) EC_P256_P.length);
        ecPrivateKey.setA(EC_P256_A, (short) 0, (short) EC_P256_A.length);
        ecPrivateKey.setB(EC_P256_B, (short) 0, (short) EC_P256_B.length);
        ecPrivateKey.setG(EC_P256_G, (short) 0, (short) EC_P256_G.length);
        ecPrivateKey.setR(EC_P256_N, (short) 0, (short) EC_P256_N.length);
        ecPrivateKey.setK((short) 1);
        ecdsaSignature = Signature.getInstance(Signature.ALG_ECDSA_SHA_256, false);
    }

    protected void factoryReset() {
        super.factoryReset();
        ecPrivateKeyLoaded = false;
        rsaPrivateKey = null;
        rsaPrivateKeyByteSize = 0;
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
        // CDA requested when P1 bits 5-4 = '10' (0x10). Reject RFU '11' (0x18).
        boolean cdaRequested = ((referenceControlParameter & (byte) 0x18) == (byte) 0x10);

        // Online-only card: always return ARQC regardless of terminal request
        // Terminal may ask for TC (offline approve) or AAC (decline), but we
        // always force online authorization via ARQC
        byte responseCryptogramType = (byte) 0x80; // ARQC

        // CDA requires both RSA (for SDAD) and EC (for ECDSA) keys
        boolean canPerformCda = (rsaPrivateKey != null && rsaPrivateKeyByteSize > 0 && ecPrivateKeyLoaded);

        // Check if CDA is supported in AIP (byte 1 bit 0 = 0x01)
        // Some kernels expect CDA based on AIP, not explicit P1 request
        boolean cdaSupportedInAip = false;
        EmvTag aipTag = EmvTag.findTag((short) 0x0082);
        if (aipTag != null && aipTag.getLength() >= 1) {
            byte aipByte1 = aipTag.getData()[0];
            cdaSupportedInAip = ((aipByte1 & (byte) 0x01) != 0);
        }

        // Perform CDA if: explicitly requested OR (supported in AIP AND we can do it)
        boolean shouldPerformCda = cdaRequested || (cdaSupportedInAip && canPerformCda);

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

        // CDA path: generate shared ICC_DN, then ECDSA (r→9F10, s→9F6E),
        // then RSA SDAD (TDH includes ECDSA r as 9F10, reuses same ICC_DN)
        if (shouldPerformCda && canPerformCda) {
            generateIccDynamicNumber();
            generateEcdsaForCda(buf, cdolLen);
            generateSdad(buf, cid, cdolLen);
            // CDA response: 9F27 + 9F36 + 9F4B + 9F10 (r) + 9F6E (s)
            sendGenerateAcResponseCda(apdu, buf);
        } else if (cdaRequested && !canPerformCda) {
            // CDA requested but RSA or EC key not available
            EmvApplet.logAndThrow((short) 0x6985);
        } else {
            // No CDA — plain response with 9F27, 9F36, 9F26, 9F10
            sendGenerateAcResponseNoCda(apdu, buf);
        }

        // Scrub tmpBuffer — crypto intermediates must not linger
        Util.arrayFillNonAtomic(tmpBuffer, (short) 0, (short) tmpBuffer.length, (byte) 0x00);
    }

    /**
     * Send GENERATE AC response with CDA per EMV Book 2 Table 20.
     * Response tag 77: 9F27 (CID) + 9F36 (ATC) + 9F4B (SDAD) + 9F10 (IAD)
     *                  + optional 9F6E (ECDSA s when EC key is loaded).
     * Note: 9F26 (AC) is NOT included — AC is embedded inside the SDAD.
     */
    private void sendGenerateAcResponseCda(APDU apdu, byte[] buf) {
        short offset = (short) 0;

        EmvTag cidTag = EmvTag.findTag((short) 0x9F27);
        if (cidTag != null) { offset = cidTag.copyToArray(tmpBuffer, offset); }

        EmvTag atcTag = EmvTag.findTag((short) 0x9F36);
        if (atcTag != null) { offset = atcTag.copyToArray(tmpBuffer, offset); }

        EmvTag sdadTag = EmvTag.findTag((short) 0x9F4B);
        if (sdadTag != null) { offset = sdadTag.copyToArray(tmpBuffer, offset); }

        EmvTag iadTag = EmvTag.findTag((short) 0x9F10);
        if (iadTag != null) { offset = iadTag.copyToArray(tmpBuffer, offset); }

        // 9F6E (ECDSA s) intentionally omitted from CDA response — terminal
        // may reject unknown-length tags during ParseAndStoreCardResponse

        // Store as tag 77 and use existing sendResponse which handles chunking
        EmvTag.setTag((short) 0x0077, tmpBuffer, (short) 0, offset);
        sendResponse(apdu, buf, (short) 0x0077);
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
     * Generate ECDSA P-256 signature over ICC_DN || CDOL data during GENERATE AC.
     * Signs the full CDOL data as provided by the terminal, prepended with ICC Dynamic Number.
     * Raw r component stored in tag 9F10 (IAD), s in tag 9F6E, ICC_DN in 9F4C.
     */
    private void generateEcdsaForGenAc(byte[] buf, short cdolLen) {
        // Generate random ICC Dynamic Number (3 bytes)
        arrayRandomFill(tag9f4cDynamicNumber);
        EmvTag.setTag((short) 0x9F4C, tag9f4cDynamicNumber, (short) 0, (byte) tag9f4cDynamicNumber.length);

        // Sign: ICC_DN(3) || CDOL data (cdolLen bytes from GENERATE AC command)
        ecdsaSignature.init(ecPrivateKey, Signature.MODE_SIGN);
        ecdsaSignature.update(tag9f4cDynamicNumber, (short) 0, (short) tag9f4cDynamicNumber.length);
        short sigLen = ecdsaSignature.sign(buf, ISO7816.OFFSET_CDATA, cdolLen, ecdsaSigBuffer, (short) 0);

        // Strip DER → raw r||s (64 bytes)
        derToRawSig(ecdsaSigBuffer, (short) 0, sigLen, ecdsaRawSig, (short) 0);

        // Store r in 9F10 (IAD), s in 9F6E
        EmvTag.setTag((short) 0x9F10, ecdsaRawSig, (short) 0, (short) 32);
        EmvTag.setTag((short) 0x9F6E, ecdsaRawSig, (short) 32, (short) 32);
    }

    // Scratch offset in tmpBuffer for small temporary data (ICC DN, etc.)
    // SDAD builder uses offsets 0..~300; this region is beyond that range.
    private static final short TMP_SCRATCH_OFFSET = (short) 480;

    /**
     * Generate 8-byte ICC Dynamic Number and store in tag 9F4C.
     * Called once before ECDSA and SDAD so both use the same value.
     */
    private void generateIccDynamicNumber() {
        randomData.generateData(tmpBuffer, TMP_SCRATCH_OFFSET, (short) 8);
        if (!useRandom) {
            Util.arrayFillNonAtomic(tmpBuffer, TMP_SCRATCH_OFFSET, (short) 8, (byte) 0xAB);
        }
        EmvTag.setTag((short) 0x9F4C, tmpBuffer, TMP_SCRATCH_OFFSET, (short) 8);
    }

    /**
     * Generate ECDSA P-256 signature for CDA+ECDSA merged flow.
     * Must be called BEFORE generateSdad() so that the Transaction Data Hash
     * in the SDAD correctly includes the ECDSA r component as 9F10 (IAD).
     * Uses ICC Dynamic Number from 9F4C (set by generateIccDynamicNumber).
     * Signs: ICC_DN(8) || CDOL data. r stored in 9F10, s in 9F6E.
     */
    private void generateEcdsaForCda(byte[] buf, short cdolLen) {
        EmvTag iccDnTag = EmvTag.findTag((short) 0x9F4C);
        if (iccDnTag == null) return;

        byte[] iccDn = iccDnTag.getData();
        short iccDnLen = iccDnTag.getLength();

        // Sign: ICC_DN(8) || CDOL data
        ecdsaSignature.init(ecPrivateKey, Signature.MODE_SIGN);
        ecdsaSignature.update(iccDn, (short) 0, iccDnLen);
        short sigLen = ecdsaSignature.sign(buf, ISO7816.OFFSET_CDATA, cdolLen, ecdsaSigBuffer, (short) 0);

        // Strip DER → raw r||s (64 bytes)
        derToRawSig(ecdsaSigBuffer, (short) 0, sigLen, ecdsaRawSig, (short) 0);

        // Store r in 9F10 (IAD), s in 9F6E
        EmvTag.setTag((short) 0x9F10, ecdsaRawSig, (short) 0, (short) 32);
        EmvTag.setTag((short) 0x9F6E, ecdsaRawSig, (short) 32, (short) 32);
    }

    /**
     * Build GENERATE AC response with ECDSA signature tags.
     * Response tag 77: 9F27 (CID), 9F36 (ATC), 9F26 (AC), 9F10 (r), 9F6E (s), 9F4C (ICC_DN)
     */
    private void sendGenerateAcResponseEcdsa(APDU apdu, byte[] buf) {
        short offset = (short) 0;

        // 9F27 (CID)
        EmvTag cidTag = EmvTag.findTag((short) 0x9F27);
        if (cidTag != null) {
            offset = cidTag.copyToArray(tmpBuffer, offset);
        }

        // 9F36 (ATC)
        EmvTag atcTag = EmvTag.findTag((short) 0x9F36);
        if (atcTag != null) {
            offset = atcTag.copyToArray(tmpBuffer, offset);
        }

        // 9F26 (AC)
        EmvTag acTag = EmvTag.findTag((short) 0x9F26);
        if (acTag != null) {
            offset = acTag.copyToArray(tmpBuffer, offset);
        }

        // 9F10 (IAD = ECDSA r, 32 bytes)
        EmvTag iadTag = EmvTag.findTag((short) 0x9F10);
        if (iadTag != null) {
            offset = iadTag.copyToArray(tmpBuffer, offset);
        }

        // 9F6E (ECDSA s, 32 bytes)
        EmvTag ecdsaSTag = EmvTag.findTag((short) 0x9F6E);
        if (ecdsaSTag != null) {
            offset = ecdsaSTag.copyToArray(tmpBuffer, offset);
        }

        // 9F4C (ICC Dynamic Number, 3 bytes)
        EmvTag dnTag = EmvTag.findTag((short) 0x9F4C);
        if (dnTag != null) {
            offset = dnTag.copyToArray(tmpBuffer, offset);
        }

        // Build tag 77 template wrapper
        short contentLen = offset;
        short responseOffset = (short) 0;

        buf[ISO7816.OFFSET_CDATA] = (byte) 0x77;
        responseOffset = (short) (ISO7816.OFFSET_CDATA + 1);

        if (contentLen > (short) 127) {
            buf[responseOffset++] = (byte) 0x81;
            buf[responseOffset++] = (byte) (contentLen & 0xFF);
        } else {
            buf[responseOffset++] = (byte) contentLen;
        }

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
        tmpBuffer[2] = (byte) 0x01;  // Hash Algorithm Indicator (SHA-1)

        // ICC Dynamic Data for CDA Format 05:
        // - ICC Dynamic Number Length (1 byte)
        // - ICC Dynamic Number (LDD bytes, we use 8)
        // - Cryptogram Information Data (1 byte)
        // - Application Cryptogram (8 bytes)
        // - Transaction Data Hash Code (20 bytes) - hash over CDOL data
        // Total: 1 + 8 + 1 + 8 + 20 = 38 bytes

        byte iccDynNumLen = (byte) 8;
        byte iccDynamicDataLength = (byte) (1 + iccDynNumLen + 1 + 8 + 20); // len + DN + CID + AC + TDH
        tmpBuffer[3] = iccDynamicDataLength;

        short offset = 4;

        // ICC Dynamic Number Length
        tmpBuffer[offset++] = iccDynNumLen;

        // ICC Dynamic Number (8 bytes) - reuse from 9F4C if already generated,
        // otherwise generate fresh
        EmvTag iccDnTag = EmvTag.findTag((short) 0x9F4C);
        if (iccDnTag != null && iccDnTag.getLength() == iccDynNumLen) {
            Util.arrayCopy(iccDnTag.getData(), (short) 0, tmpBuffer, offset, (short) iccDynNumLen);
        } else {
            randomData.generateData(tmpBuffer, offset, (short) iccDynNumLen);
            if (!useRandom) {
                Util.arrayFillNonAtomic(tmpBuffer, offset, (short) iccDynNumLen, (byte) 0xAB);
            }
            EmvTag.setTag((short) 0x9F4C, tmpBuffer, offset, iccDynNumLen);
        }
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

        // 3. Calculate CDA response content length for tag 77 wrapper
        // CDA response per Book 2 Table 20: 9F27(4) + 9F36(5) + 9F4B(2+lenBytes+NIC) + 9F10(3+iadLen)
        // Note: NO 9F26 in CDA response — AC is inside SDAD
        EmvTag iadTagForLen = EmvTag.findTag((short) 0x9F10);
        short iadLenForCalc = (iadTagForLen != null) ? (short) (iadTagForLen.getLength() & 0xFF) : 0;
        short sdadLengthBytes = (rsaPrivateKeyByteSize >= (short) 256) ? (short) 3 : (short) 2;
        short responseContentLen = (short) (4 + 5 + 2 + sdadLengthBytes + rsaPrivateKeyByteSize + 3 + iadLenForCalc);
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

        // 9F26 (AC) is NOT included in CDA response per Book 2 Table 20
        // AC is embedded inside the SDAD (ICC Dynamic Data)
        // 9F4B (SDAD) is excluded from hash per Book 2 Section 6.6.2 Step 10

        // 9F10 (IAD) - variable length
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

        // 9F4B (SDAD) is excluded per EMV Book 2 Section 6.6.3 Step 10:
        // "with the exception of the Signed Dynamic Application Data"

        shaMessageDigest.doFinal(tmpBuffer, (short) 0, (short) 0, tmpBuffer, offset);
        // DEBUG: Store the Transaction Data Hash output
        Util.arrayCopy(tmpBuffer, offset, debugHashOutput, (short) 0, (short) 20);
        offset += 20;

        // Trailer at end
        tmpBuffer[(short) (signedDataSize - 1)] = (byte) 0xBC;

        // Compute SDAD hash (SHA-1)
        // Hash input: bytes 1 through (signedDataSize - 22) = format through padding
        //             + Unpredictable Number (9F37)
        short checksumStartIndex = (short) (signedDataSize - 21);

        shaMessageDigest.reset();
        // Hash: Format through Pad Pattern (bytes 1 to checksumStartIndex-1)
        shaMessageDigest.update(tmpBuffer, (short) 1, (short) (checksumStartIndex - 1));

        // Include Unpredictable Number from CDOL data
        // CDOL1: 9F02(6)+9F03(6)+9F1A(2)+95(5)+5F2A(2)+9A(3)+9C(1)+9F37(4)... UN at offset 25
        // CDOL2: 8A(2)+9F02(6)+9F03(6)+9F1A(2)+95(5)+5F2A(2)+9A(3)+9C(1)+9F37(4)... UN at offset 27
        // Determine UN offset based on CDOL length: CDOL2 (60 bytes) vs CDOL1 (43-58 bytes)
        short unOffset = (cdolLen == (short) 60) ? (short) 27 : (short) 25;
        if (cdolLen >= (short) (unOffset + 4)) {
            shaMessageDigest.update(buf, (short) (ISO7816.OFFSET_CDATA + unOffset), (short) 4);
        }

        shaMessageDigest.doFinal(tmpBuffer, (short) 0, (short) 0, tmpBuffer, checksumStartIndex);

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
        EmvTag tag = EmvTag.findTag(tagId);
        if (tag == null) {
            // Return 6A88 (Referenced data not found) per EMV spec
            EmvApplet.logAndThrow((short) 0x6A88);
        }
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

        // Full EMV mode for both contact and contactless:
        // Return AIP + AFL, terminal will do READ RECORD then GENERATE AC
        sendResponseTemplate(apdu, buf, responseTemplateGetProcessingOptions);
    }

    /* qVSDC removed — full EMV mode for all contactless transactions.
     * ECDSA signing now happens in processGenerateAc() via generateEcdsaForGenAc().
     */

    private void processDynamicDataAuthentication(APDU apdu, byte[] buf) {
        if (Util.getShort(buf, ISO7816.OFFSET_P1) != (short) 0x0000) {
            EmvApplet.logAndThrow(ISO7816.SW_INCORRECT_P1P2);
        }

        // ECDSA P-256 signing (no EMV SDAD structure — raw signature for on-chain verification)
        // Signed data: ICC Dynamic Number (9F4C) || DDOL data (Unpredictable Number from APDU)
        // ALG_ECDSA_SHA_256 handles SHA-256 hashing internally, outputs DER-encoded signature

        // Generate random ICC Dynamic Number
        short iccDynNumLen = (short) tag9f4cDynamicNumber.length;
        arrayRandomFill(tag9f4cDynamicNumber);

        // Store ICC Dynamic Number in tag 9F4C for extraction
        EmvTag.setTag((short) 0x9F4C, tag9f4cDynamicNumber, (short) 0, (byte) iccDynNumLen);

        // Get DDOL data length from LC
        short LC = (short) (buf[ISO7816.OFFSET_LC] & 0x00FF);

        // Sign: feed ICC Dynamic Number first, then DDOL data (Unpredictable Number)
        ecdsaSignature.init(ecPrivateKey, Signature.MODE_SIGN);
        ecdsaSignature.update(tag9f4cDynamicNumber, (short) 0, iccDynNumLen);
        short sigLen = ecdsaSignature.sign(buf, ISO7816.OFFSET_CDATA, LC, tmpBuffer, (short) 0);

        // Store ECDSA signature in tag 9F4B (DER-encoded, ~70-72 bytes)
        EmvTag.setTag((short) 0x9F4B, tmpBuffer, (short) 0, sigLen);

        // Scrub tmpBuffer — signature intermediates must not linger
        Util.arrayFillNonAtomic(tmpBuffer, (short) 0, (short) tmpBuffer.length, (byte) 0x00);

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

        // Scrub tmpBuffer — decrypted PIN data must not linger
        Util.arrayFillNonAtomic(tmpBuffer, (short) 0, (short) tmpBuffer.length, (byte) 0x00);

        EmvApplet.logAndThrow(ISO7816.SW_NO_ERROR);
    }

    private void arrayRandomFill(byte[] dst) {
        randomData.generateData(dst, (short) 0, (short) dst.length);
        if (!useRandom) {
            Util.arrayFillNonAtomic(dst, (short) 0, (short) dst.length, (byte) 0xAB);
        }
    }

    private void arrayRandomFill4(byte[] dst, short offset) {
        randomData.generateData(dst, offset, (short) 4);
        if (!useRandom) {
            Util.arrayFillNonAtomic(dst, offset, (short) 4, (byte) 0xAB);
        }
    }

    // Strip DER encoding from ECDSA signature, extract raw r||s (64 bytes) into dst
    // DER format: 30 <len> 02 <rlen> <r...> 02 <slen> <s...>
    private void derToRawSig(byte[] der, short derOff, short derLen, byte[] dst, short dstOff) {
        Util.arrayFillNonAtomic(dst, dstOff, (short) 64, (byte) 0x00);
        short pos = (short) (derOff + 2); // skip 30 <len>
        // r component
        pos++; // skip 02
        short rLen = (short) (der[pos++] & 0xFF);
        short rPad = (rLen > 32) ? (short) (rLen - 32) : (short) 0;
        short rDstOff = (rLen < 32) ? (short) (dstOff + 32 - rLen) : dstOff;
        Util.arrayCopy(der, (short) (pos + rPad), dst, rDstOff, (short) (rLen - rPad));
        pos += rLen;
        // s component
        pos++; // skip 02
        short sLen = (short) (der[pos++] & 0xFF);
        short sPad = (sLen > 32) ? (short) (sLen - 32) : (short) 0;
        short sDstOff = (sLen < 32) ? (short) (dstOff + 64 - sLen) : (short) (dstOff + 32);
        Util.arrayCopy(der, (short) (pos + sPad), dst, sDstOff, (short) (sLen - sPad));
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
            case (byte)0xE2:  // STORE DATA (GP personalization)
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

        // STORE DATA (INS E2) — accept CLA 00, 80, or 84 per CPS v2.0
        if (buf[ISO7816.OFFSET_INS] == (byte) 0xE2) {
            processStoreData(apdu, buf);
            return;
        }

        // Get CLA+INS as command, but mask out the chaining bit (0x10) from CLA
        // This allows chained commands (CLA=0x90) to be recognized as regular commands (CLA=0x80)
        short cmd = (short)(((buf[ISO7816.OFFSET_CLA] & 0xEF) << 8) | (buf[ISO7816.OFFSET_INS] & 0xFF));

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
                    tmpBuffer[0] = (byte) 0xAA;
                    tmpBuffer[1] = (byte) 0xBB;
                    tmpBuffer[2] = (byte) 0xCC;
                    pendingResponseOffset = (short) 0;
                    pendingResponseLength = (short) 3;
                    ISOException.throwIt((short) 0x6103);
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
