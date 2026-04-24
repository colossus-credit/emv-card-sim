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
    private boolean isContactInterface = true; // default contact; set at SELECT from AID
    // Tracks whether the 1st GENERATE AC of this transaction has been issued.
    // Per EMV Book 2 §8.1.1 and Book 3 §6.5.5, the ATC increments once per
    // transaction (at 1st GenAC) and the same ATC is used for 2nd GenAC. The
    // ECDSA signature is also produced only on 1st GenAC; 2nd GenAC returns the
    // same signature tags. Reset on SELECT (transient, cleared on deselect).
    private boolean firstGenAcSeen = false;

    // Symmetric block cipher key material received via DGI 8000 (CPS v2.0
    // Annex A.2 Table A-2). In a spec-compliant EMV implementation this is the
    // issuer Application-Cryptogram master key (MK_AC) used to derive per-
    // transaction session keys for 3DES-CBC-MAC or AES-CMAC generation of
    // tag 9F26. ColossusNet trusts the ECDSA signature in 9F10/9F6E for
    // issuer-side authentication and uses a placeholder AC (see audit F-46),
    // so this buffer is stored but not read at transaction time. Kept on-card
    // so bureau flows that emit DGI 8000 per CPS don't error, and so that
    // future real-MAC work has the material already loaded.
    private byte[] symmetricKeyData = null;
    private short symmetricKeyLength = 0;

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

    // Upper bound on PDOL / CDOL data cached per transaction. The ISO 7816 short
    // APDU data field is capped at Lc = 0xFF = 255 bytes; EMV GENERATE AC with
    // extended CDOL payloads never exceeds ~80 bytes in practice. 128 gives us
    // headroom for wider DOLs (e.g. terminals including 9F02/9F03/9F66/9F6C +
    // amount/currency/merchant strings) without enforcing a spec-illegal cap.
    private static final short MAX_DOL_BYTES = (short) 128;

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
            // CPS 8000: Block cipher (symmetric) keys — CPS v2.0 Annex A.2 Table A-2.
            // A spec-compliant EMV issuer uses this for MK_AC (Application Cryptogram
            // master key), MK_SMC/MK_SMI (secure messaging), etc., and derives
            // per-transaction session keys for 3DES-CBC-MAC or AES-CMAC.
            //
            // ColossusNet's current threat model trusts the ECDSA signature in
            // tags 9F10/9F6E for issuer-side authentication and uses a
            // placeholder SHA-1-based AC (audit F-46). So we accept and store
            // the key bytes on-card to remain compliant with standard bureau
            // perso flows that emit DGI 8000, but we don't use them yet.
            // When F-46 is addressed the stored material will already be here.
            case (short) 0x8000:
                if (length < 0 || length > (short) symmetricKeyData.length) {
                    ISOException.throwIt((short) 0x6A80);  // incorrect data field
                }
                JCSystem.beginTransaction();
                Util.arrayCopy(buf, offset, symmetricKeyData, (short) 0, length);
                symmetricKeyLength = length;
                JCSystem.commitTransaction();
                break;

            // CPS 8010: Offline PIN block
            case (short) 0x8010:
                Util.arrayCopy(buf, offset, pinCode, (short) 0, length);
                break;

            // CPS DGI 8103: ICC Modulus (DDA/PIN Encipherment) — CPS v2.0 Annex A.2 Table A-10.
            // Plain-form RSA private key; paired with DGI 8101 for the exponent.
            // Spec: "personalise either DGIs '8101' ICC Private Key and '8103' Modulus,
            // or '8201' to '8205' CRT constants." We use the plain form.
            case (short) 0x8103:
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

            // CPS DGI 8101: ICC Private Key (DDA/PIN Encipherment) — CPS v2.0 Annex A.2 Table A-8.
            // Plain-form RSA exponent; must arrive after the modulus (DGI 8103).
            case (short) 0x8101:
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

            // CPS DGI 8105: ICC ECC Secret Key — CPS v2.0 Annex A.2 Table A-11b.
            // P-256 private key scalar (32 bytes).
            case (short) 0x8105:
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

        // DGI 8000 symmetric key storage (see F-33 comment on the field).
        // 32 bytes covers typical bureau block-cipher key material (AES-128 =
        // 16B, AES-192 = 24B, AES-256 = 32B, 3DES-2key = 16B, 3DES-3key = 24B).
        symmetricKeyData = new byte[32];
        symmetricKeyLength = 0;

        challenge = JCSystem.makeTransientByteArray((short) 8, JCSystem.CLEAR_ON_DESELECT);

        tag9f4cDynamicNumber = JCSystem.makeTransientByteArray((short) 3, JCSystem.CLEAR_ON_DESELECT);
        tag9f69CardAuthData = JCSystem.makeTransientByteArray((short) 7, JCSystem.CLEAR_ON_DESELECT);
        ecdsaSigBuffer = JCSystem.makeTransientByteArray((short) 72, JCSystem.CLEAR_ON_DESELECT);
        ecdsaRawSig = JCSystem.makeTransientByteArray((short) 64, JCSystem.CLEAR_ON_DESELECT);

        // Storage for CDOL1 data - transient so it's cleared on deselect.
        // Sized to MAX_DOL_BYTES so we accept any DOL the terminal builds,
        // up to the ISO 7816 short-APDU data field limit. F-44/F-52 fix: we
        // no longer hardcode an "expected" length — the card hashes exactly
        // what the terminal sent in CDOL1, byte-for-byte (Book 2 §6.6.2).
        storedCdol1Data = JCSystem.makeTransientByteArray(MAX_DOL_BYTES, JCSystem.CLEAR_ON_DESELECT);
        storedCdol1Length = 0;

        // Storage for PDOL data - same sizing rules as CDOL1 above (F-43/F-51).
        storedPdolData = JCSystem.makeTransientByteArray(MAX_DOL_BYTES, JCSystem.CLEAR_ON_DESELECT);
        storedPdolLength = 0;

        // DEBUG: Storage for hash input/output — only allocated in dev builds
        if (!BuildConfig.PRODUCTION) {
            debugHashInput = JCSystem.makeTransientByteArray((short) 256, JCSystem.CLEAR_ON_DESELECT);
            debugHashOutput = JCSystem.makeTransientByteArray((short) 20, JCSystem.CLEAR_ON_DESELECT);
        }
        debugHashInputLength = 0;

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
        firstGenAcSeen = false;
    }

    private void processSelect(APDU apdu, byte[] buf) {
        // Reset stored data for new transaction
        storedCdol1Length = 0;
        storedPdolLength = 0;
        // New transaction scope: ATC increments and ECDSA signing happen on
        // the next 1st GenAC; 2nd GenAC will reuse the same ATC.
        firstGenAcSeen = false;

        // Detect contact vs contactless from the SELECT AID.
        // Contactless AID ends with 0x1010 (e.g. A0000009511010).
        // Contact AID ends with 0x0001 (e.g. A0000009510001).
        short aidLen = (short) (buf[ISO7816.OFFSET_LC] & 0xFF);
        if (aidLen >= (short) 2) {
            short suffixOffset = (short) (ISO7816.OFFSET_CDATA + aidLen - 2);
            isContactInterface = !(buf[suffixOffset] == (byte) 0x10
                                && buf[(short) (suffixOffset + 1)] == (byte) 0x10);
        }

        // Don't clear logs here - it prevents reading logs via opensc-tool
        // The rolling log limit (maxCount=10) handles old logs

        // Check if PAN (tag 5A) exists in the ICC
        if (EmvTag.findTag((short) 0x5A) != null) {
            arrayRandomFill(challenge);

            if (tagA5Fci != null && (tagA5Fci.getLength() & 0xFF) > 0) {
                short length = tagA5Fci.expandTlvToArray(tmpBuffer, (short) 0);
                EmvTag.setTag((short) 0xA5, tmpBuffer, (short) 0, (byte) length);
            }

            // Require BOTH the 6F FCI template reference AND a populated tag
            // list — after factoryReset() the template object still exists but
            // has length = 0. Returning an empty [6F 00] FCI would confuse
            // properly-written terminals and breaks the property test's
            // "SELECT with invalid AID should not return 9000 with data".
            if (tag6fFci != null && (tag6fFci.getLength() & 0xFF) > 0) {
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
        // F-48: EMV Book 3 §9.1.1 Table 34 — P2 must be '00'. Reject otherwise
        // with 6A86 rather than silently proceeding, to catch terminals whose
        // kernel hasn't been updated to the current spec.
        if (buf[ISO7816.OFFSET_P2] != (byte) 0x00) {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }

        byte referenceControlParameter = buf[ISO7816.OFFSET_P1];
        // Check if CDA is requested (P1 bit 4 = 0x10)
        // CDA requested when P1 bits 5-4 = '10' (0x10). Reject RFU '11' (0x18).
        boolean cdaRequested = ((referenceControlParameter & (byte) 0x18) == (byte) 0x10);

        // Determine response cryptogram type (CID) per EMV Book 3 §6.5.5.4.
        // 1st GenAC: online-only card always returns ARQC (force online).
        // 2nd GenAC: must return TC or AAC (never ARQC); honor terminal's P1
        //   request because this card performs no card-side risk management
        //   and the issuer has already decided via ARC (carried in CDOL2).
        //   Cryptogram hierarchy: TC > ARQC > AAC. Card may return equal or
        //   lower than requested, never higher.
        byte responseCryptogramType;
        byte requestedType = (byte) (referenceControlParameter & (byte) 0xC0);
        if (!firstGenAcSeen) {
            responseCryptogramType = (byte) 0x80; // ARQC on 1st
        } else {
            if (requestedType == (byte) 0x40) {
                responseCryptogramType = (byte) 0x40; // TC (terminal requested TC)
            } else {
                // AAC for explicit AAC request (0x00) OR illegal ARQC-on-2nd (0x80)
                responseCryptogramType = (byte) 0x00;
            }
        }

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

        short cdolLen = (short) (buf[ISO7816.OFFSET_LC] & 0x00FF);

        // Capture before we flip the flag so the response builder knows
        // whether this is the 1st or 2nd GenAC call.
        boolean isFirstGenAcCall = !firstGenAcSeen;

        // 1st GenAC only: increment ATC, compute AC, sign ECDSA (for contact).
        // Per EMV Book 2 §8.1.1, the session key — and thus the AC — is derived
        // from the ATC; a single transaction must use a single ATC across 1st
        // and 2nd GenAC. Per EMV Book 3 §6.5.5, the card's signatures / MAC
        // are produced at 1st GenAC; 2nd GenAC returns the same tag values
        // (with only CID reflecting the terminal's completion decision).
        if (isFirstGenAcCall) {
            incrementApplicationTransactionCounter();

            // Generate Application Cryptogram (9F26) — contact overwrites with
            // ECDSA s[0:8] below; contactless keeps the SHA-1 placeholder.
            generateApplicationCryptogram(buf, ISO7816.OFFSET_CDATA, cdolLen);

            // Contact-only: sign ATC||CDOL at GenAC time (vs contactless which
            // signs ATC||PDOL at GPO). CDOL covers the full transaction context
            // — terminal risk management results, UN, etc. — that PDOL alone
            // doesn't carry.
            if (isContactInterface && ecPrivateKeyLoaded && cdolLen > 0) {
                generateEcdsaAtGenAc(buf, ISO7816.OFFSET_CDATA, cdolLen);
            }

            firstGenAcSeen = true;
        }
        // 2nd GenAC: ATC unchanged, 9F26/9F10 still hold values from 1st
        // GenAC. Only 9F27 (CID) was updated above to reflect TC/AAC.
        // ECDSA-payload tags (4F/84/5F2D) are trimmed from the 2nd GenAC
        // response — see sendGenerateAcResponseNoCda().

        // CDA path: ECDSA already done at GPO (r in 9F10, s in 9F6E, ICC_DN in 9F4C).
        // Just build SDAD — its TDH includes 9F10 (ECDSA r). ICC_DN reused from 9F4C.
        if (shouldPerformCda && canPerformCda) {
            generateSdad(buf, cid, cdolLen);
            // CDA response: 9F27 + 9F36 + 9F4B + 9F10 (no 9F6E — delivered via READ RECORD)
            sendGenerateAcResponseCda(apdu, buf);
        } else if (cdaRequested && !canPerformCda) {
            // CDA requested but RSA or EC key not available
            EmvApplet.logAndThrow((short) 0x6985);
        } else {
            // No CDA — plain response with 9F27, 9F36, 9F26, 9F10
            sendGenerateAcResponseNoCda(apdu, buf, isFirstGenAcCall);
        }

        // Scrub tmpBuffer — crypto intermediates must not linger
        Util.arrayFillNonAtomic(tmpBuffer, (short) 0, (short) tmpBuffer.length, (byte) 0x00);
    }

    /**
     * Send GENERATE AC response with CDA per EMV Book 2 Table 20.
     * Response tag 77: 9F27 (CID) + 9F36 (ATC) + 9F4B (SDAD) + 9F10 (IAD).
     * Note: 9F26 (AC) is NOT included — AC is embedded inside the SDAD.
     *       9F6E (ECDSA s) omitted — terminal rejects non-standard tag lengths.
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

        // 9F6E (ECDSA s) omitted — terminal rejects non-standard tag lengths

        // Store as tag 77 and use existing sendResponse which handles chunking
        EmvTag.setTag((short) 0x0077, tmpBuffer, (short) 0, offset);
        sendResponse(apdu, buf, (short) 0x0077);
    }

    /**
     * Send GENERATE AC response without CDA (no 9F4B).
     * Contact 1st GenAC: 9F27 + 9F36 + 9F26 + 9F10 + 4F + 84 + 5F2D
     *   (extraneous 4F/84/5F2D carry ECDSA s halves for DE55 forwarding).
     * Contact 2nd GenAC: 9F27 + 9F36 + 9F26 + 9F10 only
     *   (spec-clean per EMV Book 3 §6.5.5 Table 14; ECDSA s already
     *   captured by processor on 1st GenAC — no need to re-send and
     *   strict kernels may reject non-standard tags on 2nd GenAC).
     * Contactless: original template path (contactless uses CDA, not this path).
     */
    private void sendGenerateAcResponseNoCda(APDU apdu, byte[] buf, boolean isFirstGenAcCall) {
        if (!isContactInterface) {
            // Contactless: unchanged template path
            sendResponseTemplate(apdu, buf, responseTemplateGenerateAc);
            return;
        }

        // Contact: spec-mandated core tags present on both 1st and 2nd GenAC.
        // ECDSA mapping: r[0:32] → 9F10 (IAD), s[0:8] → 9F26 (AC).
        short offset = (short) 0;

        EmvTag cidTag = EmvTag.findTag((short) 0x9F27);
        if (cidTag != null) { offset = cidTag.copyToArray(tmpBuffer, offset); }

        EmvTag atcTag = EmvTag.findTag((short) 0x9F36);
        if (atcTag != null) { offset = atcTag.copyToArray(tmpBuffer, offset); }

        EmvTag acTag = EmvTag.findTag((short) 0x9F26);     // s[0:8]
        if (acTag != null) { offset = acTag.copyToArray(tmpBuffer, offset); }

        EmvTag iadTag = EmvTag.findTag((short) 0x9F10);    // r[0:32]
        if (iadTag != null) { offset = iadTag.copyToArray(tmpBuffer, offset); }

        // ECDSA s[8:24] and s[24:32] are only emitted on the 1st GenAC — the
        // processor forwards the 1st-GenAC 77 template in ISO 8583 DE55, so
        // on-chain verification already has them. Omitting from 2nd GenAC
        // keeps the response aligned with EMV Book 3 §6.5.5 Table 14.
        if (isFirstGenAcCall) {
            EmvTag aidTag = EmvTag.findTag((short) 0x004F);    // s[8:24]
            if (aidTag != null) { offset = aidTag.copyToArray(tmpBuffer, offset); }

            // 84 (DF Name) double-write with the same s[8:24] bytes.
            // Direct TLV write — don't touch tag store (would corrupt FCI on next SELECT).
            tmpBuffer[offset++] = (byte) 0x84;
            tmpBuffer[offset++] = (byte) 0x10;
            Util.arrayCopyNonAtomic(ecdsaRawSig, (short) 40, tmpBuffer, offset, (short) 16);
            offset += (short) 16;

            EmvTag langTag = EmvTag.findTag((short) 0x5F2D);   // s[24:32]
            if (langTag != null) { offset = langTag.copyToArray(tmpBuffer, offset); }
        }

        EmvTag.setTag((short) 0x0077, tmpBuffer, (short) 0, offset);
        sendResponse(apdu, buf, (short) 0x0077);
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
     * Generate ECDSA P-256 signature at GPO time over ATC || PDOL data.
     * Signs: ATC(2) || storedPdolData(58) = 60 bytes.
     * ATC is pre-increment (N). GenAC will increment to N+1. Verifier subtracts 1.
     * r stored in 9F10 (returned at GenAC), s in 9F6E (delivered via READ RECORD).
     */
    private void generateEcdsaAtGpo() {
        // Get current ATC (pre-increment value)
        EmvTag atcTag = EmvTag.findTag((short) 0x9F36);
        if (atcTag == null) return;

        // Sign: ATC(2) || PDOL data(58)
        ecdsaSignature.init(ecPrivateKey, Signature.MODE_SIGN);
        ecdsaSignature.update(atcTag.getData(), (short) 0, atcTag.getLength());
        short sigLen = ecdsaSignature.sign(storedPdolData, (short) 0, storedPdolLength, ecdsaSigBuffer, (short) 0);

        // Strip DER → raw r||s (64 bytes)
        derToRawSig(ecdsaSigBuffer, (short) 0, sigLen, ecdsaRawSig, (short) 0);

        // Contactless only: r→9F10 (returned at GenAC), s→9F6E (via READ RECORD)
        EmvTag.setTag((short) 0x9F10, ecdsaRawSig, (short) 0, (short) 32);
        EmvTag.setTag((short) 0x9F6E, ecdsaRawSig, (short) 32, (short) 32);
    }

    /**
     * Generate ECDSA P-256 signature at GenAC time over ATC || CDOL data.
     * Contact-only. Signs ATC(2) || CDOL data (typically 58 bytes matching PDOL).
     * ATC here is post-increment (the ATC carried in the GenAC response).
     *
     * Signature is distributed across standard EMV tags that every terminal
     * passes through to DE55:
     *   r[0:32]  → 9F10  (IAD, 32 bytes)
     *   s[0:8]   → 9F26  (Application Cryptogram, 8 bytes — replaces real AC)
     *   s[8:24]  → 4F    (AID, 16 bytes)
     *   s[24:32] → 5F2D  (Language Preference, 8 bytes)
     */
    private void generateEcdsaAtGenAc(byte[] buf, short cdolOffset, short cdolLen) {
        EmvTag atcTag = EmvTag.findTag((short) 0x9F36);
        if (atcTag == null) return;

        ecdsaSignature.init(ecPrivateKey, Signature.MODE_SIGN);
        ecdsaSignature.update(atcTag.getData(), (short) 0, atcTag.getLength());
        short sigLen = ecdsaSignature.sign(buf, cdolOffset, cdolLen, ecdsaSigBuffer, (short) 0);

        derToRawSig(ecdsaSigBuffer, (short) 0, sigLen, ecdsaRawSig, (short) 0);

        // r (32 bytes) → 9F10 (IAD)
        EmvTag.setTag((short) 0x9F10, ecdsaRawSig, (short) 0, (short) 32);
        // s[0:8] → 9F26 (overwrites the AC generated by generateApplicationCryptogram)
        EmvTag.setTag((short) 0x9F26, ecdsaRawSig, (short) 32, (short) 8);
        // s[8:24] → 4F (16 bytes)
        EmvTag.setTag((short) 0x004F, ecdsaRawSig, (short) 40, (short) 16);
        // s[24:32] → 5F2D (8 bytes)
        EmvTag.setTag((short) 0x5F2D, ecdsaRawSig, (short) 56, (short) 8);
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
        offset = (short) (offset + 8);

        // Transaction Data Hash Code (20 bytes)
        // Per EMV Book 2, this hash is over:
        // PDOL data + CDOL1 data + [CDOL2 data] + separator byte + TLV of response tags
        shaMessageDigest.reset();

        if (!BuildConfig.PRODUCTION) { debugHashInputLength = 0; }

        // Transaction Data Hash input, per EMV Book 2 §6.6.2: the card hashes
        // exactly what the terminal sent in PDOL and CDOL, byte-for-byte, with
        // no truncation to a card-internal "expected length" and no zero-padding
        // when the terminal sent less than expected. Pre-F-43/F-44 the applet
        // truncated both to 58 bytes and padded shorter payloads with 0x00 —
        // both guaranteed a TDH mismatch with any terminal that built a DOL of
        // a different length from our profile.

        // 1. Include PDOL data first (cached at GPO time).
        if (storedPdolLength > 0) {
            shaMessageDigest.update(storedPdolData, (short) 0, storedPdolLength);
            if (!BuildConfig.PRODUCTION && (short)(debugHashInputLength + storedPdolLength) <= (short) 256) {
                Util.arrayCopy(storedPdolData, (short) 0, debugHashInput, debugHashInputLength, storedPdolLength);
                debugHashInputLength = (short)(debugHashInputLength + storedPdolLength);
            }
        }

        // 2. Include CDOL data. CDOL1 arrives in the first GENERATE AC; CDOL2
        // arrives in the second (if terminal issues one). We detect CDOL2 by
        // the cached CDOL1 being present AND the current payload differing —
        // simpler and more reliable than the pre-existing `cdolLen == 60`
        // length heuristic (flagged separately as F-53).
        boolean isSecondGenerateAc = (storedCdol1Length > 0) && (cdolLen != storedCdol1Length);

        if (isSecondGenerateAc) {
            // Second GENERATE AC: hash cached CDOL1 first, then the new CDOL2.
            shaMessageDigest.update(storedCdol1Data, (short) 0, storedCdol1Length);
            if (!BuildConfig.PRODUCTION && (short)(debugHashInputLength + storedCdol1Length) <= (short) 256) {
                Util.arrayCopy(storedCdol1Data, (short) 0, debugHashInput, debugHashInputLength, storedCdol1Length);
                debugHashInputLength = (short)(debugHashInputLength + storedCdol1Length);
            }
            if (cdolLen > 0) {
                shaMessageDigest.update(buf, ISO7816.OFFSET_CDATA, cdolLen);
                if (!BuildConfig.PRODUCTION && (short)(debugHashInputLength + cdolLen) <= (short) 256) {
                    Util.arrayCopy(buf, ISO7816.OFFSET_CDATA, debugHashInput, debugHashInputLength, cdolLen);
                    debugHashInputLength = (short)(debugHashInputLength + cdolLen);
                }
            }
        } else {
            // First GENERATE AC: cache CDOL1 for the potential second GenAC,
            // then hash the full payload as received (F-44/F-52). Capped at
            // MAX_DOL_BYTES for safety; terminals sending more than that are
            // outside our support envelope.
            if (cdolLen > 0 && cdolLen <= MAX_DOL_BYTES) {
                Util.arrayCopy(buf, ISO7816.OFFSET_CDATA, storedCdol1Data, (short) 0, cdolLen);
                storedCdol1Length = cdolLen;
            }
            if (cdolLen > 0) {
                shaMessageDigest.update(buf, ISO7816.OFFSET_CDATA, cdolLen);
                if (!BuildConfig.PRODUCTION && (short)(debugHashInputLength + cdolLen) <= (short) 256) {
                    Util.arrayCopy(buf, ISO7816.OFFSET_CDATA, debugHashInput, debugHashInputLength, cdolLen);
                    debugHashInputLength = (short)(debugHashInputLength + cdolLen);
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
        if (responseContentLen >= (short) 256) {
            tmpBuffer[400] = (byte) (responseContentLen & 0xFF);
            shaMessageDigest.update(tmpBuffer, (short) 400, (short) 1);
            if (!BuildConfig.PRODUCTION && debugHashInputLength < (short) 256) {
                debugHashInput[debugHashInputLength] = (byte) (responseContentLen & 0xFF);
                debugHashInputLength = (short)(debugHashInputLength + 1);
            }
        }

        // 4. Include response TLV tags in TDH (EMV Book 2 Section 6.5.1.4)
        // 9F27 (CID) - 1 byte value
        tmpBuffer[400] = (byte) 0x9F;
        tmpBuffer[401] = (byte) 0x27;
        tmpBuffer[402] = (byte) 0x01;
        tmpBuffer[403] = cryptogramInfoData;
        shaMessageDigest.update(tmpBuffer, (short) 400, (short) 4);
        if (!BuildConfig.PRODUCTION && (short)(debugHashInputLength + 4) <= (short) 256) {
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
        if (!BuildConfig.PRODUCTION && (short)(debugHashInputLength + 5) <= (short) 256) {
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
            if (!BuildConfig.PRODUCTION && (short)(debugHashInputLength + 3 + iadLen) <= (short) 256) {
                Util.arrayCopy(tmpBuffer, (short) 400, debugHashInput, debugHashInputLength, (short) (3 + iadLen));
                debugHashInputLength = (short)(debugHashInputLength + 3 + iadLen);
            }
        }

        // 9F4B (SDAD) excluded per EMV Book 2 Section 6.6.3 Step 10

        shaMessageDigest.doFinal(tmpBuffer, (short) 0, (short) 0, tmpBuffer, offset);
        if (!BuildConfig.PRODUCTION && debugHashOutput != null) {
            Util.arrayCopy(tmpBuffer, offset, debugHashOutput, (short) 0, (short) 20);
        }
        offset = (short) (offset + 20);

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
            Util.setShort(tmpBuffer, offset, iter.getTagId());
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

        // PDOL data is at ISO7816.OFFSET_CDATA + 2, length pdolLen.
        // Store PDOL data for CDA Transaction Data Hash calculation (F-43/F-51).
        // Accept up to MAX_DOL_BYTES. If the terminal built a PDOL longer than
        // this, we fall back to "no PDOL cached" rather than truncating — the
        // later TDH step would produce a hash mismatch anyway, so better to
        // surface it as a clean "no PDOL" state than a silent half-hash.
        if (pdolLen > 0 && pdolLen <= MAX_DOL_BYTES) {
            Util.arrayCopy(buf, (short) (ISO7816.OFFSET_CDATA + 2), storedPdolData, (short) 0, pdolLen);
            storedPdolLength = pdolLen;
        } else {
            storedPdolLength = 0;
        }

        // ECDSA signing at GPO — contactless only. Contact signs at GenAC over
        // the CDOL, which carries more transaction context (TVR, UN, etc.).
        // Contactless: sign ATC || PDOL, r→9F10, s→9F6E. Terminal reads 9F6E
        // via READ RECORD (tag 70, per C-2 A.1.165). 9F10 returned in CDA GenAC.
        // Note: ATC here is pre-increment (N). GenAC increments to N+1. Verifier subtracts 1.
        if (!isContactInterface && ecPrivateKeyLoaded && storedPdolLength > 0) {
            generateEcdsaAtGpo();
        }

        // Full EMV mode for both contact and contactless:
        // Return AIP + AFL, terminal will do READ RECORD then GENERATE AC
        sendResponseTemplate(apdu, buf, responseTemplateGetProcessingOptions);
    }

    /* qVSDC removed — full EMV mode for all contactless transactions.
     * ECDSA signing happens at GPO time via generateEcdsaAtGpo().
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

            case CMD_GET_RESPONSE:
                processGetResponse(apdu, buf);
                break;
            default:
                EmvApplet.logAndThrow(ISO7816.SW_INS_NOT_SUPPORTED);
        }

    }
}
