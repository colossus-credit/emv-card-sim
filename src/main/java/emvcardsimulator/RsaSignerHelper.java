package emvcardsimulator;

import javacardx.crypto.Cipher;
import javacard.security.RSAPrivateKey;

/**
 * Generated helper — wraps javacardx.crypto.Cipher for raw RSA operations.
 * Built with has_rsa_cipher=true (card supports javacardx.crypto).
 */
class RsaSignerHelper {
    private final Cipher cipher;

    RsaSignerHelper() {
        cipher = Cipher.getInstance(Cipher.ALG_RSA_NOPAD, false);
    }

    void doFinal(RSAPrivateKey key, byte[] in, short inOff, short inLen, byte[] out, short outOff) {
        cipher.init(key, Cipher.MODE_DECRYPT);
        cipher.doFinal(in, inOff, inLen, out, outOff);
    }
}
