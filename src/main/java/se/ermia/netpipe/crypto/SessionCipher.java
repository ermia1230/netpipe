package se.ermia.netpipe.crypto;

import java.io.InputStream;
import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.spec.IvParameterSpec;
import se.ermia.netpipe.exception.CryptoException;

/**
 * AES-128-CTR session cipher for encrypted bidirectional communication.
 *
 * <p>Skeleton provided by Peter Sjödin (KTH/IK2206).
 * Implementation by Ermia Ghaffari.</p>
 *
 * <p>Uses AES in CTR (Counter) mode with NoPadding, which turns AES into a
 * stream cipher suitable for real-time bidirectional data forwarding.</p>
 *
 * @see <a href="https://www.youtube.com/watch?v=LtUU8Q3rgjM">AES Cipher Tutorial</a>
 */
public class SessionCipher {

    private static final String CIPHER_SPEC = "AES/CTR/NoPadding";
    private static final int IV_LENGTH_BYTES = 16;

    private final SessionKey key;
    private final byte[] iv;
    private final Cipher encryptCipher;
    private final Cipher decryptCipher;

    /**
     * Create a SessionCipher with a new random IV.
     *
     * @param key the AES session key
     * @throws CryptoException if cipher initialisation fails
     */
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    public SessionCipher(SessionKey key) throws CryptoException {
        this.key = key;
        this.iv = new byte[IV_LENGTH_BYTES];
        SECURE_RANDOM.nextBytes(this.iv);
        try {
            this.encryptCipher = createCipher(Cipher.ENCRYPT_MODE);
            this.decryptCipher = createCipher(Cipher.DECRYPT_MODE);
        } catch (GeneralSecurityException e) {
            throw new CryptoException("Failed to initialise AES-CTR cipher", e);
        }
    }

    /**
     * Create a SessionCipher with a provided IV.
     *
     * @param key     the AES session key
     * @param ivBytes the initialisation vector (must be 16 bytes)
     * @throws CryptoException if the IV is invalid or cipher initialisation fails
     */
    public SessionCipher(SessionKey key, byte[] ivBytes) throws CryptoException {
        if (ivBytes == null || ivBytes.length != IV_LENGTH_BYTES) {
            throw new CryptoException(
                    "IV must be " + IV_LENGTH_BYTES + " bytes, got "
                    + (ivBytes == null ? "null" : ivBytes.length));
        }
        this.key = key;
        this.iv = ivBytes.clone();
        try {
            this.encryptCipher = createCipher(Cipher.ENCRYPT_MODE);
            this.decryptCipher = createCipher(Cipher.DECRYPT_MODE);
        } catch (GeneralSecurityException e) {
            throw new CryptoException("Failed to initialise AES-CTR cipher", e);
        }
    }

    /**
     * Return the session key.
     */
    public SessionKey getSessionKey() {
        return key;
    }

    /**
     * Return a copy of the IV.
     */
    public byte[] getIVBytes() {
        return iv.clone();
    }

    /**
     * Wrap an output stream for encrypted writing.
     */
    public CipherOutputStream openEncryptedOutputStream(OutputStream os) {
        return new CipherOutputStream(os, encryptCipher);
    }

    /**
     * Wrap an input stream for decrypted reading.
     */
    public CipherInputStream openDecryptedInputStream(InputStream is) {
        return new CipherInputStream(is, decryptCipher);
    }

    private Cipher createCipher(int mode) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance(CIPHER_SPEC);
        cipher.init(mode, key.getSecretKey(), new IvParameterSpec(iv));
        return cipher;
    }
}
