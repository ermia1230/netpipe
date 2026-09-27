package se.ermia.netpipe.crypto;

import se.ermia.netpipe.exception.CryptoException;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.spec.IvParameterSpec;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;

/**
 * AES-128-CTR session cipher for encrypted bidirectional communication.
 *
 * <p>Uses AES in CTR (Counter) mode with NoPadding. To prevent keystream reuse
 * (two-time pad vulnerability) in bidirectional communication, separate IVs are
 * derived for client-to-server and server-to-client directions by toggling the
 * highest-order byte of the base IV.</p>
 *
 * <p>Skeleton provided by Peter Sjödin (KTH/IK2206).
 * Implementation and directional IV security fix by Ermia Ghaffari.</p>
 */
public class SessionCipher {

    private static final String CIPHER_SPEC = "AES/CTR/NoPadding";
    private static final int IV_LENGTH_BYTES = 16;
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    private final SessionKey key;
    private final byte[] iv;
    private final Cipher encryptCipher;
    private final Cipher decryptCipher;

    /**
     * Create a SessionCipher with a new random IV (client-side default).
     *
     * @param key the AES session key
     * @throws CryptoException if cipher initialisation fails
     */
    public SessionCipher(SessionKey key) throws CryptoException {
        this(key, generateRandomIV(), false);
    }

    /**
     * Create a SessionCipher with a provided IV (client-side default).
     */
    public SessionCipher(SessionKey key, byte[] ivBytes) throws CryptoException {
        this(key, ivBytes, false);
    }

    /**
     * Create a SessionCipher specifying whether this endpoint is the server.
     *
     * @param key      the AES session key
     * @param ivBytes  the base initialisation vector (16 bytes)
     * @param isServer {@code true} if server side, {@code false} if client side
     * @throws CryptoException if IV is invalid or cipher initialisation fails
     */
    public SessionCipher(SessionKey key, byte[] ivBytes, boolean isServer) throws CryptoException {
        if (ivBytes == null || ivBytes.length != IV_LENGTH_BYTES) {
            throw new CryptoException(
                    "IV must be " + IV_LENGTH_BYTES + " bytes, got "
                    + (ivBytes == null ? "null" : ivBytes.length));
        }
        this.key = key;
        this.iv = ivBytes.clone();

        // Derive distinct directional IVs to prevent CTR keystream reuse
        byte[] ivClientToServer = ivBytes.clone();
        byte[] ivServerToClient = ivBytes.clone();
        ivServerToClient[0] ^= (byte) 0x80;

        byte[] encIV = isServer ? ivServerToClient : ivClientToServer;
        byte[] decIV = isServer ? ivClientToServer : ivServerToClient;

        try {
            this.encryptCipher = createCipher(Cipher.ENCRYPT_MODE, encIV);
            this.decryptCipher = createCipher(Cipher.DECRYPT_MODE, decIV);
        } catch (GeneralSecurityException e) {
            throw new CryptoException("Failed to initialise AES-CTR cipher", e);
        }
    }

    private static byte[] generateRandomIV() {
        byte[] newIv = new byte[IV_LENGTH_BYTES];
        SECURE_RANDOM.nextBytes(newIv);
        return newIv;
    }

    /**
     * Return the session key.
     */
    public SessionKey getSessionKey() {
        return key;
    }

    /**
     * Return a copy of the base IV.
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

    private Cipher createCipher(int mode, byte[] ivParameter) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance(CIPHER_SPEC);
        cipher.init(mode, key.getSecretKey(), new IvParameterSpec(ivParameter));
        return cipher;
    }
}
