package se.ermia.netpipe.crypto;

import java.security.NoSuchAlgorithmException;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

/**
 * AES session key generation and reconstruction.
 *
 * <p>Skeleton provided by Peter Sjödin (KTH/IK2206).
 * Implementation by Ermia Ghaffari.</p>
 *
 * @see <a href="https://docs.oracle.com/javase/8/docs/technotes/guides/security/crypto/CryptoSpec.html#KeyGenerator">
 *     Java KeyGenerator Documentation</a>
 */
public class SessionKey {

    private static final String ALGORITHM = "AES";
    private final SecretKey secret;

    /**
     * Generate a new random AES key of the given bit length.
     *
     * @param lengthInBits key length in bits (e.g. 128, 192, 256)
     */
    public SessionKey(int lengthInBits) {
        try {
            KeyGenerator keyGen = KeyGenerator.getInstance(ALGORITHM);
            keyGen.init(lengthInBits);
            this.secret = keyGen.generateKey();
        } catch (NoSuchAlgorithmException e) {
            throw new AssertionError("AES not available", e);
        }
    }

    /**
     * Reconstruct a session key from raw key bytes.
     *
     * @param keyBytes the encoded key material
     * @throws IllegalArgumentException if keyBytes is null or has an invalid length
     */
    public SessionKey(byte[] keyBytes) {
        if (keyBytes == null || (keyBytes.length != 16 && keyBytes.length != 24 && keyBytes.length != 32)) {
            throw new IllegalArgumentException(
                    "Invalid AES key length: " + (keyBytes == null ? "null" : keyBytes.length + " bytes")
                    + " (must be 16, 24, or 32)");
        }
        this.secret = new SecretKeySpec(keyBytes, ALGORITHM);
    }

    /**
     * Return the underlying {@link SecretKey}.
     */
    public SecretKey getSecretKey() {
        return secret;
    }

    /**
     * Return the key material as a byte array.
     */
    public byte[] getKeyBytes() {
        return secret.getEncoded();
    }
}
