package se.ermia.netpipe.crypto;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * SHA-256 digest wrapper for the Secure NetPipe handshake protocol.
 *
 * <p>Skeleton provided by Peter Sjödin (KTH/IK2206).
 * Implementation by Ermia Ghaffari.</p>
 *
 * @see <a href="https://www.baeldung.com/sha-256-hashing-java">SHA-256 Hashing in Java</a>
 */
@SuppressWarnings("PMD.AvoidMessageDigestField")
public class HandshakeDigest {

    private static final String ALGORITHM = "SHA-256";
    private final MessageDigest messageDigest;

    /**
     * Initialise a new SHA-256 digest.
     */
    public HandshakeDigest() {
        try {
            this.messageDigest = MessageDigest.getInstance(ALGORITHM);
        } catch (NoSuchAlgorithmException e) {
            // SHA-256 is required by every conforming JRE
            throw new AssertionError("SHA-256 not available", e);
        }
    }

    /**
     * Feed data into the digest.
     */
    public void update(byte[] input) {
        messageDigest.update(input);
    }

    /**
     * Compute and return the final digest, resetting the internal state.
     */
    public byte[] digest() {
        return messageDigest.digest();
    }

    /**
     * Constant-time comparison of two digests to prevent timing attacks.
     */
    public static boolean isEqual(byte[] a, byte[] b) {
        return MessageDigest.isEqual(a, b);
    }
}
