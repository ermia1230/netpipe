package se.ermia.netpipe.crypto;

import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import javax.crypto.Cipher;
import se.ermia.netpipe.exception.CryptoException;

/**
 * RSA encryption and decryption for the handshake phase.
 *
 * <p>Used to encrypt/decrypt session keys, IVs, timestamps, and digest signatures
 * exchanged during the handshake. Supports public-key operations (from an X.509
 * certificate) and private-key operations (from PKCS8/DER encoded bytes).</p>
 *
 * <p>Skeleton provided by Peter Sjödin (KTH/IK2206).
 * Implementation by Ermia Ghaffari.</p>
 *
 * <p><strong>Educational note:</strong> This implementation uses RSA with default
 * PKCS1v1.5 padding for compatibility with the original protocol design. Production
 * systems should use OAEP padding ({@code RSA/ECB/OAEPWithSHA-256AndMGF1Padding})
 * and proper {@link java.security.Signature} API for signing.</p>
 *
 * @see <a href="https://docs.oracle.com/javase/8/docs/api/javax/crypto/Cipher.html">Cipher API</a>
 */
public class HandshakeCrypto {

    private static final String ALGORITHM = "RSA";

    private final PrivateKey privateKey;
    private final PublicKey publicKey;

    /**
     * Create an instance using a public key from an X.509 certificate.
     * Used for encrypting data that only the certificate holder can decrypt,
     * or for verifying signatures.
     */
    public HandshakeCrypto(HandshakeCertificate handshakeCertificate) {
        this.publicKey = handshakeCertificate.getCertificate().getPublicKey();
        this.privateKey = null;
    }

    /**
     * Create an instance using a private key in PKCS8/DER format.
     * Used for decrypting data encrypted with the corresponding public key,
     * or for creating signatures.
     *
     * @param keyBytes PKCS8-encoded private key bytes
     * @throws CryptoException if the key material is invalid
     */
    public HandshakeCrypto(byte[] keyBytes) throws CryptoException {
        try {
            KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM);
            PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
            this.privateKey = keyFactory.generatePrivate(spec);
            this.publicKey = null;
        } catch (GeneralSecurityException e) {
            throw new CryptoException("Failed to load RSA private key from PKCS8 bytes", e);
        }
    }

    /**
     * Decrypt ciphertext using the available key.
     * If a public key is set, decrypts with public key (signature verification).
     * If a private key is set, decrypts with private key.
     *
     * @param ciphertext the data to decrypt
     * @return the decrypted plaintext
     * @throws CryptoException if decryption fails
     */
    public byte[] decrypt(byte[] ciphertext) throws CryptoException {
        try {
            // Create a new Cipher instance per call for thread safety
            Cipher cipher = Cipher.getInstance(ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, getActiveKey());
            return cipher.doFinal(ciphertext);
        } catch (GeneralSecurityException e) {
            throw new CryptoException("RSA decryption failed", e);
        }
    }

    /**
     * Encrypt plaintext using the available key.
     * If a public key is set, encrypts with public key.
     * If a private key is set, encrypts with private key (signing).
     *
     * @param plaintext the data to encrypt
     * @return the ciphertext
     * @throws CryptoException if encryption fails
     */
    public byte[] encrypt(byte[] plaintext) throws CryptoException {
        try {
            Cipher cipher = Cipher.getInstance(ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, getActiveKey());
            return cipher.doFinal(plaintext);
        } catch (GeneralSecurityException e) {
            throw new CryptoException("RSA encryption failed", e);
        }
    }

    private java.security.Key getActiveKey() {
        return (publicKey != null) ? publicKey : privateKey;
    }
}
