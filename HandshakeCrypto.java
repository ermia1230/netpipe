import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

/**
 * This code is written by Ermia Ghaffari, with the skeleton provided by Peter
 * Sjodin at KTH.
 * The {@code HandshakeCrypto} class is responsible for encryption and
 * decryption
 * using public and private keys during handshake operations.
 * 
 * The {@code HandshakeCryptoTest} class is used to verify the functionality of
 * this code.
 * 
 * References for insights into certificate and cryptographic operations in
 * Java:
 * https://docs.oracle.com/javase/8/docs/api/javax/crypto/Cipher.html
 *
 * This class provides constructors for setting up cryptographic operations with
 * public or
 * private keys, and methods for encryption and decryption of byte arrays.
 */

public class HandshakeCrypto {

	private PrivateKey privateKey;
	private PublicKey publicKey;
	private Cipher cipher;
	private final String algorithm = "RSA";

	/*
	 * Constructor to create an instance for encryption/decryption with a public
	 * key.
	 * The public key is given as a X509 certificate.
	 */
	public HandshakeCrypto(HandshakeCertificate handshakeCertificate) {
		try {
			this.publicKey = handshakeCertificate.getCertificate().getPublicKey();
		} catch (Exception exception) {
			throw exception;
		}
	}

	/*
	 * Constructor to create an instance for encryption/decryption with a private
	 * key.
	 * The private key is given as a byte array in PKCS8/DER format.
	 */
	public HandshakeCrypto(byte[] keybytes) throws GeneralSecurityException {
		try {
			KeyFactory keyFactory = KeyFactory.getInstance(algorithm);
			PKCS8EncodedKeySpec PKCS8 = new PKCS8EncodedKeySpec(keybytes);
			this.privateKey = keyFactory.generatePrivate(PKCS8);
		} catch (NoSuchAlgorithmException | InvalidKeySpecException exception) {
			throw exception;
		}
	}

	/*
	 * Decrypt byte array with the key, return result as a byte array
	 */
	public byte[] decrypt(byte[] ciphertext) throws GeneralSecurityException {
		try {
			this.cipher = Cipher.getInstance(algorithm);
			if (publicKey != null) {
				this.cipher.init(Cipher.DECRYPT_MODE, publicKey);
			} else {
				this.cipher.init(Cipher.DECRYPT_MODE, privateKey);
			}
			return this.cipher.doFinal(ciphertext);
		} catch (NoSuchAlgorithmException | IllegalBlockSizeException | NoSuchPaddingException
				| InvalidKeyException | BadPaddingException exception) {
			throw exception;
		}
	}

	/*
	 * Encrypt byte array with the key, return result as a byte array
	 */
	public byte[] encrypt(byte[] plaintext) throws GeneralSecurityException {
		try {
			this.cipher = Cipher.getInstance(algorithm);
			if (publicKey != null) {
				this.cipher.init(Cipher.ENCRYPT_MODE, publicKey);
			} else {
				this.cipher.init(Cipher.ENCRYPT_MODE, privateKey);
			}
			return cipher.doFinal(plaintext);
		} catch (NoSuchAlgorithmException | IllegalBlockSizeException | NoSuchPaddingException
				| InvalidKeyException | BadPaddingException exception) {
			throw exception;
		}
	}
}
