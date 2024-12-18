import java.io.InputStream;
import java.io.OutputStream;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.spec.IvParameterSpec;
/**
 * This code is written by Ermia Ghaffari, and the skeleton of the code is provided by Peter Sjodin
 * at KTH. Additionally, there is a class called {@code SessionCipherTest} which tests the 
 * functionality of the written code. 
 * I have watched the youtube vodeo below to code this assginemnt:
 * https://www.youtube.com/watch?v=LtUU8Q3rgjM
 * I have also looked at:
 * https://stackoverflow.com/questions/29267435/generating-random-iv-for-aes-in-java
 * This class represents a session cipher.
 */

public class SessionCipher {
    private SessionKey key;
    private byte [] IV;
    private int numberOfBits = 128;
    private int bytesInBits = 8;
    private Cipher encryptCipher;
    private Cipher decryptCipher;
    private final String cipherConfig = "AES/CTR/NoPadding";

    /*
     * Constructor to create a SessionCipher from a SessionKey. The IV is
     * created automatically.
     */
    public SessionCipher(SessionKey key) throws Exception {
        try{
        this.key = key;
        this.IV = new byte[numberOfBits/bytesInBits];
        generateIV();
        encryptCipher = Cipher.getInstance(cipherConfig);
        encryptCipher.init(Cipher.ENCRYPT_MODE, key.getSecretKey(), new IvParameterSpec(this.IV));

        decryptCipher = Cipher.getInstance(cipherConfig);
        decryptCipher.init(Cipher.DECRYPT_MODE, key.getSecretKey(), new IvParameterSpec(this.IV));
        }catch(Exception exception){
           throw exception;
        }

    }

    private void generateIV(){
        //Random random = new Random();
        //random.nextBytes(IV);
        try{
            SecureRandom random = new SecureRandom();
            random.nextBytes(this.IV);

        }catch(Exception exception){
            throw exception;
        }
    }

    /*
     * Constructor to create a SessionCipher from a SessionKey and an IV,
     * given as a byte array.
     */

    public SessionCipher(SessionKey key, byte[] ivbytes) throws Exception {
        if (ivbytes.length != 16) {
            throw new IllegalArgumentException("IV should be 128 bits!");
        }
        try{
            this.key = key;
            this.IV = ivbytes;
            encryptCipher = Cipher.getInstance(cipherConfig);
            encryptCipher.init(Cipher.ENCRYPT_MODE, key.getSecretKey(), new IvParameterSpec(this.IV));

            decryptCipher = Cipher.getInstance(cipherConfig);
            decryptCipher.init(Cipher.DECRYPT_MODE, key.getSecretKey(), new IvParameterSpec(this.IV));
        }catch(Exception exception){
            throw exception;
        }
    }

    /*
     * Return the SessionKey
     */
    public SessionKey getSessionKey() {
        return this.key;
    }

    /*
     * Return the IV as a byte array
     */
    public byte[] getIVBytes() {
        return this.IV;
    }

    /*
     * Attach OutputStream to which encrypted data will be written.
     * Return result as a CipherOutputStream instance.
     */
    CipherOutputStream openEncryptedOutputStream(OutputStream os) throws Exception {
        try {
            return new CipherOutputStream(os, encryptCipher);
        } catch (Exception e) {
            throw new Exception("Error", e);
        }
    }

    /*
     * Attach InputStream from which decrypted data will be read.
     * Return result as a CipherInputStream instance.
     */

    CipherInputStream openDecryptedInputStream(InputStream inputstream) throws Exception {
        try {
            return new CipherInputStream(inputstream, decryptCipher);
        } catch (Exception e) {
            throw new Exception("Error", e);
        }
    }
}
