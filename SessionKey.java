
import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.security.NoSuchAlgorithmException;

/**
 * This code is written by Ermia Ghaffari, and the skeleton of the code is provided by Peter Sjodin
 * at KTH. Additionally, there is a class called {@code SessionKeyTest} which tests the 
 * functionality of the written code. 
 * Note that the following resources were used to write the code:
 * 1- https://docs.oracle.com/javase/8/docs/technotes/guides/security/crypto/CryptoSpec.html#Security
 * 2- https://docs.oracle.com/javase/8/docs/technotes/guides/security/crypto/CryptoSpec.html#KeyGenerator
 * This class represents a session key.
 * It can either generate a random key of a specified length or use a provided byte array to create the key.
 */

class SessionKey {
    private SecretKey secret;

    /*
     * Constructor to create a secret key of a given length
     */
    public SessionKey(Integer length) throws NoSuchAlgorithmException {
        try{
            KeyGenerator key = KeyGenerator.getInstance("AES");
            key.init(length);
            this.secret = key.generateKey();
        }catch(NoSuchAlgorithmException exception){
            throw exception;
        }
    }

    /*
     * Constructor to create a secret key from key material
     * given as a byte array
     */
    public SessionKey(byte[] keybytes) {
        try{
            this.secret = new SecretKeySpec(keybytes, "AES");           
        }catch (Exception exception){
            throw exception;
        }
    }

    /*
     * Return the secret key
     */
    public SecretKey getSecretKey() {
        return this.secret;
    }

    /*
     * Return the secret key encoded as a byte array
     */
    public byte[] getKeyBytes() {
        return this.secret.getEncoded();
    }
    /* 
    public static void main(String[] args) {
        try {
            int length = 128;
            SessionKey sessionKey = new SessionKey(length);
            byte[] keyBytes = sessionKey.getKeyBytes();
            SessionKey KeyBytes = new SessionKey(keyBytes);
            byte[] BytesNewKey = KeyBytes.getKeyBytes();
            boolean areKeysSame = Arrays.equals(keyBytes, BytesNewKey);
            System.out.println("Are both keys the same? " + areKeysSame);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    */
}

