import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * This code is written by Ermia Ghaffari, and the skeleton of the code is provided by Peter Sjödin
 * at KTH. Additionally, there is a class called {@code HandshakeDigestTest} which tests the 
 * functionality of the written code.
 * These resources were used in order to get a better insight:
 * https://www.baeldung.com/sha-256-hashing-java
 * https://stackoverflow.com/questions/5531455/how-to-hash-some-string-with-sha-256-in-java 
 *
 * This class represents a Handshake Digest.
 */
public class HandshakeDigest {
    private MessageDigest messageDigest;
    private final String algorithm = "SHA-256";

    /*
     * Constructor -- initialise a digest for SHA-256
     */

    public HandshakeDigest() throws NoSuchAlgorithmException {
        try{
            this.messageDigest = MessageDigest.getInstance(algorithm);
        }catch(NoSuchAlgorithmException exception){
            throw exception;
        }
    }

    /*
     * Update digest with input data
     */
    public void update(byte[] input) {
        messageDigest.update(input);
    }

    /*
     * Compute final digest
     */
    public byte[] digest() {
        return messageDigest.digest();
    }
};
