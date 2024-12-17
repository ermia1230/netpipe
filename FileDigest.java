import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Base64;

/**
 * This code is written by Ermia Ghaffari, and the skeleton of the code is provided by Peter Sjödin
 * at KTH. Additionally, there is a class called {@code HandshakeDigestTest} which tests the 
 * functionality of the written code.
 * 
 * These resources were used in order to get a better insight and read files in a bite array and
 * to print the hash as a Base64-encoded string. 
 * https://howtodoinjava.com/java/io/read-file-content-into-byte-array
 * https://stackoverflow.com/questions/62579685/converting-a-hash-to-base64-encoding-should-i-be-storing-the-hash-as-a-string-o
 * 
 * This code computes a file digest using the HandshakeDigest class and prints the 
 * resulting hash as a Base64-encoded string.
 */

public class FileDigest {
    public static void main(String[] args) throws Exception {
        if (args.length == 0) {
            System.out.println(" No filename provided.");
            System.exit(1);
        }
        String filename = args[0];
        try {
            System.out.println(generateFileHash(filename));   
        } catch (Exception exception) {
            throw exception;           
          
        }
    }
    private static String generateFileHash(String filename) throws Exception {
        HandshakeDigest handshakeDigest = new HandshakeDigest();
        Path filePath = Paths.get(filename);
        byte[] fileContent = Files.readAllBytes(filePath);
        handshakeDigest.update(fileContent);
        byte[] digestBytes = handshakeDigest.digest();
        return Base64.getEncoder().encodeToString(digestBytes);
    }
}
