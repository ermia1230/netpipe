import java.io.FileInputStream;
import java.io.IOException;
import java.security.cert.CertificateException;
import java.util.Base64;
/**
 * This utility class, {@code Utils}, provides helper methods for handling 
 * certificates required during the handshake process in a secure communication protocol.
 * Resources used:
 * - https://www.baeldung.com/java-base64-encode-and-decode
 *
 * @author Ermia Ghaffari
 */
public class Utils {
    /**
     * Loads a certificate from the specified file path, encodes it into a Base64 string 
     * for text-based transmission.
     * @param certificateFilePath The file path to the certificate file in PEM or DER format.
     * @return A Base64-encoded string representing the certificate.
     * @throws CertificateException
     */
    public static String certificateEncode(String certificatePath) throws IOException, CertificateException{
        try{
        FileInputStream file = new FileInputStream(certificatePath);
        HandshakeCertificate certificate = new HandshakeCertificate(file);
        byte[] certBytes = certificate.getBytes();
        return Base64.getEncoder().encodeToString(certBytes);
        }catch(IOException exception){
            throw exception;
        }
    }
    /**
     * Loads a certificate from the specified file path, encodes it into a Base64 string 
     * for text-based transmission.
     * @param certificateFilePath The file path to the certificate file in PEM or DER format.
     * @return A Base64-encoded string representing the certificate.
     * @throws CertificateException
     */

    public static HandshakeCertificate certificateDecode(String serverCertificateEncoded) throws Exception{
        try{
        byte[] serverCertificateBytes = Base64.getDecoder().decode(serverCertificateEncoded);
        HandshakeCertificate serverCertificate = new HandshakeCertificate(serverCertificateBytes);
        return serverCertificate;
        }catch(Exception exception){
            throw exception;
        }
    }
}
