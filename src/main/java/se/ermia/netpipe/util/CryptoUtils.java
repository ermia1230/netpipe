package se.ermia.netpipe.util;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.cert.CertificateException;
import java.util.Base64;
import se.ermia.netpipe.crypto.HandshakeCertificate;
import se.ermia.netpipe.crypto.HandshakeCrypto;
import se.ermia.netpipe.exception.CryptoException;

/**
 * Utility methods for certificate encoding/decoding and private key loading.
 *
 * @author Ermia Ghaffari
 * @see <a href="https://www.baeldung.com/java-base64-encode-and-decode">Base64 in Java</a>
 */
public final class CryptoUtils {

    private CryptoUtils() {
        // Utility class
    }

    /**
     * Load a certificate from a file and return its Base64-encoded DER representation.
     *
     * @param certPath path to a PEM or DER certificate file
     * @return Base64-encoded certificate bytes
     */
    public static String encodeCertificate(String certPath) throws IOException, CertificateException {
        try (InputStream is = Files.newInputStream(Paths.get(certPath))) {
            HandshakeCertificate cert = new HandshakeCertificate(is);
            return Base64.getEncoder().encodeToString(cert.getBytes());
        }
    }

    /**
     * Decode a Base64-encoded certificate string back into a {@link HandshakeCertificate}.
     *
     * @param base64Cert the Base64-encoded certificate
     * @return the decoded certificate
     */
    public static HandshakeCertificate decodeCertificate(String base64Cert) throws CertificateException {
        byte[] certBytes = Base64.getDecoder().decode(base64Cert);
        return new HandshakeCertificate(certBytes);
    }

    /**
     * Load a PKCS8/DER-encoded RSA private key from a file.
     *
     * @param keyPath path to the private key file
     * @return a HandshakeCrypto instance configured with the private key
     */
    public static HandshakeCrypto loadPrivateKey(String keyPath) throws IOException, CryptoException {
        try (InputStream is = Files.newInputStream(Paths.get(keyPath));
             ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
            byte[] buffer = new byte[2048];
            int bytesRead;
            while ((bytesRead = is.read(buffer)) != -1) {
                baos.write(buffer, 0, bytesRead);
            }
            return new HandshakeCrypto(baos.toByteArray());
        }
    }

    /**
     * Load a CA certificate from a file.
     *
     * @param caCertPath path to the CA certificate file
     * @return the CA certificate
     */
    public static HandshakeCertificate loadCACertificate(String caCertPath)
            throws IOException, CertificateException {
        try (InputStream is = Files.newInputStream(Paths.get(caCertPath))) {
            return new HandshakeCertificate(is);
        }
    }
}
