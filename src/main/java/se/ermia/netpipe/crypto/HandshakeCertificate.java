package se.ermia.netpipe.crypto;

import se.ermia.netpipe.exception.CertificateValidationException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;

/**
 * X.509 certificate handling for the Secure NetPipe handshake.
 *
 * <p>Parses certificates from PEM/DER input, verifies them against a CA,
 * and extracts subject attributes (CN, email).</p>
 *
 * <p>Skeleton provided by Peter Sjödin (KTH/IK2206).
 * Implementation by Ermia Ghaffari.</p>
 *
 * @see <a href="https://docs.oracle.com/en/java/javase/17/docs/api/java.base/java/security/cert/CertificateFactory.html">
 *     CertificateFactory API</a>
 */
public class HandshakeCertificate {

    private static final Logger log = LoggerFactory.getLogger(HandshakeCertificate.class);
    private static final String CERTIFICATE_TYPE = "X.509";

    private final X509Certificate certificate;

    /**
     * Create a certificate from data on an input stream (PEM or DER format).
     */
    public HandshakeCertificate(InputStream instream) throws CertificateException {
        CertificateFactory factory = CertificateFactory.getInstance(CERTIFICATE_TYPE);
        this.certificate = (X509Certificate) factory.generateCertificate(instream);
    }

    /**
     * Create a certificate from its encoded byte representation (DER format).
     */
    public HandshakeCertificate(byte[] certBytes) throws CertificateException {
        CertificateFactory factory = CertificateFactory.getInstance(CERTIFICATE_TYPE);
        this.certificate = (X509Certificate) factory.generateCertificate(
                new ByteArrayInputStream(certBytes));
    }

    /**
     * Return the DER-encoded representation of this certificate.
     */
    public byte[] getBytes() throws CertificateEncodingException {
        return certificate.getEncoded();
    }

    /**
     * Return the underlying X.509 certificate object.
     */
    public X509Certificate getCertificate() {
        return certificate;
    }

    /**
     * Cryptographically verify this certificate against a CA certificate,
     * and check that the certificate is currently valid (not expired, not yet valid).
     *
     * @param caCert the certificate authority's certificate
     * @throws CertificateValidationException if verification fails for any reason
     */
    public void verify(HandshakeCertificate caCert) throws CertificateValidationException {
        try {
            // Verify the cryptographic signature
            PublicKey caPublicKey = caCert.getCertificate().getPublicKey();
            certificate.verify(caPublicKey);

            // Verify the certificate is currently valid (not expired)
            certificate.checkValidity();

            log.info("Certificate verified: CN={}", getCN());
        } catch (CertificateExpiredException e) {
            throw new CertificateValidationException(
                    "Certificate has expired: " + certificate.getNotAfter(), e);
        } catch (CertificateNotYetValidException e) {
            throw new CertificateValidationException(
                    "Certificate is not yet valid: " + certificate.getNotBefore(), e);
        } catch (CertificateException | NoSuchAlgorithmException | InvalidKeyException
                 | SignatureException | NoSuchProviderException e) {
            throw new CertificateValidationException(
                    "Certificate verification failed", e);
        }
    }

    /**
     * Extract the Common Name (CN) from the certificate subject.
     *
     * @return the CN value, or {@code null} if not present
     */
    public String getCN() {
        String dn = certificate.getSubjectX500Principal().getName();
        int index = dn.indexOf("CN=");
        if (index == -1) {
            return null;
        }
        int start = index + 3;
        int end = dn.indexOf(',', start);
        if (end == -1) {
            end = dn.length();
        }
        return dn.substring(start, end).trim().replace("\\", "");
    }

    /**
     * Extract the email address from the certificate subject.
     *
     * <p>Parses the legacy {@code EMAILADDRESS} attribute from the subject DN.
     * The deprecated {@code getSubjectDN()} method is used because
     * {@code getSubjectX500Principal()} does not reliably expose email fields
     * across all certificate formats.</p>
     *
     * @return the email address, or {@code null} if not present
     */
    @SuppressWarnings("deprecation")
    public String getEmail() {
        String dn = certificate.getSubjectDN().getName();
        int index = dn.indexOf("EMAILADDRESS=");
        if (index == -1) {
            return null;
        }
        int start = index + 13;
        int end = dn.indexOf(',', start);
        if (end == -1) {
            end = dn.length();
        }
        return dn.substring(start, end).trim().replace("\\", "");
    }
}
