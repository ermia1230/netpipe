import java.io.ByteArrayInputStream;
import java.io.InputStream;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
/**
 * This code is written by Ermia Ghaffari, and the skeleton of the code was provided by Peter Sjodin at KTH.
 * Additionally, the {@code HandshakeCertificateTest} class is used to test the functionality of this code.
 * The following resources were referenced to gain insight into certificate handling in Java:
 * - https://docs.oracle.com/en/java/javase/17/docs/api/java.base/java/security/cert/CertificateFactory.html
 * - https://stackoverflow.com/questions/3389143/generate-x509certificate-from-byte
 * - https://stackoverflow.com/questions/58135268/how-to-verify-the-signature-of-a-x509-certificate
 * - https://stackoverflow.com/questions/2914521/how-to-extract-cn-from-x509certificate-in-java
 * This class represents a certificate used in a handshake. 
 * HandshakeCertificate class represents X509 certificates exchanged
 * during initial handshake
 */
public class HandshakeCertificate {
    private final String certificateType = "X.509";
    private X509Certificate certificate;

    /*
     * Constructor to create a certificate from data read on an input stream.
     * The data is DER-encoded, in binary or Base64 encoding (PEM format).
     */

    HandshakeCertificate(InputStream instream) throws CertificateException {
        try{
        CertificateFactory x509CertificateFactory = CertificateFactory.getInstance(certificateType);
        this.certificate = (X509Certificate) x509CertificateFactory.generateCertificate(instream);
        }catch(CertificateException exception){
           throw exception;
        }
    }

    /*
     * Constructor to create a certificate from its encoded representation
     * given as a byte array
     */
    HandshakeCertificate(byte[] certbytes) throws CertificateException {
        try{
            CertificateFactory x509CertificateFactory = CertificateFactory.getInstance(certificateType);
            this.certificate = (X509Certificate) x509CertificateFactory.generateCertificate(new ByteArrayInputStream(certbytes){
            });
            }catch(CertificateException exception){
                throw exception;
            }
    }

    /*
     * Return the encoded representation of certificate as a byte array
     */
    public byte[] getBytes() throws CertificateEncodingException {
        try{
        return this.certificate.getEncoded();
        }catch(CertificateEncodingException exception){
            throw exception;
        }
    }

    /*
     * Return the X509 certificate
     */
    public X509Certificate getCertificate() {
        return this.certificate;
    }

    /*
     * Cryptographically validate a certificate.
     * Throw relevant exception if validation fails.
     */
    public void verify(HandshakeCertificate cacert) throws CertificateException, 
        NoSuchAlgorithmException, InvalidKeyException, SignatureException, NoSuchProviderException {
        PublicKey publicKey = cacert.getCertificate().getPublicKey();
        certificate.verify(publicKey);
        System.out.println("Verification is successful");
    }

    /*
     * Return CN (Common Name) of subject
     */
    public String getCN() {
        /*
           X500Name x500name = new JcaX509CertificateHolder(cert).getSubject();
           RDN cn = x500name.getRDNs(BCStyle.CN)[0];
           return IETFUtils.valueToString(cn.getFirst().getValue());
         */
        String certificateDN = this.certificate.getSubjectX500Principal().getName();
        int index = certificateDN.indexOf("CN=");
        if (index != -1) {
            int start = index + 3;
            int end = certificateDN.indexOf(",", start);
            if (end == -1) { 
                end = certificateDN.length();
            }
        String cnValue = certificateDN.substring(start, end).trim().replace("\\", "");
        return cnValue;
        }
        return null;
    }

    /*
     * return email address of subject
     * The method getSubjectDN() from the type X509Certificate is deprecated since version 16
     * I could not use getSubjectX500Principal(). It had too many edge cases, I tested different
     * certificates and it did not work for all types. I went with a simple solution, but not the best one. 
     */
    public String getEmail() {
        
        // String certificateDN = this.certificate.getSubjectX500Principal().getName();
        // int index = certificateDN.indexOf("CN=");
        // if (index != -1) {
        //     int start = certificateDN.indexOf(",", index);
        //     int end = certificateDN.indexOf(",", start);
        //     if (end == -1) { 
        //         end = certificateDN.length();
        //     }
        // String cnValue = certificateDN.substring(start, end).trim().replace("\\", "");
        // return cnValue;
        // }
        // return "Email Not found";
        // 
        String certificateDN = this.certificate.getSubjectDN().getName();
        int index = certificateDN.indexOf("EMAILADDRESS=");
        if (index != -1) {
            int start = index + 13;
            int end = certificateDN.indexOf(",", start);
            if (end == -1) { 
                end = certificateDN.length();
            }
        String EmailValue = certificateDN.substring(start, end).trim().replace("\\", "");
        return EmailValue;
        }
        return null;
    
    }
    /* 
    public static void main(String [] args){
        try {
            FileInputStream caCertStream = new FileInputStream("/Users/ermiaghaffari/Desktop/ermia-HandshakeCertificate/CA.pem");
            HandshakeCertificate cert = new HandshakeCertificate(caCertStream);
            System.out.println("Start");
            System.out.println("Start");
            //System.out.println(cert.getCertificate().getSubjectX500Principal().getName());
            //System.out.println(cert.getCN());
            System.out.println(cert.getCertificate().getSubjectDN().getName());
            System.out.println(cert.getEmail());

        } catch (IOException e) {
            System.out.println("Error: " + e.getMessage());
            e.printStackTrace();
        }

    }*/
}
