package se.ermia.netpipe.crypto;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import se.ermia.netpipe.exception.CertificateValidationException;

import java.io.InputStream;
import java.security.cert.CertificateException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@DisplayName("HandshakeCertificate Test")
public class HandshakeCertificateTest {

    @Test
    @Timeout(5)
    public void testValidPemCertParsing() throws Exception {
        try (InputStream certIn = getClass().getResourceAsStream("/certs/server.pem")) {
            HandshakeCertificate cert = new HandshakeCertificate(certIn);
            assertThat(cert.getCertificate()).isNotNull();
            assertThat(cert.getCN()).isEqualTo("server.test.netpipe");
        }
    }

    @Test
    @Timeout(5)
    public void testCaVerification() throws Exception {
        try (InputStream certIn = getClass().getResourceAsStream("/certs/server.pem");
             InputStream caIn = getClass().getResourceAsStream("/certs/ca.pem")) {
            HandshakeCertificate cert = new HandshakeCertificate(certIn);
            HandshakeCertificate ca = new HandshakeCertificate(caIn);
            
            // Should pass without throwing
            cert.verify(ca);
        }
    }

    @Test
    @Timeout(5)
    public void testWrongCaRejection() throws Exception {
        try (InputStream untrustedIn = getClass().getResourceAsStream("/certs/untrusted.pem");
             InputStream caIn = getClass().getResourceAsStream("/certs/ca.pem")) {
            HandshakeCertificate cert = new HandshakeCertificate(untrustedIn);
            HandshakeCertificate ca = new HandshakeCertificate(caIn);
            
            assertThatThrownBy(() -> cert.verify(ca))
                    .isInstanceOf(CertificateValidationException.class);
        }
    }

    @Test
    @Timeout(5)
    public void testCnExtraction() throws Exception {
        try (InputStream certIn = getClass().getResourceAsStream("/certs/client.pem")) {
            HandshakeCertificate cert = new HandshakeCertificate(certIn);
            assertThat(cert.getCN()).isEqualTo("client.test.netpipe");
        }
    }

    @Test
    @Timeout(5)
    public void testGetBytesReconstructRoundtrip() throws Exception {
        try (InputStream certIn = getClass().getResourceAsStream("/certs/server.pem")) {
            HandshakeCertificate original = new HandshakeCertificate(certIn);
            byte[] bytes = original.getBytes();
            
            HandshakeCertificate reconstructed = new HandshakeCertificate(bytes);
            assertThat(reconstructed.getCertificate()).isEqualTo(original.getCertificate());
            assertThat(reconstructed.getCN()).isEqualTo(original.getCN());
        }
    }
}
