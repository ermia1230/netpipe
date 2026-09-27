package se.ermia.netpipe.crypto;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import java.io.InputStream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@DisplayName("HandshakeCrypto Test")
public class HandshakeCryptoTest {

    @Test
    @Timeout(5)
    public void testRsaEncryptDecryptRoundtrip() throws Exception {
        try (InputStream certIn = getClass().getResourceAsStream("/certs/server.pem");
             InputStream keyIn = getClass().getResourceAsStream("/certs/server-private.der")) {
            
            HandshakeCertificate cert = new HandshakeCertificate(certIn);
            HandshakeCrypto publicKeyCrypto = new HandshakeCrypto(cert);
            HandshakeCrypto privateKeyCrypto = new HandshakeCrypto(keyIn.readAllBytes());

            byte[] original = "test message".getBytes();
            byte[] ciphertext = publicKeyCrypto.encrypt(original);
            
            assertThat(ciphertext).isNotEqualTo(original);
            
            byte[] decrypted = privateKeyCrypto.decrypt(ciphertext);
            assertThat(decrypted).isEqualTo(original);
        }
    }

    @Test
    @Timeout(5)
    public void testWrongKeyFails() throws Exception {
        try (InputStream serverCertIn = getClass().getResourceAsStream("/certs/server.pem");
             InputStream clientKeyIn = getClass().getResourceAsStream("/certs/client-private.der")) {
            
            HandshakeCertificate cert = new HandshakeCertificate(serverCertIn);
            HandshakeCrypto publicKeyCrypto = new HandshakeCrypto(cert);
            HandshakeCrypto wrongPrivateKeyCrypto = new HandshakeCrypto(clientKeyIn.readAllBytes());

            byte[] original = "test message".getBytes();
            byte[] ciphertext = publicKeyCrypto.encrypt(original);
            
            assertThatThrownBy(() -> wrongPrivateKeyCrypto.decrypt(ciphertext))
                .isInstanceOf(Exception.class);
        }
    }

    @Test
    @Timeout(5)
    public void testCorruptedCiphertext() throws Exception {
        try (InputStream certIn = getClass().getResourceAsStream("/certs/server.pem");
             InputStream keyIn = getClass().getResourceAsStream("/certs/server-private.der")) {
            
            HandshakeCertificate cert = new HandshakeCertificate(certIn);
            HandshakeCrypto publicKeyCrypto = new HandshakeCrypto(cert);
            HandshakeCrypto privateKeyCrypto = new HandshakeCrypto(keyIn.readAllBytes());

            byte[] original = "test message".getBytes();
            byte[] ciphertext = publicKeyCrypto.encrypt(original);
            
            ciphertext[5] ^= 0xFF; // Corrupt
            
            assertThatThrownBy(() -> privateKeyCrypto.decrypt(ciphertext))
                .isInstanceOf(Exception.class);
        }
    }

    @Test
    @Timeout(5)
    public void testBinaryPayload() throws Exception {
        try (InputStream certIn = getClass().getResourceAsStream("/certs/server.pem");
             InputStream keyIn = getClass().getResourceAsStream("/certs/server-private.der")) {
            
            HandshakeCertificate cert = new HandshakeCertificate(certIn);
            HandshakeCrypto publicKeyCrypto = new HandshakeCrypto(cert);
            HandshakeCrypto privateKeyCrypto = new HandshakeCrypto(keyIn.readAllBytes());

            byte[] original = new byte[]{0, (byte)255, 127, -128, 42};
            byte[] ciphertext = publicKeyCrypto.encrypt(original);
            byte[] decrypted = privateKeyCrypto.decrypt(ciphertext);
            
            assertThat(decrypted).isEqualTo(original);
        }
    }
}
