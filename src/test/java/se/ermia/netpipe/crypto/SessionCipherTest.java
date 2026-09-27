package se.ermia.netpipe.crypto;

import se.ermia.netpipe.exception.CryptoException;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Arrays;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@DisplayName("SessionCipher Test")
public class SessionCipherTest {

    @Test
    @Timeout(5)
    public void testEncryptDecryptRoundtrip() throws Exception {
        SessionKey key = new SessionKey(128);
        SessionCipher cipher = new SessionCipher(key);

        byte[] original = "hello secure world".getBytes();
        
        ByteArrayOutputStream encryptedOut = new ByteArrayOutputStream();
        try (OutputStream cos = cipher.openEncryptedOutputStream(encryptedOut)) {
            cos.write(original);
        }
        
        byte[] ciphertext = encryptedOut.toByteArray();
        assertThat(ciphertext).isNotEqualTo(original);
        
        SessionCipher decryptCipher = new SessionCipher(key, cipher.getIVBytes());
        ByteArrayInputStream bais = new ByteArrayInputStream(ciphertext);
        try (InputStream cis = decryptCipher.openDecryptedInputStream(bais)) {
            byte[] decrypted = cis.readAllBytes();
            assertThat(decrypted).isEqualTo(original);
        }
    }

    @Test
    @Timeout(5)
    public void testBinaryData() throws Exception {
        SessionKey key = new SessionKey(128);
        SessionCipher cipher = new SessionCipher(key);

        byte[] original = new byte[]{0, (byte) 255, 127, -128, 5, 10, 20};
        
        ByteArrayOutputStream encryptedOut = new ByteArrayOutputStream();
        try (OutputStream cos = cipher.openEncryptedOutputStream(encryptedOut)) {
            cos.write(original);
        }
        
        byte[] ciphertext = encryptedOut.toByteArray();
        
        SessionCipher decryptCipher = new SessionCipher(key, cipher.getIVBytes());
        ByteArrayInputStream bais = new ByteArrayInputStream(ciphertext);
        try (InputStream cis = decryptCipher.openDecryptedInputStream(bais)) {
            byte[] decrypted = cis.readAllBytes();
            assertThat(decrypted).isEqualTo(original);
        }
    }

    @Test
    @Timeout(5)
    public void testEmptyPayload() throws Exception {
        SessionKey key = new SessionKey(128);
        SessionCipher cipher = new SessionCipher(key);

        byte[] original = new byte[0];
        
        ByteArrayOutputStream encryptedOut = new ByteArrayOutputStream();
        try (OutputStream cos = cipher.openEncryptedOutputStream(encryptedOut)) {
            cos.write(original);
        }
        
        byte[] ciphertext = encryptedOut.toByteArray();
        
        SessionCipher decryptCipher = new SessionCipher(key, cipher.getIVBytes());
        ByteArrayInputStream bais = new ByteArrayInputStream(ciphertext);
        try (InputStream cis = decryptCipher.openDecryptedInputStream(bais)) {
            byte[] decrypted = cis.readAllBytes();
            assertThat(decrypted).isEqualTo(original);
        }
    }

    @Test
    @Timeout(5)
    public void testLargePayload() throws Exception {
        SessionKey key = new SessionKey(128);
        SessionCipher cipher = new SessionCipher(key);

        byte[] original = new byte[100000]; // 100 KB
        for (int i = 0; i < original.length; i++) {
            original[i] = (byte) (i % 256);
        }
        
        ByteArrayOutputStream encryptedOut = new ByteArrayOutputStream();
        try (OutputStream cos = cipher.openEncryptedOutputStream(encryptedOut)) {
            cos.write(original);
        }
        
        byte[] ciphertext = encryptedOut.toByteArray();
        
        SessionCipher decryptCipher = new SessionCipher(key, cipher.getIVBytes());
        ByteArrayInputStream bais = new ByteArrayInputStream(ciphertext);
        try (InputStream cis = decryptCipher.openDecryptedInputStream(bais)) {
            byte[] decrypted = cis.readAllBytes();
            assertThat(decrypted).isEqualTo(original);
        }
    }

    @Test
    @Timeout(5)
    public void testDifferentIvDifferentCiphertext() throws Exception {
        SessionKey key = new SessionKey(128);
        byte[] original = "hello secure world".getBytes();
        
        SessionCipher cipher1 = new SessionCipher(key);
        ByteArrayOutputStream out1 = new ByteArrayOutputStream();
        try (OutputStream cos1 = cipher1.openEncryptedOutputStream(out1)) {
            cos1.write(original);
        }
        byte[] ciphertext1 = out1.toByteArray();
        
        SessionCipher cipher2 = new SessionCipher(key); // New random IV
        ByteArrayOutputStream out2 = new ByteArrayOutputStream();
        try (OutputStream cos2 = cipher2.openEncryptedOutputStream(out2)) {
            cos2.write(original);
        }
        byte[] ciphertext2 = out2.toByteArray();
        
        assertThat(cipher1.getIVBytes()).isNotEqualTo(cipher2.getIVBytes());
        assertThat(ciphertext1).isNotEqualTo(ciphertext2);
    }

    @Test
    @Timeout(5)
    public void testInvalidIvLengthRejected() {
        SessionKey key = new SessionKey(128);
        assertThatThrownBy(() -> new SessionCipher(key, new byte[15]))
                .isInstanceOf(CryptoException.class);
                
        assertThatThrownBy(() -> new SessionCipher(key, new byte[17]))
                .isInstanceOf(CryptoException.class);
                
        assertThatThrownBy(() -> new SessionCipher(key, null))
                .isInstanceOf(CryptoException.class);
    }

    @Test
    @Timeout(5)
    public void testCorruptedCiphertext() throws Exception {
        SessionKey key = new SessionKey(128);
        SessionCipher cipher = new SessionCipher(key);

        byte[] original = "hello secure world".getBytes();
        
        ByteArrayOutputStream encryptedOut = new ByteArrayOutputStream();
        try (OutputStream cos = cipher.openEncryptedOutputStream(encryptedOut)) {
            cos.write(original);
        }
        
        byte[] ciphertext = encryptedOut.toByteArray();
        ciphertext[0] ^= 0xFF; // Corrupt first byte
        
        SessionCipher decryptCipher = new SessionCipher(key, cipher.getIVBytes());
        ByteArrayInputStream bais = new ByteArrayInputStream(ciphertext);
        try (InputStream cis = decryptCipher.openDecryptedInputStream(bais)) {
            byte[] decrypted = cis.readAllBytes();
            assertThat(decrypted).isNotEqualTo(original);
            // CTR mode doesn't authenticate, so it just decrypts to garbage
        }
    }
}
