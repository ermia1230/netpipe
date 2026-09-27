package se.ermia.netpipe.crypto;

import net.jqwik.api.ForAll;
import net.jqwik.api.Property;
import net.jqwik.api.constraints.Size;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Arrays;

import static org.assertj.core.api.Assertions.assertThat;

public class CryptoPropertyTest {

    @Property
    public void testEncryptDecryptRoundtrip(@ForAll byte[] data) throws Exception {
        SessionKey key = new SessionKey(128);
        SessionCipher cipher = new SessionCipher(key);

        ByteArrayOutputStream encryptedOut = new ByteArrayOutputStream();
        try (OutputStream cos = cipher.openEncryptedOutputStream(encryptedOut)) {
            cos.write(data);
        }
        
        byte[] ciphertext = encryptedOut.toByteArray();
        
        SessionCipher decryptCipher = new SessionCipher(key, cipher.getIVBytes());
        ByteArrayInputStream bais = new ByteArrayInputStream(ciphertext);
        try (InputStream cis = decryptCipher.openDecryptedInputStream(bais)) {
            byte[] decrypted = cis.readAllBytes();
            assertThat(decrypted).isEqualTo(data);
        }
    }

    @Property
    public void testSessionKeySerialization(@ForAll @Size(value = 16) byte[] keyBytes) {
        SessionKey original = new SessionKey(keyBytes);
        byte[] serialized = original.getKeyBytes();
        
        SessionKey reconstructed = new SessionKey(serialized);
        assertThat(reconstructed.getKeyBytes()).isEqualTo(original.getKeyBytes());
    }
}
