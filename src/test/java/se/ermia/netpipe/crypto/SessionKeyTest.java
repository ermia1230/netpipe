package se.ermia.netpipe.crypto;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@DisplayName("SessionKey Test")
public class SessionKeyTest {

    @Test
    @Timeout(5)
    public void testValidAes128KeyGeneration() {
        SessionKey key = new SessionKey(128);
        assertThat(key.getKeyBytes()).hasSize(16);
        assertThat(key.getSecretKey().getAlgorithm()).isEqualTo("AES");
    }

    @Test
    @Timeout(5)
    public void testReconstructionFromBytes() {
        SessionKey original = new SessionKey(128);
        SessionKey reconstructed = new SessionKey(original.getKeyBytes());
        assertThat(reconstructed.getKeyBytes()).isEqualTo(original.getKeyBytes());
        assertThat(reconstructed.getSecretKey().getEncoded()).isEqualTo(original.getSecretKey().getEncoded());
    }

    @Test
    @Timeout(5)
    public void testEqualityOfOriginalReconstructed() {
        SessionKey original = new SessionKey(128);
        SessionKey reconstructed = new SessionKey(original.getKeyBytes());
        assertThat(reconstructed.getKeyBytes()).containsExactly(original.getKeyBytes());
    }

    @Test
    @Timeout(5)
    public void testRandomKeysDiffer() {
        SessionKey key1 = new SessionKey(128);
        SessionKey key2 = new SessionKey(128);
        assertThat(key1.getKeyBytes()).isNotEqualTo(key2.getKeyBytes());
    }

    @Test
    @Timeout(5)
    public void testInvalidKeyLengthRejected() {
        assertThatThrownBy(() -> new SessionKey(new byte[15]))
                .isInstanceOf(IllegalArgumentException.class);
        
        assertThatThrownBy(() -> new SessionKey(new byte[17]))
                .isInstanceOf(IllegalArgumentException.class);
                
        assertThatThrownBy(() -> new SessionKey((byte[]) null))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
