package se.ermia.netpipe.crypto;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("HandshakeDigest Test")
public class HandshakeDigestTest {

    @Test
    @Timeout(5)
    public void testKnownSha256Vector() {
        HandshakeDigest digest = new HandshakeDigest();
        digest.update("test".getBytes());
        byte[] result = digest.digest();
        // SHA-256 for "test"
        String expectedHex = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";
        assertThat(bytesToHex(result)).isEqualTo(expectedHex);
    }

    @Test
    @Timeout(5)
    public void testSameInputSameDigest() {
        HandshakeDigest digest1 = new HandshakeDigest();
        digest1.update("hello".getBytes());
        byte[] d1 = digest1.digest();

        HandshakeDigest digest2 = new HandshakeDigest();
        digest2.update("hello".getBytes());
        byte[] d2 = digest2.digest();

        assertThat(HandshakeDigest.isEqual(d1, d2)).isTrue();
    }

    @Test
    @Timeout(5)
    public void testOneByteChangeDifferentDigest() {
        HandshakeDigest digest1 = new HandshakeDigest();
        digest1.update("hello".getBytes());
        byte[] d1 = digest1.digest();

        HandshakeDigest digest2 = new HandshakeDigest();
        digest2.update("hellp".getBytes());
        byte[] d2 = digest2.digest();

        assertThat(HandshakeDigest.isEqual(d1, d2)).isFalse();
    }

    @Test
    @Timeout(5)
    public void testEmptyData() {
        HandshakeDigest digest = new HandshakeDigest();
        byte[] result = digest.digest();
        String expectedHex = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"; // Empty string SHA-256
        assertThat(bytesToHex(result)).isEqualTo(expectedHex);
    }

    @Test
    @Timeout(5)
    public void testBinaryData() {
        HandshakeDigest digest1 = new HandshakeDigest();
        byte[] data = new byte[]{0, (byte) 255, 127, -128, 5};
        digest1.update(data);
        byte[] d1 = digest1.digest();

        HandshakeDigest digest2 = new HandshakeDigest();
        digest2.update(data);
        byte[] d2 = digest2.digest();

        assertThat(d1).isEqualTo(d2);
    }

    @Test
    @Timeout(5)
    public void testLargerPayload() {
        HandshakeDigest digest = new HandshakeDigest();
        byte[] data = new byte[10000];
        for (int i = 0; i < data.length; i++) {
            data[i] = (byte) (i % 256);
        }
        digest.update(data);
        byte[] result = digest.digest();
        assertThat(result).hasSize(32);
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}
