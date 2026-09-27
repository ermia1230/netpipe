package se.ermia.netpipe.protocol;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import se.ermia.netpipe.config.NetPipeConfig;
import se.ermia.netpipe.server.NetPipeServer;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@DisplayName("TimestampValidation Test")
public class TimestampValidationTest {

    private static final DateTimeFormatter FORMATTER = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    @Test
    @Timeout(5)
    public void testCurrentTimestampAccepted() {
        String current = LocalDateTime.now().format(FORMATTER);
        
        assertThatCode(() -> {
            // Using a simple reflection or a helper logic to validate
            // NetPipeServer.validateTimestamp is package-private.
            // Since this test is in protocol package and NetPipeServer is in server package,
            // we will simulate the validation logic directly as requested by prompt instruction:
            // "The simplest approach: create a TimestampValidationTest in the protocol package that tests timestamp format parsing and skew logic directly. Import the DateTimeFormatter pattern and NetPipeConfig.MAX_TIMESTAMP_SKEW_SECONDS."
            
            LocalDateTime received = LocalDateTime.parse(current, FORMATTER);
            long skewSeconds = Math.abs(java.time.Duration.between(received, LocalDateTime.now()).toSeconds());
            if (skewSeconds > NetPipeConfig.MAX_TIMESTAMP_SKEW_SECONDS) {
                throw new Exception("Skew too large");
            }
        }).doesNotThrowAnyException();
    }

    @Test
    @Timeout(5)
    public void testExpiredTimestamp() {
        String expired = LocalDateTime.now().minusSeconds(301).format(FORMATTER);
        
        assertThatThrownBy(() -> {
            LocalDateTime received = LocalDateTime.parse(expired, FORMATTER);
            long skewSeconds = Math.abs(java.time.Duration.between(received, LocalDateTime.now()).toSeconds());
            if (skewSeconds > NetPipeConfig.MAX_TIMESTAMP_SKEW_SECONDS) {
                throw new RuntimeException("Skew too large");
            }
        }).isInstanceOf(RuntimeException.class);
    }

    @Test
    @Timeout(5)
    public void testFutureTimestamp() {
        String future = LocalDateTime.now().plusSeconds(301).format(FORMATTER);
        
        assertThatThrownBy(() -> {
            LocalDateTime received = LocalDateTime.parse(future, FORMATTER);
            long skewSeconds = Math.abs(java.time.Duration.between(received, LocalDateTime.now()).toSeconds());
            if (skewSeconds > NetPipeConfig.MAX_TIMESTAMP_SKEW_SECONDS) {
                throw new RuntimeException("Skew too large");
            }
        }).isInstanceOf(RuntimeException.class);
    }

    @Test
    @Timeout(5)
    public void testMalformedTimestampString() {
        String malformed = "2024-01-01T12:00:00Z";
        
        assertThatThrownBy(() -> {
            LocalDateTime.parse(malformed, FORMATTER);
        }).isInstanceOf(java.time.format.DateTimeParseException.class);
    }
}
