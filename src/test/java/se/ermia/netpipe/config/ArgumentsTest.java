package se.ermia.netpipe.config;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@DisplayName("Arguments Test")
public class ArgumentsTest {

    @Test
    @Timeout(5)
    public void testValidArguments() {
        Arguments args = new Arguments();
        args.setArgumentSpec("port", "port number");
        args.setArgumentSpec("host", "host name");
        
        args.loadArguments(new String[]{"--port=8080", "--host=localhost"});
        
        assertThat(args.get("port")).isEqualTo("8080");
        assertThat(args.get("host")).isEqualTo("localhost");
    }

    @Test
    @Timeout(5)
    public void testUnknownOption() {
        Arguments args = new Arguments();
        args.setArgumentSpec("port", "port number");
        
        assertThatThrownBy(() -> args.loadArguments(new String[]{"--port=8080", "--unknown=value"}))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Unknown argument");
    }

    @Test
    @Timeout(5)
    public void testMissingValue() {
        Arguments args = new Arguments();
        args.setArgumentSpec("port", "port number");
        
        assertThatThrownBy(() -> args.loadArguments(new String[]{"--port="}))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("requires a value");
    }

    @Test
    @Timeout(5)
    public void testMissingDashDash() {
        Arguments args = new Arguments();
        args.setArgumentSpec("port", "port number");
        
        assertThatThrownBy(() -> args.loadArguments(new String[]{"port=8080"}))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("does not start with");
    }

    @Test
    @Timeout(5)
    public void testDuplicateOptions() {
        Arguments args = new Arguments();
        args.setArgumentSpec("port", "port number");
        
        assertThatThrownBy(() -> args.loadArguments(new String[]{"--port=8080", "--port=9090"}))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Duplicate argument");
    }

    @Test
    @Timeout(5)
    public void testEmptyValues() {
        Arguments args = new Arguments();
        args.setArgumentSpec("port", "port number");
        
        assertThatThrownBy(() -> args.loadArguments(new String[]{"--port"})) // missing =
                .isInstanceOf(IllegalArgumentException.class);
    }
}
