package se.ermia.netpipe.config;

/**
 * Centralised configuration constants and defaults for Secure NetPipe.
 *
 * <p>Supports a precedence model: CLI argument &gt; environment variable &gt; default.</p>
 *
 * @author Ermia Ghaffari
 */
public final class NetPipeConfig {

    /** Default server port. */
    public static final int DEFAULT_PORT = 2206;

    /** Default host for client connections. */
    public static final String DEFAULT_HOST = "localhost";

    /** Socket timeout in milliseconds (30 seconds). */
    public static final int SOCKET_TIMEOUT_MS = 30_000;

    /** Handshake timeout in milliseconds (15 seconds). */
    public static final int HANDSHAKE_TIMEOUT_MS = 15_000;

    /** Maximum allowed clock skew for timestamp validation (seconds). */
    public static final long MAX_TIMESTAMP_SKEW_SECONDS = 300;

    /** AES key length in bits. */
    public static final int AES_KEY_LENGTH_BITS = 128;

    private NetPipeConfig() {
        // Constants only
    }

    /**
     * Resolve a configuration value using precedence: CLI &gt; env &gt; default.
     *
     * @param cliValue     value from CLI argument (may be null)
     * @param envVariable  name of the environment variable to check
     * @param defaultValue fallback default value
     * @return the resolved value
     */
    public static String resolve(String cliValue, String envVariable, String defaultValue) {
        if (cliValue != null && !cliValue.isEmpty()) {
            return cliValue;
        }
        String envValue = System.getenv(envVariable);
        if (envValue != null && !envValue.isEmpty()) {
            return envValue;
        }
        return defaultValue;
    }
}
