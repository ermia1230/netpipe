package se.ermia.netpipe.exception;

/**
 * Thrown when timestamp validation fails during the Finished-message verification.
 * This includes expired timestamps, future timestamps, and malformed timestamp strings.
 */
public class TimestampValidationException extends HandshakeException {

    private static final long serialVersionUID = 1L;

    public TimestampValidationException(String message) {
        super(message);
    }

    public TimestampValidationException(String message, Throwable cause) {
        super(message, cause);
    }
}
