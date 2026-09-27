package se.ermia.netpipe.exception;

/**
 * Thrown when a received handshake message is malformed, has an unexpected type,
 * or is missing required parameters.
 */
public class InvalidMessageException extends HandshakeException {

    private static final long serialVersionUID = 1L;

    public InvalidMessageException(String message) {
        super(message);
    }

    public InvalidMessageException(String message, Throwable cause) {
        super(message, cause);
    }
}
