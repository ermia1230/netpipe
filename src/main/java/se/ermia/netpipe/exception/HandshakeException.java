package se.ermia.netpipe.exception;

/**
 * Thrown when the handshake protocol encounters an error.
 */
public class HandshakeException extends NetPipeException {

    private static final long serialVersionUID = 1L;

    public HandshakeException(String message) {
        super(message);
    }

    public HandshakeException(String message, Throwable cause) {
        super(message, cause);
    }
}
