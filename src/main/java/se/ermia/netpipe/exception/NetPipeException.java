package se.ermia.netpipe.exception;

/**
 * Base exception for all Secure NetPipe protocol errors.
 */
public class NetPipeException extends Exception {

    private static final long serialVersionUID = 1L;

    public NetPipeException(String message) {
        super(message);
    }

    public NetPipeException(String message, Throwable cause) {
        super(message, cause);
    }
}
