package se.ermia.netpipe.exception;

/**
 * Thrown when session establishment fails, such as during session key
 * or IV exchange and decryption.
 */
public class SessionEstablishmentException extends NetPipeException {

    private static final long serialVersionUID = 1L;

    public SessionEstablishmentException(String message) {
        super(message);
    }

    public SessionEstablishmentException(String message, Throwable cause) {
        super(message, cause);
    }
}
