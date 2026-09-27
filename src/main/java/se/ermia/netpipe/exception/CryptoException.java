package se.ermia.netpipe.exception;

/**
 * Thrown when a cryptographic operation fails, wrapping lower-level
 * {@link java.security.GeneralSecurityException} details.
 */
public class CryptoException extends NetPipeException {

    private static final long serialVersionUID = 1L;

    public CryptoException(String message) {
        super(message);
    }

    public CryptoException(String message, Throwable cause) {
        super(message, cause);
    }
}
