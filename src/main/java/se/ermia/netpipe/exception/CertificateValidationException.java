package se.ermia.netpipe.exception;

/**
 * Thrown when X.509 certificate validation fails during handshake.
 */
public class CertificateValidationException extends HandshakeException {

    private static final long serialVersionUID = 1L;

    public CertificateValidationException(String message) {
        super(message);
    }

    public CertificateValidationException(String message, Throwable cause) {
        super(message, cause);
    }
}
