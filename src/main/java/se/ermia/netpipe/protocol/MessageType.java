package se.ermia.netpipe.protocol;

/**
 * Handshake message types for the Secure NetPipe protocol.
 *
 * <p>Skeleton design by Peter Sjödin (KTH). Extracted to standalone enum
 * by Ermia Ghaffari for improved testability and state-machine integration.</p>
 */
public enum MessageType {

    CLIENTHELLO(1),
    SERVERHELLO(2),
    SESSION(3),
    SERVERFINISHED(4),
    CLIENTFINISHED(5);

    private final int code;

    MessageType(int code) {
        this.code = code;
    }

    public int getCode() {
        return code;
    }

    /**
     * Look up a MessageType by its integer code.
     *
     * @param code the integer code
     * @return the corresponding MessageType
     * @throws IllegalArgumentException if the code is unknown
     */
    public static MessageType fromCode(int code) {
        for (MessageType type : values()) {
            if (type.code == code) {
                return type;
            }
        }
        throw new IllegalArgumentException("Unknown message type code: " + code);
    }
}
