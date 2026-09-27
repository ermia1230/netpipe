package se.ermia.netpipe.exception;

/**
 * Unchecked exception thrown when an invalid protocol state transition is attempted.
 * This indicates a programming error — the handshake code tried to move to a state
 * that is not reachable from the current state.
 */
public class ProtocolStateException extends IllegalStateException {

    private static final long serialVersionUID = 1L;

    public ProtocolStateException(String message) {
        super(message);
    }

    public ProtocolStateException(String currentState, String attemptedState) {
        super("Invalid protocol state transition: " + currentState + " -> " + attemptedState);
    }
}
