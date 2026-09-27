package se.ermia.netpipe.protocol;

import se.ermia.netpipe.exception.ProtocolStateException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.EnumMap;
import java.util.EnumSet;
import java.util.Map;
import java.util.Set;

/**
 * Validates and enforces handshake protocol state transitions.
 *
 * <p>Each side of the connection (client or server) maintains its own state machine.
 * Invalid transitions throw {@link ProtocolStateException} to prevent protocol
 * violations such as receiving a SESSION message before SERVERHELLO.</p>
 *
 * @author Ermia Ghaffari
 */
public class ProtocolStateMachine {

    private static final Logger log = LoggerFactory.getLogger(ProtocolStateMachine.class);

    private static final Map<ProtocolState, Set<ProtocolState>> VALID_TRANSITIONS;

    static {
        VALID_TRANSITIONS = new EnumMap<>(ProtocolState.class);

        // Client-side transitions
        allow(ProtocolState.CONNECTED, ProtocolState.CLIENT_HELLO_SENT);
        allow(ProtocolState.CLIENT_HELLO_SENT, ProtocolState.SERVER_HELLO_RECEIVED);
        allow(ProtocolState.SERVER_HELLO_RECEIVED, ProtocolState.CERTIFICATE_VERIFIED);
        allow(ProtocolState.CERTIFICATE_VERIFIED, ProtocolState.SESSION_SENT);
        allow(ProtocolState.SESSION_SENT, ProtocolState.SERVER_FINISHED_VERIFIED);
        allow(ProtocolState.SERVER_FINISHED_VERIFIED, ProtocolState.CLIENT_FINISHED_SENT);
        allow(ProtocolState.CLIENT_FINISHED_SENT, ProtocolState.SECURE_CHANNEL_ESTABLISHED);

        // Server-side transitions
        allow(ProtocolState.CONNECTED, ProtocolState.CLIENT_HELLO_RECEIVED);
        allow(ProtocolState.CLIENT_HELLO_RECEIVED, ProtocolState.CERTIFICATE_VERIFIED);
        allow(ProtocolState.CERTIFICATE_VERIFIED, ProtocolState.SERVER_HELLO_SENT);
        allow(ProtocolState.SERVER_HELLO_SENT, ProtocolState.SESSION_RECEIVED);
        allow(ProtocolState.SESSION_RECEIVED, ProtocolState.SERVER_FINISHED_SENT);
        allow(ProtocolState.SERVER_FINISHED_SENT, ProtocolState.CLIENT_FINISHED_VERIFIED);
        allow(ProtocolState.CLIENT_FINISHED_VERIFIED, ProtocolState.SECURE_CHANNEL_ESTABLISHED);

        // Common transitions — any state can transition to FAILED or CLOSED
        for (ProtocolState state : ProtocolState.values()) {
            if (state != ProtocolState.FAILED && state != ProtocolState.CLOSED) {
                allow(state, ProtocolState.FAILED);
            }
        }
        allow(ProtocolState.SECURE_CHANNEL_ESTABLISHED, ProtocolState.CLOSED);
    }

    private volatile ProtocolState currentState;
    private final String role;

    /**
     * Create a new state machine starting in {@link ProtocolState#CONNECTED}.
     *
     * @param role descriptive label for logging (e.g. "client" or "server")
     */
    public ProtocolStateMachine(String role) {
        this.role = role;
        this.currentState = ProtocolState.CONNECTED;
        log.debug("[{}] State machine initialized: {}", role, currentState);
    }

    /**
     * Transition to a new state. Thread-safe.
     *
     * @param newState the target state
     * @throws ProtocolStateException if the transition is not valid
     */
    public synchronized void transition(ProtocolState newState) {
        Set<ProtocolState> allowed = VALID_TRANSITIONS.getOrDefault(
                currentState, EnumSet.noneOf(ProtocolState.class));

        if (!allowed.contains(newState)) {
            throw new ProtocolStateException(currentState.name(), newState.name());
        }

        ProtocolState previous = currentState;
        currentState = newState;
        log.debug("[{}] State transition: {} -> {}", role, previous, newState);
    }

    /**
     * Return the current protocol state.
     */
    public synchronized ProtocolState getState() {
        return currentState;
    }

    /**
     * Check whether the given target state is a valid transition from the current state.
     */
    public synchronized boolean canTransition(ProtocolState target) {
        return VALID_TRANSITIONS.getOrDefault(
                currentState, EnumSet.noneOf(ProtocolState.class)).contains(target);
    }

    private static void allow(ProtocolState from, ProtocolState to) {
        VALID_TRANSITIONS.computeIfAbsent(from, k -> EnumSet.noneOf(ProtocolState.class)).add(to);
    }
}
