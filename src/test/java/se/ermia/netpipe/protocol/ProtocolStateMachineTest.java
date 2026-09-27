package se.ermia.netpipe.protocol;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import se.ermia.netpipe.exception.ProtocolStateException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@DisplayName("ProtocolStateMachine Test")
public class ProtocolStateMachineTest {

    @Test
    @Timeout(5)
    public void testInitialStateIsConnected() {
        ProtocolStateMachine psm = new ProtocolStateMachine("test");
        assertThat(psm.getState()).isEqualTo(ProtocolState.CONNECTED);
    }

    @Test
    @Timeout(5)
    public void testValidClientSideFullTransition() {
        ProtocolStateMachine psm = new ProtocolStateMachine("client");

        psm.transition(ProtocolState.CLIENT_HELLO_SENT);
        assertThat(psm.getState()).isEqualTo(ProtocolState.CLIENT_HELLO_SENT);

        psm.transition(ProtocolState.SERVER_HELLO_RECEIVED);
        psm.transition(ProtocolState.CERTIFICATE_VERIFIED);
        psm.transition(ProtocolState.SESSION_SENT);
        psm.transition(ProtocolState.SERVER_FINISHED_VERIFIED);
        psm.transition(ProtocolState.CLIENT_FINISHED_SENT);
        psm.transition(ProtocolState.SECURE_CHANNEL_ESTABLISHED);
        psm.transition(ProtocolState.CLOSED);

        assertThat(psm.getState()).isEqualTo(ProtocolState.CLOSED);
    }

    @Test
    @Timeout(5)
    public void testValidServerSideFullTransition() {
        ProtocolStateMachine psm = new ProtocolStateMachine("server");

        psm.transition(ProtocolState.CLIENT_HELLO_RECEIVED);
        psm.transition(ProtocolState.CERTIFICATE_VERIFIED);
        psm.transition(ProtocolState.SERVER_HELLO_SENT);
        psm.transition(ProtocolState.SESSION_RECEIVED);
        psm.transition(ProtocolState.SERVER_FINISHED_SENT);
        psm.transition(ProtocolState.CLIENT_FINISHED_VERIFIED);
        psm.transition(ProtocolState.SECURE_CHANNEL_ESTABLISHED);
        psm.transition(ProtocolState.CLOSED);

        assertThat(psm.getState()).isEqualTo(ProtocolState.CLOSED);
    }

    @Test
    @Timeout(5)
    public void testInvalidTransitionThrowsException() {
        ProtocolStateMachine psm = new ProtocolStateMachine("test");
        // CONNECTED -> SERVER_HELLO_RECEIVED is invalid (must go through CLIENT_HELLO_SENT first)
        assertThatThrownBy(() -> psm.transition(ProtocolState.SERVER_HELLO_RECEIVED))
                .isInstanceOf(ProtocolStateException.class);
    }

    @Test
    @Timeout(5)
    public void testSessionBeforeServerHelloRejected() {
        ProtocolStateMachine psm = new ProtocolStateMachine("test");
        // SESSION message before SERVERHELLO should be rejected
        assertThatThrownBy(() -> psm.transition(ProtocolState.SESSION_SENT))
                .isInstanceOf(ProtocolStateException.class);
    }

    @Test
    @Timeout(5)
    public void testAnyStateCanTransitionToFailed() {
        // Test from CONNECTED
        ProtocolStateMachine psm1 = new ProtocolStateMachine("test");
        psm1.transition(ProtocolState.FAILED);
        assertThat(psm1.getState()).isEqualTo(ProtocolState.FAILED);

        // Test from a mid-handshake state
        ProtocolStateMachine psm2 = new ProtocolStateMachine("test");
        psm2.transition(ProtocolState.CLIENT_HELLO_RECEIVED);
        psm2.transition(ProtocolState.FAILED);
        assertThat(psm2.getState()).isEqualTo(ProtocolState.FAILED);
    }

    @Test
    @Timeout(5)
    public void testSecureChannelCanTransitionToClosed() {
        ProtocolStateMachine psm = new ProtocolStateMachine("server");
        psm.transition(ProtocolState.CLIENT_HELLO_RECEIVED);
        psm.transition(ProtocolState.CERTIFICATE_VERIFIED);
        psm.transition(ProtocolState.SERVER_HELLO_SENT);
        psm.transition(ProtocolState.SESSION_RECEIVED);
        psm.transition(ProtocolState.SERVER_FINISHED_SENT);
        psm.transition(ProtocolState.CLIENT_FINISHED_VERIFIED);
        psm.transition(ProtocolState.SECURE_CHANNEL_ESTABLISHED);
        psm.transition(ProtocolState.CLOSED);
        assertThat(psm.getState()).isEqualTo(ProtocolState.CLOSED);
    }

    @Test
    @Timeout(5)
    public void testCanTransitionQuery() {
        ProtocolStateMachine psm = new ProtocolStateMachine("test");
        assertThat(psm.canTransition(ProtocolState.CLIENT_HELLO_SENT)).isTrue();
        assertThat(psm.canTransition(ProtocolState.SECURE_CHANNEL_ESTABLISHED)).isFalse();
    }
}
