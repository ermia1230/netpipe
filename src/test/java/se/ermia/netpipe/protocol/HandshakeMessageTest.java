package se.ermia.netpipe.protocol;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import se.ermia.netpipe.exception.InvalidMessageException;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.net.Socket;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@DisplayName("HandshakeMessage Test")
public class HandshakeMessageTest {

    @Test
    @Timeout(5)
    public void testEncodeDecodeRoundtrip() throws Exception {
        HandshakeMessage msg = new HandshakeMessage(MessageType.CLIENTHELLO);
        msg.putParameter("Certificate", "base64data");
        
        byte[] bytes = msg.getBytes();
        HandshakeMessage decoded = HandshakeMessage.fromBytes(bytes);
        
        assertThat(decoded.getType()).isEqualTo(MessageType.CLIENTHELLO);
        assertThat(decoded.getParameter("Certificate")).isEqualTo("base64data");
    }

    @Test
    @Timeout(5)
    public void testMultipleParametersPreserved() throws Exception {
        HandshakeMessage msg = new HandshakeMessage(MessageType.SESSION);
        msg.putParameter("SessionKey", "keydata");
        msg.putParameter("SessionIV", "ivdata");
        
        byte[] bytes = msg.getBytes();
        HandshakeMessage decoded = HandshakeMessage.fromBytes(bytes);
        
        assertThat(decoded.getParameter("SessionKey")).isEqualTo("keydata");
        assertThat(decoded.getParameter("SessionIV")).isEqualTo("ivdata");
    }

    @Test
    @Timeout(5)
    public void testEmptyParameterValue() throws Exception {
        HandshakeMessage msg = new HandshakeMessage(MessageType.SERVERHELLO);
        msg.putParameter("Empty", "");
        
        byte[] bytes = msg.getBytes();
        HandshakeMessage decoded = HandshakeMessage.fromBytes(bytes);
        
        assertThat(decoded.getParameter("Empty")).isEqualTo("");
    }

    @Test
    @Timeout(5)
    public void testOversizedMessageRejection() throws Exception {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        DataOutputStream dos = new DataOutputStream(baos);
        dos.writeInt(HandshakeMessage.MAX_MESSAGE_SIZE + 1); // Oversized length
        
        final ByteArrayInputStream bais = new ByteArrayInputStream(baos.toByteArray());
        Socket socket = new Socket() {
            @Override
            public java.io.InputStream getInputStream() {
                return bais;
            }
        };
        
        assertThatThrownBy(() -> HandshakeMessage.recv(socket))
                .isInstanceOf(InvalidMessageException.class)
                .hasMessageContaining("too large");
    }

    @Test
    @Timeout(5)
    public void testFromBytesWithGarbageData() {
        byte[] garbage = new byte[]{1, 2, 3, 4, 5, 6, 7, 8};
        assertThatThrownBy(() -> HandshakeMessage.fromBytes(garbage))
                .isInstanceOf(InvalidMessageException.class);
    }
}
