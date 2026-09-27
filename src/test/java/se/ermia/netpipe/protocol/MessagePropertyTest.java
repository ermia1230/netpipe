package se.ermia.netpipe.protocol;

import net.jqwik.api.ForAll;
import net.jqwik.api.Property;
import net.jqwik.api.constraints.AlphaChars;
import net.jqwik.api.constraints.StringLength;

import static org.assertj.core.api.Assertions.assertThat;

public class MessagePropertyTest {

    @Property
    public void testEncodeDecodeRoundtrip(
            @ForAll MessageType type,
            @ForAll @AlphaChars @StringLength(min = 1, max = 20) String paramKey,
            @ForAll @AlphaChars @StringLength(min = 0, max = 100) String paramValue) throws Exception {
        
        HandshakeMessage msg = new HandshakeMessage(type);
        msg.putParameter(paramKey, paramValue);
        
        byte[] bytes = msg.getBytes();
        HandshakeMessage decoded = HandshakeMessage.fromBytes(bytes);
        
        assertThat(decoded.getType()).isEqualTo(type);
        assertThat(decoded.getParameter(paramKey)).isEqualTo(paramValue);
    }
}
