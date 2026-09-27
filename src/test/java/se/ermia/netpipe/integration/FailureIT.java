package se.ermia.netpipe.integration;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import se.ermia.netpipe.server.NetPipeServer;

import java.io.DataOutputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.nio.file.Paths;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("Failure Integration Test")
public class FailureIT {

    private static NetPipeServer server;
    private static Thread serverThread;

    private static String getCertPath(String name) {
        return Paths.get("src/test/resources/certs/" + name).toAbsolutePath().toString();
    }

    @BeforeAll
    public static void setup() throws Exception {
        server = new NetPipeServer(0, 
            getCertPath("server.pem"), 
            getCertPath("ca.pem"), 
            getCertPath("server-private.der"));
            
        serverThread = new Thread(() -> {
            try {
                server.start();
            } catch (Exception e) {
                e.printStackTrace();
            }
        });
        serverThread.start();
        Thread.sleep(1000); // Give server time to bind
    }

    @Test
    @Timeout(10)
    public void testTruncatedMessage() throws Exception {
        try (Socket socket = new Socket("localhost", server.getLocalPort())) {
            OutputStream out = socket.getOutputStream();
            DataOutputStream dos = new DataOutputStream(out);
            
            // Send length but not the data
            dos.writeInt(1000);
            dos.write(new byte[]{1, 2, 3});
            dos.flush();
            // Socket closed immediately mid-handshake
        }
        
        Thread.sleep(500);
        assertThat(serverThread.isAlive()).isTrue();
    }

    @Test
    @Timeout(10)
    public void testInvalidMessageType() throws Exception {
        try (Socket socket = new Socket("localhost", server.getLocalPort())) {
            OutputStream out = socket.getOutputStream();
            DataOutputStream dos = new DataOutputStream(out);
            
            // Send random bytes
            byte[] garbage = new byte[]{0, 0, 0, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
            dos.write(garbage);
            dos.flush();
        }
        
        Thread.sleep(500);
        assertThat(serverThread.isAlive()).isTrue();
    }

    @Test
    @Timeout(10)
    public void testConnectThenClose() throws Exception {
        try (Socket socket = new Socket("localhost", server.getLocalPort())) {
            // Do nothing, just close
        }
        
        Thread.sleep(500);
        assertThat(serverThread.isAlive()).isTrue();
    }

    @Test
    @Timeout(10)
    public void testOversizedMessage() throws Exception {
        try (Socket socket = new Socket("localhost", server.getLocalPort())) {
            OutputStream out = socket.getOutputStream();
            DataOutputStream dos = new DataOutputStream(out);
            
            // MAX_MESSAGE_SIZE + 1
            dos.writeInt(65537);
            dos.flush();
        }
        
        Thread.sleep(500);
        assertThat(serverThread.isAlive()).isTrue();
    }
}
