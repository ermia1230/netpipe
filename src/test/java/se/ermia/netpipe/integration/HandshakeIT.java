package se.ermia.netpipe.integration;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import se.ermia.netpipe.client.NetPipeClient;
import se.ermia.netpipe.server.NetPipeServer;
import se.ermia.netpipe.exception.CertificateValidationException;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.PipedInputStream;
import java.io.PipedOutputStream;
import java.nio.file.Paths;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@DisplayName("Handshake Integration Test")
public class HandshakeIT {

    private String getCertPath(String name) {
        return Paths.get("src/test/resources/certs/" + name).toAbsolutePath().toString();
    }

    @Test
    @Timeout(10)
    public void testSuccessfulHandshake() throws Exception {
        NetPipeServer server = new NetPipeServer(0, 
            getCertPath("server.pem"), 
            getCertPath("ca.pem"), 
            getCertPath("server-private.der"));
            
        Thread serverThread = new Thread(() -> {
            try {
                server.acceptOneClient(
                    new ByteArrayInputStream("Server response".getBytes()), 
                    new ByteArrayOutputStream());
            } catch (Exception e) {
                e.printStackTrace();
            }
        });
        serverThread.start();
        
        Thread.sleep(500); // Wait for server to bind

        NetPipeClient client = new NetPipeClient("localhost", server.getLocalPort(),
            getCertPath("client.pem"),
            getCertPath("ca.pem"),
            getCertPath("client-private.der"));

        ByteArrayInputStream clientInput = new ByteArrayInputStream("Hello Secure World!".getBytes());
        ByteArrayOutputStream clientOutput = new ByteArrayOutputStream();

        Thread clientThread = new Thread(() -> {
            try {
                client.connect(clientInput, clientOutput);
            } catch (Exception e) {
                e.printStackTrace();
            }
        });
        clientThread.start();

        clientThread.join(5000);
        serverThread.join(5000);

        assertThat(clientThread.isAlive()).isFalse();
        assertThat(serverThread.isAlive()).isFalse();
    }

    @Test
    @Timeout(10)
    public void testUntrustedCert() throws Exception {
        NetPipeServer server = new NetPipeServer(0, 
            getCertPath("untrusted.pem"), 
            getCertPath("ca.pem"), 
            getCertPath("untrusted-private.der"));
            
        Thread serverThread = new Thread(() -> {
            try {
                server.acceptOneClient(
                    new ByteArrayInputStream(new byte[0]), 
                    new ByteArrayOutputStream());
            } catch (Exception e) {
                // Expected to fail
            }
        });
        serverThread.start();
        
        Thread.sleep(500);

        NetPipeClient client = new NetPipeClient("localhost", server.getLocalPort(),
            getCertPath("client.pem"),
            getCertPath("ca.pem"),
            getCertPath("client-private.der"));

        PipedOutputStream localAppOut = new PipedOutputStream();
        PipedInputStream localAppIn = new PipedInputStream(localAppOut);
        
        PipedOutputStream localAppOutToRead = new PipedOutputStream();

        assertThatThrownBy(() -> {
            client.connect(localAppIn, localAppOutToRead);
        }).isInstanceOf(CertificateValidationException.class);
    }
}
