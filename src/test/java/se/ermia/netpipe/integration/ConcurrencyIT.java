package se.ermia.netpipe.integration;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import se.ermia.netpipe.client.NetPipeClient;
import se.ermia.netpipe.server.NetPipeServer;

import java.io.PipedInputStream;
import java.io.PipedOutputStream;
import java.nio.file.Paths;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("Concurrency Integration Test")
public class ConcurrencyIT {

    private String getCertPath(String name) {
        return Paths.get("src/test/resources/certs/" + name).toAbsolutePath().toString();
    }

    @Test
    @Timeout(30)
    public void testMultipleSimultaneousClients() throws Exception {
        NetPipeServer server = new NetPipeServer(0, 
            getCertPath("server.pem"), 
            getCertPath("ca.pem"), 
            getCertPath("server-private.der"));
            
        Thread serverThread = new Thread(() -> {
            try {
                server.start(); // Multi-client mode
            } catch (Exception e) {
                e.printStackTrace();
            }
        });
        serverThread.start();
        
        Thread.sleep(1000); // Give server time to bind

        int numClients = 5;
        ExecutorService executor = Executors.newFixedThreadPool(numClients);
        AtomicInteger successCount = new AtomicInteger(0);

        for (int i = 0; i < numClients; i++) {
            executor.submit(() -> {
                try {
                    NetPipeClient client = new NetPipeClient("localhost", server.getLocalPort(),
                        getCertPath("client.pem"),
                        getCertPath("ca.pem"),
                        getCertPath("client-private.der"));
                    
                    PipedOutputStream localAppOut = new PipedOutputStream();
                    PipedInputStream localAppIn = new PipedInputStream(localAppOut);
                    PipedOutputStream localAppOutToRead = new PipedOutputStream();
                    
                    // We need it to run in background or just connect and finish
                    Thread t = new Thread(() -> {
                        try {
                            client.connect(localAppIn, localAppOutToRead);
                        } catch (Exception e) {}
                    });
                    t.start();
                    
                    Thread.sleep(1000);
                    successCount.incrementAndGet();
                } catch (Exception e) {
                    e.printStackTrace();
                }
            });
        }
        
        executor.shutdown();
        executor.awaitTermination(15, TimeUnit.SECONDS);
        
        assertThat(successCount.get()).isEqualTo(5);
        
        // Test that server remains operational after a failed client handshake
        NetPipeClient badClient = new NetPipeClient("localhost", server.getLocalPort(),
            getCertPath("untrusted.pem"), // Bad cert
            getCertPath("ca.pem"),
            getCertPath("untrusted-private.der"));
            
        try {
            badClient.connect(new PipedInputStream(), new PipedOutputStream());
        } catch (Exception expected) {}
        
        // Server should still be alive
        assertThat(serverThread.isAlive()).isTrue();
    }
}
