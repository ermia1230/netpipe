package se.ermia.netpipe.transport;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;

/**
 * Bidirectional stream forwarder for encrypted communication.
 *
 * <p>Starts two threads: one reads from local input (stdin) and writes to the
 * network output (encrypted), and another reads from the network input (decrypted)
 * and writes to local output (stdout). Forwarding continues until one side
 * reaches EOF or an error occurs.</p>
 *
 * <p>Originally written by Peter Sjödin (KTH/IK2206).
 * Refactored by Ermia Ghaffari: added logging, clean shutdown, and error handling.</p>
 */
public final class Forwarder {

    private static final Logger log = LoggerFactory.getLogger(Forwarder.class);

    private Forwarder() {
        // Utility class
    }

    /**
     * Thread that copies data from an InputStream to an OutputStream.
     */
    private static class StreamForwarder implements Runnable {

        private static final int BUFFER_SIZE = 1024;

        private final InputStream input;
        private final OutputStream output;
        private final Socket shutdownSocket;
        private final String name;

        StreamForwarder(String name, InputStream input, OutputStream output, Socket socket) {
            this.name = name;
            this.input = input;
            this.output = output;
            this.shutdownSocket = socket;
        }

        StreamForwarder(String name, InputStream input, OutputStream output) {
            this(name, input, output, null);
        }

        @Override
        public void run() {
            byte[] buf = new byte[BUFFER_SIZE];
            int nread;
            try {
                while ((nread = input.read(buf, 0, BUFFER_SIZE)) != -1) {
                    output.write(buf, 0, nread);
                    output.flush();
                }
                log.debug("[{}] EOF reached", name);
            } catch (IOException ex) {
                log.debug("[{}] Stream forwarding ended: {}", name, ex.getMessage());
            }
            if (shutdownSocket != null) {
                try {
                    shutdownSocket.shutdownOutput();
                } catch (IOException e) {
                    log.debug("[{}] Error shutting down socket output: {}", name, e.getMessage());
                }
            }
        }
    }

    /**
     * Start bidirectional forwarding between local and network streams.
     * Blocks until both directions complete.
     *
     * @param localIn   local input stream (e.g. System.in)
     * @param localOut  local output stream (e.g. System.out)
     * @param netIn     network input stream (decrypted)
     * @param netOut    network output stream (encrypted)
     * @param socket    the socket (used to signal shutdown)
     */
    public static void forwardStreams(InputStream localIn, OutputStream localOut,
                                     InputStream netIn, OutputStream netOut,
                                     Socket socket) {
        Thread sender = new Thread(
                new StreamForwarder("sender", localIn, netOut, socket), "netpipe-sender");
        Thread receiver = new Thread(
                new StreamForwarder("receiver", netIn, localOut), "netpipe-receiver");

        sender.setDaemon(true);
        receiver.setDaemon(true);

        sender.start();
        receiver.start();

        try {
            sender.join();
            receiver.join();
        } catch (InterruptedException e) {
            log.debug("Forwarder interrupted");
            Thread.currentThread().interrupt();
        }
    }
}
