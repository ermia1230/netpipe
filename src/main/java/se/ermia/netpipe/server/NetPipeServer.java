package se.ermia.netpipe.server;

import se.ermia.netpipe.config.Arguments;
import se.ermia.netpipe.config.NetPipeConfig;
import se.ermia.netpipe.crypto.HandshakeCertificate;
import se.ermia.netpipe.crypto.HandshakeCrypto;
import se.ermia.netpipe.crypto.HandshakeDigest;
import se.ermia.netpipe.crypto.SessionCipher;
import se.ermia.netpipe.crypto.SessionKey;
import se.ermia.netpipe.exception.CryptoException;
import se.ermia.netpipe.exception.HandshakeException;
import se.ermia.netpipe.exception.InvalidMessageException;
import se.ermia.netpipe.exception.NetPipeException;
import se.ermia.netpipe.exception.TimestampValidationException;
import se.ermia.netpipe.protocol.HandshakeMessage;
import se.ermia.netpipe.protocol.MessageType;
import se.ermia.netpipe.protocol.ProtocolState;
import se.ermia.netpipe.protocol.ProtocolStateMachine;
import se.ermia.netpipe.transport.Forwarder;
import se.ermia.netpipe.util.CryptoUtils;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.cert.CertificateException;
import java.time.Duration;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.util.Base64;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Secure NetPipe server: accepts client connections and establishes encrypted sessions.
 *
 * <p>Supports multiple concurrent clients via a thread pool. Each client connection
 * goes through the full handshake protocol before establishing an encrypted
 * AES-CTR bidirectional channel.</p>
 *
 * <p>Skeleton provided by Peter Sjödin (KTH/IK2206).
 * Implementation and extensions by Ermia Ghaffari.</p>
 */
public class NetPipeServer {

    private static final Logger log = LoggerFactory.getLogger(NetPipeServer.class);
    private static final String PROGRAM_NAME = "NetPipeServer";
    private static final DateTimeFormatter TIMESTAMP_FORMAT =
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    private final int port;
    private final String serverCertPath;
    private final String caCertPath;
    private final String serverKeyPath;
    private final AtomicBoolean running = new AtomicBoolean(false);
    private volatile ServerSocket serverSocket;

    public NetPipeServer(int port, String serverCertPath, String caCertPath, String serverKeyPath) {
        this.port = port;
        this.serverCertPath = serverCertPath;
        this.caCertPath = caCertPath;
        this.serverKeyPath = serverKeyPath;
    }

    /**
     * Start the server, accepting connections until {@link #stop()} is called.
     */
    public void start() throws IOException {
        serverSocket = new ServerSocket(port);
        serverSocket.setSoTimeout(NetPipeConfig.SOCKET_TIMEOUT_MS);
        running.set(true);

        ExecutorService executor = Executors.newCachedThreadPool(r -> {
            Thread t = new Thread(r, "netpipe-handler");
            t.setDaemon(true);
            return t;
        });

        log.info("Server listening on port {}", port);

        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            log.info("Shutdown hook triggered");
            stop();
        }, "netpipe-shutdown"));

        try {
            while (running.get()) {
                try {
                    Socket clientSocket = serverSocket.accept();
                    clientSocket.setSoTimeout(NetPipeConfig.HANDSHAKE_TIMEOUT_MS);
                    log.info("Client connected from {}", clientSocket.getRemoteSocketAddress());
                    executor.submit(() -> handleClient(clientSocket));
                } catch (SocketTimeoutException e) {
                    // Normal — just loop and check running flag
                }
            }
        } finally {
            executor.shutdown();
            try {
                if (!executor.awaitTermination(5, TimeUnit.SECONDS)) {
                    executor.shutdownNow();
                }
            } catch (InterruptedException e) {
                executor.shutdownNow();
                Thread.currentThread().interrupt();
            }
        }
    }

    /**
     * Accept exactly one client, perform handshake, then forward streams.
     * Used for testing and single-connection mode.
     */
    public void acceptOneClient() throws IOException {
        acceptOneClient(System.in, System.out);
    }

    @SuppressWarnings("PMD.UseTryWithResources")
    public void acceptOneClient(InputStream localIn, OutputStream localOut) throws IOException {
        serverSocket = new ServerSocket(port);
        running.set(true);
        log.info("Server listening on port {} (single-client mode)", port);

        try {
            Socket clientSocket = serverSocket.accept();
            clientSocket.setSoTimeout(NetPipeConfig.HANDSHAKE_TIMEOUT_MS);
            log.info("Client connected from {}", clientSocket.getRemoteSocketAddress());
            handleClient(clientSocket, localIn, localOut);
        } finally {
            closeQuietly(serverSocket);
        }
    }

    /**
     * Stop the server.
     */
    public void stop() {
        running.set(false);
        closeQuietly(serverSocket);
        log.info("Server stopped");
    }

    /**
     * Return the actual port the server is listening on (useful when port 0 is used).
     */
    public int getLocalPort() {
        ServerSocket ss = serverSocket;
        return (ss != null) ? ss.getLocalPort() : -1;
    }

    /**
     * Return whether the server is currently running.
     */
    public boolean isRunning() {
        return running.get();
    }

    private void handleClient(Socket socket) {
        handleClient(socket, System.in, System.out);
    }

    @SuppressWarnings("PMD.UseTryWithResources")
    private void handleClient(Socket socket, InputStream localIn, OutputStream localOut) {
        ProtocolStateMachine stateMachine = new ProtocolStateMachine("server");
        try {
            // 1. Receive ClientHello
            HandshakeMessage clientHello = HandshakeMessage.recv(socket);
            if (clientHello.getType() != MessageType.CLIENTHELLO) {
                throw new InvalidMessageException(
                        "Expected CLIENTHELLO, got " + clientHello.getType());
            }
            String clientCertBase64 = clientHello.getParameter("Certificate");
            if (clientCertBase64 == null) {
                throw new InvalidMessageException("CLIENTHELLO missing Certificate parameter");
            }
            stateMachine.transition(ProtocolState.CLIENT_HELLO_RECEIVED);
            log.debug("Received ClientHello");

            // 2. Verify client certificate
            HandshakeCertificate clientCert = CryptoUtils.decodeCertificate(clientCertBase64);
            HandshakeCertificate caCert = CryptoUtils.loadCACertificate(caCertPath);
            clientCert.verify(caCert);
            stateMachine.transition(ProtocolState.CERTIFICATE_VERIFIED);
            log.info("Client certificate verified: CN={}", clientCert.getCN());

            // 3. Send ServerHello
            String serverCertBase64 = CryptoUtils.encodeCertificate(serverCertPath);
            HandshakeMessage serverHello = new HandshakeMessage(MessageType.SERVERHELLO);
            serverHello.putParameter("Certificate", serverCertBase64);
            serverHello.send(socket);
            stateMachine.transition(ProtocolState.SERVER_HELLO_SENT);
            log.debug("Sent ServerHello");

            // 4. Receive Session (encrypted session key + IV)
            HandshakeCrypto serverPrivateKey = CryptoUtils.loadPrivateKey(serverKeyPath);
            HandshakeMessage sessionMsg = HandshakeMessage.recv(socket);
            if (sessionMsg.getType() != MessageType.SESSION) {
                throw new InvalidMessageException(
                        "Expected SESSION, got " + sessionMsg.getType());
            }
            String sessionKeyB64 = sessionMsg.getParameter("SessionKey");
            String sessionIVB64 = sessionMsg.getParameter("SessionIV");
            if (sessionKeyB64 == null || sessionIVB64 == null) {
                throw new InvalidMessageException("SESSION missing SessionKey or SessionIV");
            }
            byte[] sessionKeyBytes = serverPrivateKey.decrypt(
                    Base64.getDecoder().decode(sessionKeyB64));
            byte[] sessionIVBytes = serverPrivateKey.decrypt(
                    Base64.getDecoder().decode(sessionIVB64));
            stateMachine.transition(ProtocolState.SESSION_RECEIVED);
            log.debug("Session parameters received and decrypted");

            // 5. Send ServerFinished
            sendFinished(socket, serverPrivateKey, serverHello);
            stateMachine.transition(ProtocolState.SERVER_FINISHED_SENT);
            log.debug("Sent ServerFinished");

            // 6. Receive and verify ClientFinished
            verifyFinished(socket, clientCert, clientHello, sessionMsg,
                    MessageType.CLIENTFINISHED);
            stateMachine.transition(ProtocolState.CLIENT_FINISHED_VERIFIED);
            log.info("ClientFinished verified — handshake complete");

            // 7. Establish encrypted session
            stateMachine.transition(ProtocolState.SECURE_CHANNEL_ESTABLISHED);
            socket.setSoTimeout(0); // Remove handshake timeout for data phase

            SessionKey sessionKey = new SessionKey(sessionKeyBytes);
            SessionCipher cipher = new SessionCipher(sessionKey, sessionIVBytes);
            InputStream decryptedIn = cipher.openDecryptedInputStream(socket.getInputStream());
            OutputStream encryptedOut = cipher.openEncryptedOutputStream(socket.getOutputStream());

            log.info("Secure session established with {}", socket.getRemoteSocketAddress());
            Forwarder.forwardStreams(localIn, localOut, decryptedIn, encryptedOut, socket);

            stateMachine.transition(ProtocolState.CLOSED);
        } catch (NetPipeException | IOException | CertificateException e) {
            log.warn("Handshake failed: {}", e.getMessage());
            stateMachine.transition(ProtocolState.FAILED);
        } finally {
            closeQuietly(socket);
        }
    }

    /**
     * Send a Finished message with digest signature and encrypted timestamp.
     */
    static void sendFinished(Socket socket, HandshakeCrypto privateKey,
                             HandshakeMessage... messagesToSign)
            throws IOException, CryptoException {
        HandshakeDigest digest = new HandshakeDigest();
        for (HandshakeMessage msg : messagesToSign) {
            digest.update(msg.getBytes());
        }
        byte[] signature = privateKey.encrypt(digest.digest());

        String timestamp = LocalDateTime.now().format(TIMESTAMP_FORMAT);
        byte[] encryptedTimestamp = privateKey.encrypt(
                timestamp.getBytes(StandardCharsets.UTF_8));

        MessageType type = (messagesToSign.length == 1)
                ? MessageType.SERVERFINISHED : MessageType.CLIENTFINISHED;

        HandshakeMessage finished = new HandshakeMessage(type);
        finished.putParameter("Signature", Base64.getEncoder().encodeToString(signature));
        finished.putParameter("TimeStamp", Base64.getEncoder().encodeToString(encryptedTimestamp));
        finished.send(socket);
    }

    /**
     * Receive and verify a Finished message.
     */
    static void verifyFinished(Socket socket, HandshakeCertificate peerCert,
                               HandshakeMessage expectedMsg1, HandshakeMessage expectedMsg2,
                               MessageType expectedType)
            throws IOException, HandshakeException, CryptoException, InvalidMessageException {
        HandshakeMessage finished = HandshakeMessage.recv(socket);
        if (finished.getType() != expectedType) {
            throw new InvalidMessageException(
                    "Expected " + expectedType + ", got " + finished.getType());
        }
        String signatureB64 = finished.getParameter("Signature");
        String timestampB64 = finished.getParameter("TimeStamp");
        if (signatureB64 == null || timestampB64 == null) {
            throw new InvalidMessageException(
                    expectedType + " missing Signature or TimeStamp");
        }

        HandshakeCrypto peerCrypto = new HandshakeCrypto(peerCert);
        byte[] decryptedTimestamp = peerCrypto.decrypt(
                Base64.getDecoder().decode(timestampB64));
        String timestampStr = new String(decryptedTimestamp, StandardCharsets.UTF_8);
        validateTimestamp(timestampStr);

        byte[] decryptedSignature = peerCrypto.decrypt(
                Base64.getDecoder().decode(signatureB64));
        HandshakeDigest digest = new HandshakeDigest();
        digest.update(expectedMsg1.getBytes());
        if (expectedMsg2 != null) {
            digest.update(expectedMsg2.getBytes());
        }

        if (!MessageDigest.isEqual(decryptedSignature, digest.digest())) {
            throw new HandshakeException("Signature verification failed");
        }
    }

    /**
     * Validate that a timestamp is within the allowed clock skew.
     */
    static void validateTimestamp(String timestampStr) throws TimestampValidationException {
        try {
            LocalDateTime received = LocalDateTime.parse(timestampStr, TIMESTAMP_FORMAT);
            long skewSeconds = Math.abs(
                    Duration.between(received, LocalDateTime.now()).toSeconds());
            if (skewSeconds > NetPipeConfig.MAX_TIMESTAMP_SKEW_SECONDS) {
                throw new TimestampValidationException(
                        "Timestamp skew too large: " + skewSeconds + "s (max "
                        + NetPipeConfig.MAX_TIMESTAMP_SKEW_SECONDS + "s)");
            }
            log.debug("Timestamp valid (skew: {}s)", skewSeconds);
        } catch (DateTimeParseException e) {
            throw new TimestampValidationException("Malformed timestamp: " + timestampStr, e);
        }
    }

    private static void closeQuietly(java.io.Closeable closeable) {
        if (closeable != null) {
            try {
                closeable.close();
            } catch (IOException e) {
                log.debug("Error closing resource: {}", e.getMessage());
            }
        }
    }

    // --- CLI entry point ---

    private static void usage() {
        System.err.println("Usage: " + PROGRAM_NAME + " options");
        System.err.println("  --port=<portnumber>");
        System.err.println("  --usercert=<filename>");
        System.err.println("  --cacert=<filename>");
        System.err.println("  --key=<filename>");
    }

    public static void main(String[] args) {
        Arguments arguments = new Arguments();
        arguments.setArgumentSpec("port", "portnumber");
        arguments.setArgumentSpec("usercert", "server certificate file-path");
        arguments.setArgumentSpec("cacert", "CA certificate file-path");
        arguments.setArgumentSpec("key", "server private key file-path");

        try {
            arguments.loadArguments(args);
        } catch (IllegalArgumentException e) {
            usage();
            System.exit(1);
        }

        int port = Integer.parseInt(NetPipeConfig.resolve(
                arguments.get("port"), "NETPIPE_PORT",
                String.valueOf(NetPipeConfig.DEFAULT_PORT)));
        String serverCertPath = arguments.get("usercert");
        String caCertPath = arguments.get("cacert");
        String serverKeyPath = arguments.get("key");

        NetPipeServer server = new NetPipeServer(port, serverCertPath, caCertPath, serverKeyPath);
        try {
            server.start();
        } catch (IOException e) {
            log.error("Server error: {}", e.getMessage());
            System.exit(1);
        }
    }
}
