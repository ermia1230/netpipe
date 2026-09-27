package se.ermia.netpipe.client;

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
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.cert.CertificateException;
import java.time.Duration;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.util.Base64;

import se.ermia.netpipe.exception.TimestampValidationException;

/**
 * Secure NetPipe client: connects to a server and establishes an encrypted session.
 *
 * <p>Performs the full handshake protocol — ClientHello, ServerHello verification,
 * session-key exchange, Finished message verification — before forwarding data
 * through an AES-CTR encrypted channel.</p>
 *
 * <p>Skeleton provided by Peter Sjödin (KTH/IK2206).
 * Implementation and extensions by Ermia Ghaffari.</p>
 */
public class NetPipeClient {

    private static final Logger log = LoggerFactory.getLogger(NetPipeClient.class);
    private static final String PROGRAM_NAME = "NetPipeClient";
    private static final DateTimeFormatter TIMESTAMP_FORMAT =
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    private final String host;
    private final int port;
    private final String clientCertPath;
    private final String caCertPath;
    private final String clientKeyPath;

    public NetPipeClient(String host, int port, String clientCertPath,
                         String caCertPath, String clientKeyPath) {
        this.host = host;
        this.port = port;
        this.clientCertPath = clientCertPath;
        this.caCertPath = caCertPath;
        this.clientKeyPath = clientKeyPath;
    }

    /**
     * Connect to the server, perform the handshake, and forward streams.
     * This is the full lifecycle — connect, handshake, forward, close.
     */
    public void connect() throws IOException, NetPipeException, CertificateException {
        connect(System.in, System.out);
    }

    /**
     * Connect with custom input/output streams (for testing).
     */
    @SuppressWarnings("PMD.UseTryWithResources")
    public void connect(InputStream localIn, OutputStream localOut)
            throws IOException, NetPipeException, CertificateException {
        ProtocolStateMachine stateMachine = new ProtocolStateMachine("client");
        Socket socket = null;
        try {
            socket = new Socket(host, port);
            socket.setSoTimeout(NetPipeConfig.HANDSHAKE_TIMEOUT_MS);
            log.info("Connected to {}:{}", host, port);

            // 1. Send ClientHello
            String clientCertBase64 = CryptoUtils.encodeCertificate(clientCertPath);
            HandshakeMessage clientHello = new HandshakeMessage(MessageType.CLIENTHELLO);
            clientHello.putParameter("Certificate", clientCertBase64);
            clientHello.send(socket);
            stateMachine.transition(ProtocolState.CLIENT_HELLO_SENT);
            log.debug("Sent ClientHello");

            // 2. Receive ServerHello
            HandshakeMessage serverHello = HandshakeMessage.recv(socket);
            if (serverHello.getType() != MessageType.SERVERHELLO) {
                throw new InvalidMessageException(
                        "Expected SERVERHELLO, got " + serverHello.getType());
            }
            String serverCertBase64 = serverHello.getParameter("Certificate");
            if (serverCertBase64 == null) {
                throw new InvalidMessageException("SERVERHELLO missing Certificate parameter");
            }
            stateMachine.transition(ProtocolState.SERVER_HELLO_RECEIVED);
            log.debug("Received ServerHello");

            // 3. Verify server certificate
            HandshakeCertificate serverCert = CryptoUtils.decodeCertificate(serverCertBase64);
            HandshakeCertificate caCert = CryptoUtils.loadCACertificate(caCertPath);
            serverCert.verify(caCert);
            stateMachine.transition(ProtocolState.CERTIFICATE_VERIFIED);
            log.info("Server certificate verified: CN={}", serverCert.getCN());

            // 4. Send Session (encrypted session key + IV)
            SessionKey sessionKey = new SessionKey(NetPipeConfig.AES_KEY_LENGTH_BITS);
            SessionCipher sessionCipher = new SessionCipher(sessionKey);
            byte[] sessionKeyBytes = sessionKey.getKeyBytes();
            byte[] sessionIVBytes = sessionCipher.getIVBytes();

            HandshakeCrypto serverPubKeyCrypto = new HandshakeCrypto(serverCert);
            byte[] encryptedKey = serverPubKeyCrypto.encrypt(sessionKeyBytes);
            byte[] encryptedIV = serverPubKeyCrypto.encrypt(sessionIVBytes);

            HandshakeMessage sessionMsg = new HandshakeMessage(MessageType.SESSION);
            sessionMsg.putParameter("SessionKey",
                    Base64.getEncoder().encodeToString(encryptedKey));
            sessionMsg.putParameter("SessionIV",
                    Base64.getEncoder().encodeToString(encryptedIV));
            sessionMsg.send(socket);
            stateMachine.transition(ProtocolState.SESSION_SENT);
            log.debug("Sent Session parameters");

            // 5. Receive and verify ServerFinished
            verifyFinished(socket, serverCert, serverHello, null,
                    MessageType.SERVERFINISHED);
            stateMachine.transition(ProtocolState.SERVER_FINISHED_VERIFIED);
            log.debug("ServerFinished verified");

            // 6. Send ClientFinished
            HandshakeCrypto clientPrivateKey = CryptoUtils.loadPrivateKey(clientKeyPath);
            sendFinished(socket, clientPrivateKey, MessageType.CLIENTFINISHED,
                    clientHello, sessionMsg);
            stateMachine.transition(ProtocolState.CLIENT_FINISHED_SENT);
            log.debug("Sent ClientFinished");

            // 7. Establish encrypted session
            stateMachine.transition(ProtocolState.SECURE_CHANNEL_ESTABLISHED);
            socket.setSoTimeout(0); // Remove handshake timeout for data phase

            SessionCipher dataCipher = new SessionCipher(sessionKey, sessionIVBytes, false);
            InputStream decryptedIn = dataCipher.openDecryptedInputStream(socket.getInputStream());
            OutputStream encryptedOut = dataCipher.openEncryptedOutputStream(socket.getOutputStream());

            log.info("Secure session established with {}:{}", host, port);
            Forwarder.forwardStreams(localIn, localOut, decryptedIn, encryptedOut, socket);

        } catch (NetPipeException | IOException | CertificateException e) {
            stateMachine.transition(ProtocolState.FAILED);
            throw e;
        } catch (RuntimeException e) {
            stateMachine.transition(ProtocolState.FAILED);
            throw new NetPipeException("Unexpected runtime error during handshake", e);
        } finally {
            if (socket != null) {
                try {
                    socket.close();
                } catch (IOException e) {
                    log.debug("Error closing socket: {}", e.getMessage());
                }
            }
        }
    }

    /**
     * Send a Finished message with digest signature and encrypted timestamp.
     */
    static void sendFinished(Socket socket, HandshakeCrypto privateKey,
                             MessageType type, HandshakeMessage... messagesToSign)
            throws IOException, CryptoException {
        HandshakeDigest digest = new HandshakeDigest();
        for (HandshakeMessage msg : messagesToSign) {
            digest.update(msg.getBytes());
        }
        byte[] signature = privateKey.encrypt(digest.digest());

        String timestamp = LocalDateTime.now().format(TIMESTAMP_FORMAT);
        byte[] encryptedTimestamp = privateKey.encrypt(
                timestamp.getBytes(StandardCharsets.UTF_8));

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

    // --- CLI entry point ---

    private static void usage() {
        System.err.println("Usage: " + PROGRAM_NAME + " options");
        System.err.println("  --host=<hostname>");
        System.err.println("  --port=<portnumber>");
        System.err.println("  --usercert=<filename>");
        System.err.println("  --cacert=<filename>");
        System.err.println("  --key=<filename>");
    }

    public static void main(String[] args) {
        Arguments arguments = new Arguments();
        arguments.setArgumentSpec("host", "hostname");
        arguments.setArgumentSpec("port", "portnumber");
        arguments.setArgumentSpec("usercert", "client certificate file-path");
        arguments.setArgumentSpec("cacert", "CA certificate file-path");
        arguments.setArgumentSpec("key", "client private key file-path");

        try {
            arguments.loadArguments(args);
        } catch (IllegalArgumentException e) {
            usage();
            System.exit(1);
        }

        String host = NetPipeConfig.resolve(
                arguments.get("host"), "NETPIPE_HOST", NetPipeConfig.DEFAULT_HOST);
        int port = Integer.parseInt(NetPipeConfig.resolve(
                arguments.get("port"), "NETPIPE_PORT",
                String.valueOf(NetPipeConfig.DEFAULT_PORT)));
        String clientCertPath = arguments.get("usercert");
        String caCertPath = arguments.get("cacert");
        String clientKeyPath = arguments.get("key");

        NetPipeClient client = new NetPipeClient(host, port, clientCertPath, caCertPath, clientKeyPath);
        try {
            client.connect();
        } catch (Exception e) {
            log.error("Client error: {}", e.getMessage());
            System.exit(1);
        }
    }
}
