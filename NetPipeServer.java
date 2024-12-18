import java.net.*;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.time.Duration;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.Base64;
import java.io.*;

/**
 * This code is written by Ermia Ghaffari, and the skeleton of the code is provided by Peter Sjodin
 * at KTH. This code represents a server program that establishes a connection with 
 * {@code NetPipeClient} using a secure handshake protocol to authenticate both the server and 
 * client. In addition, {@code NetPipeServer} and {@code NetPipeClient} negotiate 
 * session parameters.
 * 
 * The handshake protocol is in plain-text. Hence, all the transferred data is encoded as text with 
 * binary data. We use Base64-encoding for transferring the plain-text data.
 * 
 * After the handshake is done, a session is established, and {@code NetPipeServer} will send 
 * data to {@code NetPipeClient} and receive data from {@code NetPipeClient}. In this way, 
 * the connection between the {@code NetPipeServer} and {@code NetPipeClient} is secured.
 * 
 * These resources were used for guidance and further understanding:
 * - https://stackoverflow.com/questions/22463062/how-can-i-parse-format-dates-with-localdatetime-java-8
 * - https://stackoverflow.com/questions/72111825/why-localdatetime-formatted-with-zone-offset
 * - https://stackoverflow.com/questions/88838/how-to-convert-strings-to-and-from-utf8-byte-arrays-in-java
 */

public class NetPipeServer {
    private static String PROGRAMNAME = NetPipeServer.class.getSimpleName();
    private static Arguments arguments;

    private static class SessionData {
        private byte[] sessionKey;
        private byte[] sessionIV;
        HandshakeMessage sessionMessage;

        public SessionData(byte[] sessionKey, byte[] sessionIV,HandshakeMessage sessionMessage ) {
            this.sessionKey = sessionKey;
            this.sessionIV = sessionIV;
            this.sessionMessage = sessionMessage;
        }

        public byte[] getSessionKey() {
            return sessionKey;
        }

        public byte[] getSessionIV() {
            return sessionIV;
        }
        public HandshakeMessage getSessionMessage(){
            return sessionMessage;
        }
    }
    private static class ClientHelloResponse {
        private final String clientCertificate;
        private final HandshakeMessage clientHello;
    
        public ClientHelloResponse(String clientCertificate, HandshakeMessage clientHello) {
            this.clientCertificate = clientCertificate;
            this.clientHello = clientHello;
        }
    
        public String getClientCertificate() {
            return clientCertificate;
        }
    
        public HandshakeMessage getclientHello() {
            return clientHello;
        }
    }

    /*
     * Usage: explain how to use the program, then exit with failure status
     */
    private static void usage() {
        String indent = "";
        System.err.println(indent + "Usage: " + PROGRAMNAME + " options");
        System.err.println(indent + "Where options are:");
        indent += "    ";
        System.err.println(indent + "--port=<portnumber>");
        System.err.println(indent + "--usercert=<filename>");
        System.err.println(indent + "--cacert=<filename>");
        System.err.println(indent + "--key=<filename>");
        System.exit(1);
    }

    /*
     * Parse arguments on command line
     */
    private static void parseArgs(String[] args) {
        arguments = new Arguments();
        arguments.setArgumentSpec("port", "portnumber");
        arguments.setArgumentSpec("usercert", "server certificate file-path");
        arguments.setArgumentSpec("cacert", "CA certificate file-path");
        arguments.setArgumentSpec("key", "server private key file-path");
        try {
        arguments.loadArguments(args);
        } catch (IllegalArgumentException ex) {
            usage();
        }
    }

    private static HandshakeMessage handshakeServerHello(Socket socket, String serverCertificate) throws IOException {
        HandshakeMessage serverHello = new HandshakeMessage(HandshakeMessage.MessageType.SERVERHELLO);
        serverHello.putParameter("Certificate", serverCertificate);
        serverHello.send(socket);
        System.out.println("ServerHello sent to the client.");
        //System.out.println(serverHello);
        return serverHello;
    }

    /*
    * The IDE was screaming about ClassNotFoundException, just put it here. No problem when using terminal
    * HandshakeMessage serverHello = HandshakeMessage.recv(socket);
    */
    private static ClientHelloResponse handshakeClientHelloRec(Socket socket) throws IOException, ClassNotFoundException{ 
        HandshakeMessage clientrHello = HandshakeMessage.recv(socket);
        System.out.println("Received ServerHello from the server.");
        HandshakeMessage.MessageType messageType = clientrHello.getType();
        String clientCertificate = clientrHello.getParameter("Certificate");
        if (clientCertificate == null || messageType != HandshakeMessage.MessageType.CLIENTHELLO) {
            throw new IOException("missing the Certificate parameter or type is not correct");
        }
        return new ClientHelloResponse(clientCertificate, clientrHello);
    }
    private static void verifyClientCertificate(HandshakeCertificate clientCert, String caCertificatePath) throws Exception{
        FileInputStream file = new FileInputStream(caCertificatePath);
        HandshakeCertificate caCertificate = new HandshakeCertificate(file);
        clientCert.verify(caCertificate);
        System.out.println("client certificate is verified using CA's certificate");
    }

    private static SessionData sessionRec(Socket socket, HandshakeCrypto serverPrivateKey) throws IOException, ClassNotFoundException, GeneralSecurityException{ 
        HandshakeMessage sessionMessage = HandshakeMessage.recv(socket);
        System.out.println("Received session from the client.");
        HandshakeMessage.MessageType messageType = sessionMessage.getType();
        String SessionKey = sessionMessage.getParameter("SessionKey");
        String SessionIV = sessionMessage.getParameter("SessionIV");
        if (sessionMessage == null || messageType != HandshakeMessage.MessageType.SESSION || SessionKey == null || SessionIV == null ) {
            throw new IOException("An error during the session exchange!");
        }
        byte[] SessionKeyDecoded = Base64.getDecoder().decode(SessionKey);
        byte[] SessionIVDecoded = Base64.getDecoder().decode(SessionIV);
        byte[] SessionKeyDecrypted = serverPrivateKey.decrypt(SessionKeyDecoded);
        byte[] SessionIVDecrypted = serverPrivateKey.decrypt(SessionIVDecoded);
        System.out.println("Session data recivied!");
        return new SessionData(SessionKeyDecrypted, SessionIVDecrypted, sessionMessage);
    }
    /*
    * Look at the refrence above for the timestamp creation and UTF_8.
    */
    private static void sendServerFinish(Socket socket, HandshakeCrypto serverPrivateKey, HandshakeMessage serverHello) throws GeneralSecurityException, IOException {
        HandshakeDigest digest = new HandshakeDigest();
        byte [] serverHelloToByte = serverHello.getBytes();
        digest.update(serverHelloToByte);
        byte [] encryptedServerhello = serverPrivateKey.encrypt(digest.digest());
        String encryptedServerhelloEncoded = Base64.getEncoder().encodeToString(encryptedServerhello);
        HandshakeMessage serverFinished = new HandshakeMessage(HandshakeMessage.MessageType.SERVERFINISHED);
        serverFinished.putParameter("Signature", encryptedServerhelloEncoded);
        String timeStamp = LocalDateTime.now(ZoneOffset.UTC).format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"));
        System.out.println(timeStamp);
        byte[] timeStampEncodedUTF = timeStamp.getBytes(StandardCharsets.UTF_8);
        byte[] encryptedTimeStamp = serverPrivateKey.encrypt(timeStampEncodedUTF);
        String base64EncryptedTimeStamp = Base64.getEncoder().encodeToString(encryptedTimeStamp); 
        serverFinished.putParameter("TimeStamp", base64EncryptedTimeStamp);
        serverFinished.send(socket);
        System.out.println("ServerFinished message sent to client.");
    }

    private static void clientFinishedRecVerify(Socket socket, HandshakeMessage sessionMessage, HandshakeMessage clienthello, HandshakeCertificate clientCertificate) throws IOException, GeneralSecurityException, ClassNotFoundException{
        HandshakeMessage clientFinished = HandshakeMessage.recv(socket);
        System.out.println("Received serverFinished from the server.");
        HandshakeMessage.MessageType messageType = clientFinished.getType();
        String clientSignature = clientFinished.getParameter("Signature");
        String timeStamp = clientFinished.getParameter("TimeStamp");
        if (clientSignature == null || timeStamp == null || messageType != HandshakeMessage.MessageType.CLIENTFINISHED) {
            throw new IOException("missing the signature or timeStamp or type is not correct");
        }
        HandshakeCrypto handshakeCrypto = new HandshakeCrypto(clientCertificate);
        byte[] encryptedTimeStamp = Base64.getDecoder().decode(timeStamp);
        byte[] decryptedTimeStampBytes = handshakeCrypto.decrypt(encryptedTimeStamp);
        String decryptedTimeStamp = new String(decryptedTimeStampBytes, StandardCharsets.UTF_8);
        System.out.println(decryptedTimeStamp);
        validateTimestamp(decryptedTimeStamp);
        byte[] serverSignatureByte = Base64.getDecoder().decode(clientSignature);
        byte[] decryptedSignature = handshakeCrypto.decrypt(serverSignatureByte);
        HandshakeDigest digest = new HandshakeDigest();
        digest.update(clienthello.getBytes());
        digest.update(sessionMessage.getBytes());
        byte[] expServerDigest = digest.digest();
        if (MessageDigest.isEqual(decryptedSignature, expServerDigest)) {
            System.out.println("The decrypted signature matches the expected server digest.");
        } else {
            throw new IOException("Signature validation failed");
        }
    }
    private static void validateTimestamp(String decryptedTimeStamp) throws IOException {
        LocalDateTime receivedTime =  LocalDateTime.parse(decryptedTimeStamp, DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"));
        LocalDateTime currentTime = LocalDateTime.now(ZoneOffset.UTC);
        Duration timeDifference = Duration.between(receivedTime, currentTime);
        System.out.println("The duration is : " + timeDifference.toSeconds());
        if (Math.abs(timeDifference.toSeconds()) > 300) {
            throw new IOException("Timestamp validation failed");
        }else{
            System.out.println("TimeStamp is valid!");
        }
    }

    /*
     * Main program.
     * Parse arguments on command line, wait for connection from client,
     * and call switcher to switch data between streams.
     */
    public static void main( String[] args) throws Exception{
        parseArgs(args);
        ServerSocket serverSocket = null;

        int port = Integer.parseInt(arguments.get("port"));
        String serverCertPath = arguments.get("usercert");
        String CaCertPath = arguments.get("cacert");
        String serverKeyPath = arguments.get("key");
        try {
            //System.out.println( "usercert:  " + serverCertPath + " cacert: " +CaCertPath + " key: " + serverKeyPath );
            serverSocket = new ServerSocket(port);
        } catch (IOException ex) {
            System.err.printf("Error listening on port %d\n", port);
            System.exit(1);
        }
        Socket socket = null;
        try {
            socket = serverSocket.accept();
        } catch (IOException ex) {
            System.out.printf("Error accepting connection on port %d\n", port);
            System.exit(1);
        }
        try {
            ClientHelloResponse clientHelloRes =  handshakeClientHelloRec(socket);
            String clientCertificate = clientHelloRes.getClientCertificate();
            HandshakeCertificate clientCertificateDecoded = Utils.certificateDecode(clientCertificate);
            verifyClientCertificate(clientCertificateDecoded, CaCertPath);
            String serverCertificate = Utils.certificateEncode(serverCertPath);
            HandshakeMessage serverHello = handshakeServerHello(socket, serverCertificate);
            HandshakeCrypto serverPrivateKey = Utils.readPrivateKey(serverKeyPath);
            SessionData sessionData = sessionRec(socket, serverPrivateKey);
            //System.out.println("Session Key: " + Base64.getEncoder().encodeToString(sessionData.getSessionKey()));
            //System.out.println("Session IV: " + Base64.getEncoder().encodeToString(sessionData.getSessionIV()));
            sendServerFinish(socket, serverPrivateKey, serverHello);
            clientFinishedRecVerify(socket, sessionData.getSessionMessage(), clientHelloRes.getclientHello(), clientCertificateDecoded);
            byte [] sessionKeyInBytes = sessionData.getSessionKey();
            SessionKey sessionKey = new SessionKey(sessionKeyInBytes);
            SessionCipher cipher = new SessionCipher(sessionKey, sessionData.getSessionIV());
            InputStream input = cipher.openDecryptedInputStream(socket.getInputStream());
            OutputStream output = cipher.openEncryptedOutputStream(socket.getOutputStream());
            Forwarder.forwardStreams(System.in, System.out, input, output, socket);
        } catch (IOException ex) {
            System.out.println("Stream forwarding error\n");
            System.exit(1);
        }
    }
}
