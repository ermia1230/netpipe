import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.time.Duration;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.Base64;

/**
 * This code is written by Ermia Ghaffari, and the skeleton of the code is provided by Peter Sjodin
 * at KTH. This code represents a client program that establishes a connection with 
 * {@code NetPipeServer} using a secure handshake protocol to authenticate both the client and 
 * server. In addition, {@code NetPipeServer} and {@code NetPipeClient} negotiate 
 * session parameters.
 * 
 * The handshake protocol is in plain-text. Hence, all the transferred data is encoded as text with 
 * binary data. We use Base64-encoding for transferring the plain-text data.
 * 
 * After the handshale is done, we will get an established session and {@code NetPipeClient} will 
 * sne data to {@code NetPipeServer} and recive data from {@code NetPipeServer}. In this way, 
 * we secure the connection between the {@code NetPipeServer} and {@code NetPipeClient}. 
 *
 * These resources were used for guidance and further understanding:
 * - https://stackoverflow.com/questions/22463062/how-can-i-parse-format-dates-with-localdatetime-java-8
 * - https://stackoverflow.com/questions/72111825/why-localdatetime-formatted-with-zone-offset
 * - https://stackoverflow.com/questions/88838/how-to-convert-strings-to-and-from-utf8-byte-arrays-in-java
 */

public class NetPipeClient {
    private static String PROGRAMNAME = NetPipeClient.class.getSimpleName();
    private static Arguments arguments;
    private static final int AES_KEY_LENGTH = 128; 

    private static class ServerHelloResponse {
        private final String serverCertificate;
        private final HandshakeMessage serverHello;
    
        public ServerHelloResponse(String serverCertificate, HandshakeMessage serverHello) {
            this.serverCertificate = serverCertificate;
            this.serverHello = serverHello;
        }
    
        public String getServerCertificate() {
            return serverCertificate;
        }
    
        public HandshakeMessage getServerHello() {
            return serverHello;
        }
    }
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

    /*
     * Usage: explain how to use the program, then exit with failure status
     */
    private static void usage() {
        String indent = "";
        System.err.println(indent + "Usage: " + PROGRAMNAME + " options");
        System.err.println(indent + "Where options are:");
        indent += "    ";
        System.err.println(indent + "--host=<hostname>");
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
        arguments.setArgumentSpec("host", "hostname");
        arguments.setArgumentSpec("port", "portnumber");
        arguments.setArgumentSpec("usercert", "client certificate file-path");
        arguments.setArgumentSpec("cacert", "CA certificate file-path");
        arguments.setArgumentSpec("key", "client private key file-path");
        try {
        arguments.loadArguments(args);
        } catch (IllegalArgumentException ex) {
            usage();
        }
    }

    private static HandshakeMessage handshakeClientHello(Socket socket, String clientCertificate) throws IOException {
        HandshakeMessage clientHello = new HandshakeMessage(HandshakeMessage.MessageType.CLIENTHELLO);
        clientHello.putParameter("Certificate", clientCertificate);
        clientHello.send(socket);
        System.out.println("ClientHello sent to the server.");
        return clientHello;
    }

    /*
    * The IDE was screaming about ClassNotFoundException, just put it here. No problem when using terminal
    * HandshakeMessage serverHello = HandshakeMessage.recv(socket);
    */
    private static ServerHelloResponse handshakeServerHelloRec(Socket socket) throws IOException, ClassNotFoundException{ 
        HandshakeMessage serverHello = HandshakeMessage.recv(socket);
        System.out.println("Received ServerHello from the server.");
        //System.out.println(serverHello);
        HandshakeMessage.MessageType messageType = serverHello.getType();
        String serverCertificate = serverHello.getParameter("Certificate");
        if (serverCertificate == null || messageType != HandshakeMessage.MessageType.SERVERHELLO) {
            throw new IOException("missing the Certificate parameter or type is not correct");
        }
        return new ServerHelloResponse(serverCertificate, serverHello);
    }
    
    private static void verifyServerCertificate(HandshakeCertificate serverCert, String caCertificatePath) throws Exception{
        FileInputStream file = new FileInputStream(caCertificatePath);
        HandshakeCertificate caCertificate = new HandshakeCertificate(file);
        serverCert.verify(caCertificate);
        System.out.println("server certificate is verified using CA's certificate");
    }


    private static SessionData sendSession(Socket socket, HandshakeCertificate handshakeCertificate) throws Exception {
        SessionKey sessionKey = new SessionKey(AES_KEY_LENGTH);
        SessionCipher sessionCipher = new SessionCipher(sessionKey);
        byte[] sessionKeyBytes = sessionKey.getKeyBytes();
        byte[] sessionIVBytes = sessionCipher.getIVBytes();
        HandshakeCrypto handshakeCrypto = new HandshakeCrypto(handshakeCertificate);
        byte[] encryptedSessionKey = handshakeCrypto.encrypt(sessionKeyBytes);
        byte[] encryptedSessionIV = handshakeCrypto.encrypt(sessionIVBytes);
        String base64EncryptedSessionKey = Base64.getEncoder().encodeToString(encryptedSessionKey);
        String base64EncryptedSessionIV = Base64.getEncoder().encodeToString(encryptedSessionIV);
        HandshakeMessage sessionMessage = new HandshakeMessage(HandshakeMessage.MessageType.SESSION);
        sessionMessage.putParameter("SessionKey", base64EncryptedSessionKey);
        sessionMessage.putParameter("SessionIV", base64EncryptedSessionIV);
        sessionMessage.send(socket);
        System.out.println("SessionKey and SessionIV sent to the server.");
        //System.out.println(Base64.getEncoder().encodeToString(sessionKeyBytes));
        //System.out.println(Base64.getEncoder().encodeToString(sessionIVBytes));
        return new SessionData(sessionKeyBytes, sessionIVBytes, sessionMessage);

    }
    private static void serverFinishedRecVerify(Socket socket, HandshakeMessage excpectedServerFinished, HandshakeCertificate serverCertificate) throws IOException, GeneralSecurityException, ClassNotFoundException{
        HandshakeMessage serverFinished = HandshakeMessage.recv(socket);
        System.out.println("Received serverFinished from the server.");
        HandshakeMessage.MessageType messageType = serverFinished.getType();
        String serverSignature = serverFinished.getParameter("Signature");
        String timeStamp = serverFinished.getParameter("TimeStamp");
        if (serverSignature == null || timeStamp == null || messageType != HandshakeMessage.MessageType.SERVERFINISHED) {
            throw new IOException("missing the signature or timeStamp or type is not correct");
        }
        HandshakeCrypto handshakeCrypto = new HandshakeCrypto(serverCertificate);
        byte[] encryptedTimeStamp = Base64.getDecoder().decode(timeStamp);
        byte[] decryptedTimeStampBytes = handshakeCrypto.decrypt(encryptedTimeStamp);
        String decryptedTimeStamp = new String(decryptedTimeStampBytes, StandardCharsets.UTF_8);
        System.out.println(decryptedTimeStamp);
        validateTimestamp(decryptedTimeStamp);
        byte[] serverSignatureByte = Base64.getDecoder().decode(serverSignature);
        byte[] decryptedSignature = handshakeCrypto.decrypt(serverSignatureByte);
        HandshakeDigest digest = new HandshakeDigest();
        digest.update(excpectedServerFinished.getBytes());
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

    private static void sendClientFinish(Socket socket, HandshakeCrypto clientPrivateKey, HandshakeMessage clinetHello, HandshakeMessage sessionMessage) throws GeneralSecurityException, IOException {
        HandshakeDigest digest = new HandshakeDigest();
        byte [] clientHelloToByte = clinetHello.getBytes();
        byte [] sessionMessageToByte = sessionMessage.getBytes();
        digest.update(clientHelloToByte);
        digest.update(sessionMessageToByte);
        byte [] encryptedClienthello = clientPrivateKey.encrypt(digest.digest());
        String encryptedClienthelloEncoded = Base64.getEncoder().encodeToString(encryptedClienthello);
        HandshakeMessage serverFinished = new HandshakeMessage(HandshakeMessage.MessageType.CLIENTFINISHED);
        serverFinished.putParameter("Signature", encryptedClienthelloEncoded);
        String timeStamp = LocalDateTime.now(ZoneOffset.UTC).format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"));
        System.out.println(timeStamp);
        byte[] timeStampEncodedUTF = timeStamp.getBytes(StandardCharsets.UTF_8);
        byte[] encryptedTimeStamp = clientPrivateKey.encrypt(timeStampEncodedUTF);
        String base64EncryptedTimeStamp = Base64.getEncoder().encodeToString(encryptedTimeStamp); 
        serverFinished.putParameter("TimeStamp", base64EncryptedTimeStamp);
        serverFinished.send(socket);
        System.out.println("ServerFinished message sent to client.");
    }

    /*
     * Main program.
     * Parse arguments on command line, connect to server,
     * and call forwarder to forward data between streams.
     */
    public static void main( String[] args) throws Exception {
        Socket socket = null;

        parseArgs(args);
        String host = arguments.get("host");
        int port = Integer.parseInt(arguments.get("port"));
        String clientCertPath = arguments.get("usercert");
        String CaCertPath = arguments.get("cacert");
        String clientKeyPath = arguments.get("key");
        try {
            //System.out.println( "usercert: "+ clientCertPath + " cacert: " +CaCertPath + " key: " +clientKeyPath );
            socket = new Socket(host, port);
        } catch (IOException ex) {
            System.err.printf("Can't connect to server at %s:%d\n", host, port);
            System.exit(1);
        }
        try {
            String clientCertificate = Utils.certificateEncode(clientCertPath);
            HandshakeMessage clientHello = handshakeClientHello(socket, clientCertificate);
            ServerHelloResponse serverHelloRes = handshakeServerHelloRec(socket);
            String serverCertificate = serverHelloRes.getServerCertificate();
            HandshakeCertificate serverCertificateDecoded = Utils.certificateDecode(serverCertificate);
            verifyServerCertificate(serverCertificateDecoded, CaCertPath);
            SessionData sessionData = sendSession(socket,serverCertificateDecoded);
            HandshakeMessage sessionMessage = sessionData.getSessionMessage();
            serverFinishedRecVerify(socket, serverHelloRes.getServerHello(), serverCertificateDecoded);
            HandshakeCrypto clientPrivateKey = Utils.readPrivateKey(clientKeyPath);
            sendClientFinish(socket,clientPrivateKey, clientHello, sessionMessage);
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
