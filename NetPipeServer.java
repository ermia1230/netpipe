import java.net.*;
import java.security.GeneralSecurityException;
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
 * - 
 */

public class NetPipeServer {
    private static String PROGRAMNAME = NetPipeServer.class.getSimpleName();
    private static Arguments arguments;

    private static class SessionData {
        private byte[] sessionKey;
        private byte[] sessionIV;

        public SessionData(byte[] sessionKey, byte[] sessionIV) {
            this.sessionKey = sessionKey;
            this.sessionIV = sessionIV;
        }

        public byte[] getSessionKey() {
            return sessionKey;
        }

        public byte[] getSessionIV() {
            return sessionIV;
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

    private static void handshakeServerHello(Socket socket, String serverCertificate) throws IOException {
        HandshakeMessage serverHello = new HandshakeMessage(HandshakeMessage.MessageType.SERVERHELLO);
        serverHello.putParameter("Certificate", serverCertificate);
        serverHello.send(socket);
        System.out.println("ServerHello sent to the client.");
    }

    /*
    * The IDE was screaming about ClassNotFoundException, just put it here. No problem when using terminal
    * HandshakeMessage serverHello = HandshakeMessage.recv(socket);
    */
    private static String handshakeClientHelloRec(Socket socket) throws IOException, ClassNotFoundException{ 
        HandshakeMessage clientrHello = HandshakeMessage.recv(socket);
        System.out.println("Received ServerHello from the server.");
        HandshakeMessage.MessageType messageType = clientrHello.getType();
        String clientCertificate = clientrHello.getParameter("Certificate");
        if (clientCertificate == null || messageType != HandshakeMessage.MessageType.CLIENTHELLO) {
            throw new IOException("missing the Certificate parameter or type is not correct");
        }
        return clientCertificate;
    }
    private static void verifyClientCertificate(HandshakeCertificate clientCert, String caCertificatePath) throws Exception{
        FileInputStream file = new FileInputStream(caCertificatePath);
        HandshakeCertificate caCertificate = new HandshakeCertificate(file);
        clientCert.verify(caCertificate);
        System.out.println("client certificate is verified using CA's certificate");
    }

    private static SessionData sessionRec(Socket socket, HandshakeCrypto serverPrivateKey) throws IOException, ClassNotFoundException, GeneralSecurityException{ 
        HandshakeMessage sessionMessage = HandshakeMessage.recv(socket);
        System.out.println("Received ServerHello from the server.");
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
        return new SessionData(SessionKeyDecrypted, SessionIVDecrypted );
    }
    private static HandshakeCrypto readServerPrivateKey(String serverKeyPath) throws GeneralSecurityException, IOException {
        try (FileInputStream fileInputStream = new FileInputStream(serverKeyPath);
             ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream()) {
            byte[] buffer = new byte[2048];  
            int bytesRead;
            while ((bytesRead = fileInputStream.read(buffer)) != -1) {
                byteArrayOutputStream.write(buffer, 0, bytesRead);
            }
            byte[] serverPrivateKeyBytes = byteArrayOutputStream.toByteArray();
            return new HandshakeCrypto(serverPrivateKeyBytes);
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
            String serverCertificate = handshakeClientHelloRec(socket);
            HandshakeCertificate serverCertificateDecoded = Utils.certificateDecode(serverCertificate);
            verifyClientCertificate(serverCertificateDecoded, CaCertPath);
            String clientCertificate = Utils.certificateEncode(serverCertPath);
            handshakeServerHello(socket, clientCertificate);
            HandshakeCrypto serverPrivateKey = readServerPrivateKey(serverKeyPath);
            SessionData sessionData = sessionRec(socket, serverPrivateKey);
            System.out.println("Session Key: " + Base64.getEncoder().encodeToString(sessionData.getSessionKey()));
            System.out.println("Session IV: " + Base64.getEncoder().encodeToString(sessionData.getSessionIV()));
            Forwarder.forwardStreams(System.in, System.out, socket.getInputStream(), socket.getOutputStream(), socket);
        } catch (IOException ex) {
            System.out.println("Stream forwarding error\n");
            System.exit(1);
        }
    }
}
