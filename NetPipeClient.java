import java.io.*;
import java.net.*;
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
 * - 
 * - 
 */

public class NetPipeClient {
    private static String PROGRAMNAME = NetPipeClient.class.getSimpleName();
    private static Arguments arguments;
    private static final int AES_KEY_LENGTH = 128; 

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

    private static void handshakeClientHello(Socket socket, String clientCertificate) throws IOException {
        HandshakeMessage clientHello = new HandshakeMessage(HandshakeMessage.MessageType.CLIENTHELLO);
        clientHello.putParameter("Certificate", clientCertificate);
        clientHello.send(socket);
        System.out.println("ClientHello sent to the server.");
    }

    /*
    * The IDE was screaming about ClassNotFoundException, just put it here. No problem when using terminal
    * HandshakeMessage serverHello = HandshakeMessage.recv(socket);
    */
    private static String handshakeServerHelloRec(Socket socket) throws IOException, ClassNotFoundException{ 
        HandshakeMessage serverHello = HandshakeMessage.recv(socket);
        System.out.println("Received ServerHello from the server.");
        HandshakeMessage.MessageType messageType = serverHello.getType();
        String serverCertificate = serverHello.getParameter("Certificate");
        if (serverCertificate == null || messageType != HandshakeMessage.MessageType.SERVERHELLO) {
            throw new IOException("missing the Certificate parameter or type is not correct");
        }
        return serverCertificate;
    }
    private static void verifyServerCertificate(HandshakeCertificate serverCert, String caCertificatePath) throws Exception{
        FileInputStream file = new FileInputStream(caCertificatePath);
        HandshakeCertificate caCertificate = new HandshakeCertificate(file);
        serverCert.verify(caCertificate);
        System.out.println("server certificate is verified using CA's certificate");
    }


    private static void sendSession(Socket socket, HandshakeCertificate handshakeCertificate) throws Exception {
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
        System.out.println(Base64.getEncoder().encodeToString(sessionKeyBytes));
        System.out.println(Base64.getEncoder().encodeToString(sessionIVBytes));

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
            handshakeClientHello(socket, clientCertificate);
            String serverCertificate = handshakeServerHelloRec(socket);
            HandshakeCertificate serverCertificateDecoded = Utils.certificateDecode(serverCertificate);
            verifyServerCertificate(serverCertificateDecoded, CaCertPath);
            sendSession(socket,serverCertificateDecoded);
            Forwarder.forwardStreams(System.in, System.out, socket.getInputStream(), socket.getOutputStream(), socket);
        } catch (IOException ex) {
            System.out.println("Stream forwarding error\n");
            System.exit(1);
        }
    }
}
