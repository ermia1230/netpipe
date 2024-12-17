import java.net.*;
import java.io.*;

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
        System.exit(1);
    }

    /*
     * Parse arguments on command line
     */
    private static void parseArgs(String[] args) {
        arguments = new Arguments();
        arguments.setArgumentSpec("host", "hostname");
        arguments.setArgumentSpec("port", "portnumber");

        try {
        arguments.loadArguments(args);
        } catch (IllegalArgumentException ex) {
            usage();
        }
    }

    /*
     * Main program.
     * Parse arguments on command line, connect to server,
     * and call forwarder to forward data between streams.
     */
    public static void main( String[] args) {
        Socket socket = null;

        parseArgs(args);
        String host = arguments.get("host");
        int port = Integer.parseInt(arguments.get("port"));
        try {
            socket = new Socket(host, port);
        } catch (IOException ex) {
            System.err.printf("Can't connect to server at %s:%d\n", host, port);
            System.exit(1);
        }
        try {
            Forwarder.forwardStreams(System.in, System.out, socket.getInputStream(), socket.getOutputStream(), socket);
        } catch (IOException ex) {
            System.out.println("Stream forwarding error\n");
            System.exit(1);
        }
    }
}
