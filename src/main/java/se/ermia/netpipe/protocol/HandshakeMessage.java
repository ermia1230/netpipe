package se.ermia.netpipe.protocol;

import se.ermia.netpipe.exception.InvalidMessageException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.util.Properties;

/**
 * Handshake message encoding/decoding and transmission for the Secure NetPipe protocol.
 *
 * <p>A HandshakeMessage is a set of key-value parameters serialised via Java
 * {@link ObjectOutputStream} and framed with a 4-byte big-endian length prefix.
 * Extends {@link Properties} for parameter storage.</p>
 *
 * <p>Skeleton provided by Peter Sjödin (KTH/IK2206).
 * Implementation, bug fixes, and extensions by Ermia Ghaffari.</p>
 *
 * <h3>Changes from original skeleton</h3>
 * <ul>
 *   <li>Length prefix widened from 2 bytes (short) to 4 bytes (int) to prevent overflow</li>
 *   <li>Added {@code MAX_MESSAGE_SIZE} to reject oversized payloads</li>
 *   <li>Fixed partial-read bug on length bytes using {@code readFully}</li>
 *   <li>Added validation for negative and zero lengths</li>
 *   <li>Extracted {@link MessageType} to standalone enum</li>
 * </ul>
 */
public class HandshakeMessage extends Properties {

    private static final long serialVersionUID = 1L;
    private static final Logger log = LoggerFactory.getLogger(HandshakeMessage.class);

    /** Width of the length-prefix field in bytes (4-byte int, big-endian). */
    static final int LENGTH_BYTES = 4;

    /**
     * Maximum allowed message size in bytes (64 KB).
     * Prevents resource exhaustion from malicious or corrupted length prefixes.
     */
    public static final int MAX_MESSAGE_SIZE = 65536;

    private final MessageType messageType;

    public HandshakeMessage(MessageType messageType) {
        this.messageType = messageType;
    }

    public MessageType getType() {
        return messageType;
    }

    /**
     * Get the value of a parameter.
     */
    public String getParameter(String param) {
        return getProperty(param);
    }

    /**
     * Set a parameter value.
     */
    public void putParameter(String param, String value) {
        put(param, value);
    }

    /**
     * Serialise this message to a byte array using Java object serialisation.
     */
    public byte[] getBytes() throws IOException {
        ByteArrayOutputStream byteOut = new ByteArrayOutputStream();
        ObjectOutputStream objOut = new ObjectOutputStream(byteOut);
        objOut.writeObject(this);
        objOut.flush();
        return byteOut.toByteArray();
    }

    /**
     * Deserialise a message from a byte array.
     *
     * @throws InvalidMessageException if the data cannot be deserialised
     */
    public static HandshakeMessage fromBytes(byte[] bytes) throws InvalidMessageException {
        try {
            ByteArrayInputStream byteIn = new ByteArrayInputStream(bytes);
            ObjectInputStream objIn = new ObjectInputStream(byteIn);
            return (HandshakeMessage) objIn.readObject();
        } catch (IOException | ClassNotFoundException | ClassCastException e) {
            throw new InvalidMessageException("Failed to deserialise handshake message", e);
        }
    }

    /**
     * Send this message on a socket.
     *
     * <p>The message is serialised to bytes, then sent with a 4-byte big-endian
     * length prefix.</p>
     */
    public void send(Socket socket) throws IOException {
        byte[] bytes = getBytes();
        OutputStream output = socket.getOutputStream();
        DataOutputStream dataOut = new DataOutputStream(output);
        dataOut.writeInt(bytes.length);
        dataOut.write(bytes);
        dataOut.flush();
        log.debug("Sent {} message ({} bytes)", messageType, bytes.length);
    }

    /**
     * Receive a handshake message from a socket.
     *
     * <p>Reads a 4-byte big-endian length, validates it, then reads exactly
     * that many bytes and deserialises them.</p>
     *
     * @throws IOException if the connection is broken or EOF is reached
     * @throws InvalidMessageException if the length is invalid or deserialisation fails
     */
    public static HandshakeMessage recv(Socket socket) throws IOException, InvalidMessageException {
        InputStream input = socket.getInputStream();
        DataInputStream dataIn = new DataInputStream(input);

        int length;
        try {
            length = dataIn.readInt();
        } catch (java.io.EOFException e) {
            throw new IOException("Connection closed while reading message length", e);
        }

        if (length <= 0) {
            throw new InvalidMessageException(
                    "Invalid message length: " + length + " (must be positive)");
        }
        if (length > MAX_MESSAGE_SIZE) {
            throw new InvalidMessageException(
                    "Message too large: " + length + " bytes (max " + MAX_MESSAGE_SIZE + ")");
        }

        byte[] buffer = new byte[length];
        dataIn.readFully(buffer);

        HandshakeMessage message = fromBytes(buffer);
        log.debug("Received {} message ({} bytes)", message.getType(), length);
        return message;
    }

    @Override
    public String toString() {
        return "HandshakeMessage{type=" + messageType + ", params=" + super.toString() + "}";
    }
}
