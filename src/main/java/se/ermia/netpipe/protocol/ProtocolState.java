package se.ermia.netpipe.protocol;

/**
 * Protocol handshake states for the Secure NetPipe protocol.
 *
 * <p>Models the lifecycle of a single handshake session from initial TCP connection
 * through to an established encrypted channel or failure.</p>
 *
 * @author Ermia Ghaffari
 */
public enum ProtocolState {

    /** TCP connection established, no handshake messages exchanged yet. */
    CONNECTED,

    /** Client has sent ClientHello with its certificate. */
    CLIENT_HELLO_SENT,

    /** Server has received and validated ClientHello. */
    CLIENT_HELLO_RECEIVED,

    /** Server has sent ServerHello with its certificate. */
    SERVER_HELLO_SENT,

    /** Client has received ServerHello. */
    SERVER_HELLO_RECEIVED,

    /** Peer certificate has been verified against the CA. */
    CERTIFICATE_VERIFIED,

    /** Client has sent encrypted session key and IV. */
    SESSION_SENT,

    /** Server has received and decrypted session parameters. */
    SESSION_RECEIVED,

    /** Server has sent ServerFinished with signature and timestamp. */
    SERVER_FINISHED_SENT,

    /** Client has received and verified ServerFinished. */
    SERVER_FINISHED_VERIFIED,

    /** Client has sent ClientFinished with signature and timestamp. */
    CLIENT_FINISHED_SENT,

    /** Server has received and verified ClientFinished. */
    CLIENT_FINISHED_VERIFIED,

    /** Encrypted AES-CTR session is active. */
    SECURE_CHANNEL_ESTABLISHED,

    /** Session has been cleanly closed. */
    CLOSED,

    /** Handshake or session failed. */
    FAILED
}
