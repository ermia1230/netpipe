# Secure NetPipe Protocol Documentation

## Protocol Overview

Secure NetPipe implements a custom secure transport protocol designed for educational purposes, providing authentication, key exchange, and confidentiality over TCP. It ensures mutual authentication using X.509 certificates and establishes a secure channel encrypted with AES-128-CTR.

## Handshake Sequence

```mermaid
sequenceDiagram
    participant Client
    participant Server

    Client->>Server: ClientHello (Certificate)
    Note over Server: Verify Client Cert
    Server->>Client: ServerHello (Certificate)
    Note over Client: Verify Server Cert
    Client->>Server: Session (Encrypted Session Key & IV)
    Note over Server: Decrypt Session Key & IV
    Server->>Client: ServerFinished (Signature & Timestamp)
    Note over Client: Verify Signature & Freshness
    Client->>Server: ClientFinished (Signature & Timestamp)
    Note over Server: Verify Signature & Freshness
    Note over Client, Server: Secure Channel Established (Directional AES-128-CTR)
```

## Protocol State Machine

```mermaid
stateDiagram-v2
    [*] --> CONNECTED
    
    state Client {
        CONNECTED --> CLIENT_HELLO_SENT: Send ClientHello
        CLIENT_HELLO_SENT --> SERVER_HELLO_RECEIVED: Receive ServerHello
        SERVER_HELLO_RECEIVED --> CERTIFICATE_VERIFIED: Verify Server Cert
        CERTIFICATE_VERIFIED --> SESSION_SENT: Send Session
        SESSION_SENT --> SERVER_FINISHED_VERIFIED: Receive/Verify ServerFinished
        SERVER_FINISHED_VERIFIED --> CLIENT_FINISHED_SENT: Send ClientFinished
        CLIENT_FINISHED_SENT --> SECURE_CHANNEL_ESTABLISHED: Secure Channel
    }
    
    state Server {
        CONNECTED --> CLIENT_HELLO_RECEIVED: Receive ClientHello
        CLIENT_HELLO_RECEIVED --> CERTIFICATE_VERIFIED: Verify Client Cert
        CERTIFICATE_VERIFIED --> SERVER_HELLO_SENT: Send ServerHello
        SERVER_HELLO_SENT --> SESSION_RECEIVED: Receive Session
        SESSION_RECEIVED --> SERVER_FINISHED_SENT: Send ServerFinished
        SERVER_FINISHED_SENT --> CLIENT_FINISHED_VERIFIED: Receive/Verify ClientFinished
        CLIENT_FINISHED_VERIFIED --> SECURE_CHANNEL_ESTABLISHED: Secure Channel
    }
    
    SECURE_CHANNEL_ESTABLISHED --> CLOSED
    
    CONNECTED --> FAILED
    CLIENT_HELLO_SENT --> FAILED
    SERVER_HELLO_RECEIVED --> FAILED
    CERTIFICATE_VERIFIED --> FAILED
    SESSION_SENT --> FAILED
    SERVER_FINISHED_VERIFIED --> FAILED
    CLIENT_FINISHED_SENT --> FAILED
    CLIENT_HELLO_RECEIVED --> FAILED
    SERVER_HELLO_SENT --> FAILED
    SESSION_RECEIVED --> FAILED
    SERVER_FINISHED_SENT --> FAILED
    CLIENT_FINISHED_VERIFIED --> FAILED
```

## Message Framing

All handshake messages are serialized via Java Object Serialization and framed with a length prefix.
- **Length Prefix:** 4-byte big-endian integer.
- **Maximum Message Size:** `MAX_MESSAGE_SIZE = 65536` bytes. Messages exceeding this limit are rejected to prevent memory exhaustion attacks.

## Message Details

### ClientHello / ServerHello
- **Type:** `CLIENTHELLO` / `SERVERHELLO`
- **Parameters:**
  - `Certificate`: Base64 encoded X.509 DER certificate.

### Session
- **Type:** `SESSION`
- **Parameters:**
  - `SessionKey`: AES-128 key encrypted with the recipient's RSA public key (Base64).
  - `SessionIV`: Base Initialization Vector (IV) encrypted with the recipient's RSA public key (Base64).

### ServerFinished / ClientFinished
- **Type:** `SERVERFINISHED` / `CLIENTFINISHED`
- **Parameters:**
  - `Signature`: SHA-256 digest of all previous handshake messages, encrypted with the sender's RSA private key (Base64).
  - `Timestamp`: Current timestamp in `yyyy-MM-dd HH:mm:ss` format, encrypted with the sender's RSA private key (Base64).

## Validation Mechanisms

- **Timestamp Freshness Check:** Validates request freshness. Maximum allowed clock skew is 300 seconds.
- **Directional CTR Keystream Safety:** Derives distinct directional IVs ($IV_{c2s} = IV$, $IV_{s2c} = IV \oplus 0x80$) to guarantee that client-to-server and server-to-client streams never reuse the same CTR keystream (eliminating two-time pad vulnerability).
- **Certificate Verification:** Certificates are parsed in DER/PEM format and verified against the trusted CA (`certificate.verify(caPublicKey)`) alongside validity window verification (`certificate.checkValidity()`).
- **Session Key Exchange:** The client generates a random AES-128 key and IV, encrypting them with the server's RSA public key.

## Error Handling

Protocol violations are detected by the `ProtocolStateMachine`. If an unexpected message type is received for the current state, a `ProtocolStateException` is thrown, transitioning the state machine to `FAILED` and closing the connection. Invalid message lengths or formats result in `InvalidMessageException`.

## Security Considerations

> **Note:** This protocol is designed for educational purposes. Real production systems should use TLS.
- **RSA Padding:** Uses RSA PKCS1v1.5 padding rather than OAEP padding.
- **Custom Signatures:** Implements custom signing using encryption with private keys rather than utilizing standard `java.security.Signature` APIs.
- **Java Serialization:** Uses `ObjectInputStream`/`ObjectOutputStream` which carries inherent security risks if untrusted data is deserialized.
