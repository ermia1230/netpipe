/**
 * JavaScript port of the NetPipe protocol package (se.ermia.netpipe.protocol)
 * and the handshake logic of NetPipeClient / NetPipeServer.
 *
 * Handshake (same order, parameters and signatures as the Java code):
 *   1. CLIENTHELLO     Certificate
 *   2. SERVERHELLO     Certificate
 *   3. SESSION         SessionKey, SessionIV   (RSA-encrypted to the server)
 *   4. SERVERFINISHED  Signature = RSA_priv(SHA-256(serverHello)), TimeStamp
 *   5. CLIENTFINISHED  Signature = RSA_priv(SHA-256(clientHello || session)), TimeStamp
 *
 * Differences from the Java transport, because messages travel through
 * Firestore documents instead of a TCP socket:
 *   - A message is encoded as canonical JSON ({"MessageType": ..., params sorted})
 *     instead of Java object serialisation; digests cover exactly those bytes.
 *   - Timestamps are UTC ("yyyy-MM-dd HH:mm:ss"), since the two users can be in
 *     different time zones.
 *   - The handshake can complete while the users are not online at the same time,
 *     so a Finished timestamp is accepted from (handshake start - 300 s) up to
 *     (now + 300 s) instead of only (now +/- 300 s).
 */
import {
  CertificateValidationError,
  CryptoError,
  HandshakeCertificate,
  HandshakeCrypto,
  HandshakeDigest,
  SessionCipher,
  SessionKey,
  decodeBase64,
  encodeBase64,
  utf8Decode,
  utf8Encode,
} from './crypto.js';

export const MAX_MESSAGE_SIZE = 65536;
export const MAX_TIMESTAMP_SKEW_SECONDS = 300;
export const AES_KEY_LENGTH_BITS = 128;

export const MessageType = Object.freeze({
  CLIENTHELLO: 'CLIENTHELLO',
  SERVERHELLO: 'SERVERHELLO',
  SESSION: 'SESSION',
  SERVERFINISHED: 'SERVERFINISHED',
  CLIENTFINISHED: 'CLIENTFINISHED',
});

export const ProtocolState = Object.freeze(
  Object.fromEntries(
    [
      'CONNECTED',
      'CLIENT_HELLO_SENT',
      'CLIENT_HELLO_RECEIVED',
      'SERVER_HELLO_SENT',
      'SERVER_HELLO_RECEIVED',
      'CERTIFICATE_VERIFIED',
      'SESSION_SENT',
      'SESSION_RECEIVED',
      'SERVER_FINISHED_SENT',
      'SERVER_FINISHED_VERIFIED',
      'CLIENT_FINISHED_SENT',
      'CLIENT_FINISHED_VERIFIED',
      'SECURE_CHANNEL_ESTABLISHED',
      'CLOSED',
      'FAILED',
    ].map((s) => [s, s])
  )
);

export class NetPipeError extends Error {
  constructor(name, message, cause) {
    super(message);
    this.name = name;
    if (cause) this.cause = cause;
  }
}
const invalidMessage = (message) => new NetPipeError('InvalidMessageException', message);
const handshakeError = (message) => new NetPipeError('HandshakeException', message);
const timestampError = (message) => new NetPipeError('TimestampValidationException', message);

const S = ProtocolState;
const VALID_TRANSITIONS = new Map();
const allow = (from, to) => {
  if (!VALID_TRANSITIONS.has(from)) VALID_TRANSITIONS.set(from, new Set());
  VALID_TRANSITIONS.get(from).add(to);
};
// Client side
allow(S.CONNECTED, S.CLIENT_HELLO_SENT);
allow(S.CLIENT_HELLO_SENT, S.SERVER_HELLO_RECEIVED);
allow(S.SERVER_HELLO_RECEIVED, S.CERTIFICATE_VERIFIED);
allow(S.CERTIFICATE_VERIFIED, S.SESSION_SENT);
allow(S.SESSION_SENT, S.SERVER_FINISHED_VERIFIED);
allow(S.SERVER_FINISHED_VERIFIED, S.CLIENT_FINISHED_SENT);
allow(S.CLIENT_FINISHED_SENT, S.SECURE_CHANNEL_ESTABLISHED);
// Server side
allow(S.CONNECTED, S.CLIENT_HELLO_RECEIVED);
allow(S.CLIENT_HELLO_RECEIVED, S.CERTIFICATE_VERIFIED);
allow(S.CERTIFICATE_VERIFIED, S.SERVER_HELLO_SENT);
allow(S.SERVER_HELLO_SENT, S.SESSION_RECEIVED);
allow(S.SESSION_RECEIVED, S.SERVER_FINISHED_SENT);
allow(S.SERVER_FINISHED_SENT, S.CLIENT_FINISHED_VERIFIED);
allow(S.CLIENT_FINISHED_VERIFIED, S.SECURE_CHANNEL_ESTABLISHED);
// Common
for (const state of Object.values(S)) {
  if (state !== S.FAILED && state !== S.CLOSED) allow(state, S.FAILED);
}
allow(S.SECURE_CHANNEL_ESTABLISHED, S.CLOSED);

/** Mirrors ProtocolStateMachine.java: rejects out-of-order transitions. */
export class ProtocolStateMachine {
  constructor(role, initial = S.CONNECTED) {
    this.role = role;
    this.state = initial;
  }

  transition(next) {
    if (!VALID_TRANSITIONS.get(this.state)?.has(next)) {
      throw new NetPipeError(
        'ProtocolStateException',
        `[${this.role}] Invalid state transition: ${this.state} -> ${next}`
      );
    }
    this.state = next;
  }

  canTransition(next) {
    return !!VALID_TRANSITIONS.get(this.state)?.has(next);
  }

  getState() {
    return this.state;
  }
}

/** Mirrors HandshakeMessage.java, with a canonical JSON encoding. */
export class HandshakeMessage {
  constructor(type, params = {}, raw = null) {
    if (!Object.values(MessageType).includes(type)) {
      throw invalidMessage(`Unknown message type: ${type}`);
    }
    this.type = type;
    this.params = { ...params };
    this.raw = raw;
  }

  getType() {
    return this.type;
  }

  getParameter(name) {
    return Object.prototype.hasOwnProperty.call(this.params, name) ? this.params[name] : null;
  }

  putParameter(name, value) {
    if (name === 'MessageType') throw invalidMessage('"MessageType" is a reserved parameter name');
    this.params[name] = String(value);
    this.raw = null;
  }

  /** The encoded message (a string). Received messages keep their exact bytes. */
  encode() {
    if (this.raw !== null) return this.raw;
    const sorted = { MessageType: this.type };
    for (const key of Object.keys(this.params).sort()) sorted[key] = this.params[key];
    return JSON.stringify(sorted);
  }

  /** UTF-8 bytes of the encoding; this is what the handshake digests cover. */
  getBytes() {
    return utf8Encode(this.encode());
  }

  static decode(raw, expectedType) {
    if (typeof raw !== 'string' || raw.length === 0) {
      throw invalidMessage(`Missing ${expectedType ?? 'handshake'} message`);
    }
    if (utf8Encode(raw).length > MAX_MESSAGE_SIZE) {
      throw invalidMessage(`Message too large (max ${MAX_MESSAGE_SIZE} bytes)`);
    }
    let parsed;
    try {
      parsed = JSON.parse(raw);
    } catch (error) {
      throw invalidMessage('Failed to decode handshake message');
    }
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
      throw invalidMessage('Handshake message must be an object');
    }
    const { MessageType: type, ...params } = parsed;
    for (const value of Object.values(params)) {
      if (typeof value !== 'string') throw invalidMessage('Handshake parameters must be strings');
    }
    const message = new HandshakeMessage(type, params, raw);
    if (expectedType && type !== expectedType) {
      throw invalidMessage(`Expected ${expectedType}, got ${type}`);
    }
    return message;
  }
}

const requireParam = (message, name) => {
  const value = message.getParameter(name);
  if (value === null) throw invalidMessage(`${message.getType()} missing ${name} parameter`);
  return value;
};

// --- Timestamps -----------------------------------------------------------

const pad = (n) => String(n).padStart(2, '0');

/** "yyyy-MM-dd HH:mm:ss" in UTC. */
export function formatTimestamp(date = new Date()) {
  return (
    `${date.getUTCFullYear()}-${pad(date.getUTCMonth() + 1)}-${pad(date.getUTCDate())} ` +
    `${pad(date.getUTCHours())}:${pad(date.getUTCMinutes())}:${pad(date.getUTCSeconds())}`
  );
}

export function parseTimestamp(text) {
  const match = /^(\d{4})-(\d{2})-(\d{2}) (\d{2}):(\d{2}):(\d{2})$/.exec(text);
  if (!match) throw timestampError(`Malformed timestamp: ${text}`);
  const [, y, mo, d, h, mi, s] = match.map(Number);
  const ms = Date.UTC(y, mo - 1, d, h, mi, s);
  const check = new Date(ms);
  if (check.getUTCMonth() !== mo - 1 || check.getUTCDate() !== d) {
    throw timestampError(`Malformed timestamp: ${text}`);
  }
  return ms;
}

/**
 * Accept timestamps from (notBeforeMs - skew) to (now + skew).
 * With notBeforeMs = now this is the Java rule |timestamp - now| <= 300 s.
 */
export function validateTimestamp(text, { nowMs = Date.now(), notBeforeMs = nowMs } = {}) {
  const ts = parseTimestamp(text);
  const skew = MAX_TIMESTAMP_SKEW_SECONDS * 1000;
  if (ts < notBeforeMs - skew || ts > nowMs + skew) {
    throw timestampError(
      `Timestamp outside allowed window: ${text} (max skew ${MAX_TIMESTAMP_SKEW_SECONDS}s)`
    );
  }
  return ts;
}

// --- Handshake steps ------------------------------------------------------

/** CLIENTHELLO / SERVERHELLO carrying the sender's certificate. */
export function createHello(type, certificate) {
  const message = new HandshakeMessage(type);
  message.putParameter('Certificate', certificate.toBase64());
  return message;
}

/**
 * Read the peer certificate from a hello and check it with `verifyPeer`
 * (e.g. `cert => cert.verify(caCert)`). Returns the certificate.
 */
export function receiveHello(message, verifyPeer) {
  const certificate = HandshakeCertificate.fromBase64(requireParam(message, 'Certificate'));
  verifyPeer(certificate);
  return certificate;
}

/** Client: fresh AES-128 key + IV, RSA-encrypted to the server's certificate. */
export function createSession(serverCertificate) {
  const sessionKey = SessionKey.generate(AES_KEY_LENGTH_BITS);
  const iv = SessionCipher.generateIV();
  const serverCrypto = HandshakeCrypto.fromCertificate(serverCertificate);
  const message = new HandshakeMessage(MessageType.SESSION);
  message.putParameter('SessionKey', encodeBase64(serverCrypto.encrypt(sessionKey.getKeyBytes())));
  message.putParameter('SessionIV', encodeBase64(serverCrypto.encrypt(iv)));
  return { message, sessionKey, iv };
}

/** Server: decrypt the session key and IV with the server's private key. */
export function receiveSession(message, privateKey) {
  const keyBytes = privateKey.decrypt(decodeBase64(requireParam(message, 'SessionKey')));
  const iv = privateKey.decrypt(decodeBase64(requireParam(message, 'SessionIV')));
  return { sessionKey: new SessionKey(keyBytes), iv };
}

const digestOf = (messages) => {
  const digest = new HandshakeDigest();
  messages.forEach((m) => digest.update(m.getBytes()));
  return digest.digest();
};

/** SERVERFINISHED / CLIENTFINISHED: signed transcript digest + signed timestamp. */
export function createFinished(type, privateKey, signedMessages, now = new Date()) {
  const message = new HandshakeMessage(type);
  message.putParameter('Signature', encodeBase64(privateKey.encrypt(digestOf(signedMessages))));
  message.putParameter('TimeStamp', encodeBase64(privateKey.encrypt(utf8Encode(formatTimestamp(now)))));
  return message;
}

/**
 * Verify a Finished message from the peer. Pass `timestamp: false` to skip the
 * freshness check when re-verifying an already completed handshake.
 */
export function verifyFinished(message, expectedType, peerCertificate, signedMessages, timestamp = {}) {
  if (message.getType() !== expectedType) {
    throw invalidMessage(`Expected ${expectedType}, got ${message.getType()}`);
  }
  const peerCrypto = HandshakeCrypto.fromCertificate(peerCertificate);
  const signature = requireParam(message, 'Signature');
  const stamp = requireParam(message, 'TimeStamp');

  if (timestamp !== false) {
    validateTimestamp(utf8Decode(peerCrypto.decrypt(decodeBase64(stamp))), timestamp);
  }
  const signed = peerCrypto.decrypt(decodeBase64(signature));
  if (!HandshakeDigest.isEqual(signed, digestOf(signedMessages))) {
    throw handshakeError('Signature verification failed');
  }
}

/** Which handshake messages each Finished message signs (as in the Java code). */
export const serverFinishedSigns = ({ serverHello }) => [serverHello];
export const clientFinishedSigns = ({ clientHello, session }) => [clientHello, session];

// --- Data phase -----------------------------------------------------------

/**
 * Encrypted, signed record in the established channel.
 *
 * Confidentiality: AES-CTR at a reserved offset of the sender's directional stream.
 * Integrity: AES-CTR alone is malleable, so each record is signed like the
 * Finished messages: RSA_priv(SHA-256(context || ciphertext)).
 */
export class SecureChannel {
  constructor({ sessionId, isServer, sessionKey, iv, privateKey, ownCertificate, peerCertificate }) {
    this.sessionId = sessionId;
    this.isServer = isServer;
    this.cipher = new SessionCipher(sessionKey, iv, isServer);
    this.privateKey = privateKey;
    this.ownCertificate = ownCertificate;
    this.peerCertificate = peerCertificate;
    this.peerCrypto = HandshakeCrypto.fromCertificate(peerCertificate);
  }

  get outgoingDirection() {
    return this.isServer ? 's2c' : 'c2s';
  }

  get incomingDirection() {
    return this.isServer ? 'c2s' : 's2c';
  }

  _recordDigest(direction, offset, ciphertext) {
    const digest = new HandshakeDigest();
    digest.update(utf8Encode(`NetPipe-Record|${this.sessionId}|${direction}|${offset}|`));
    digest.update(ciphertext);
    return digest.digest();
  }

  /** Byte length a string will occupy in the stream. */
  static byteLength(text) {
    return utf8Encode(text).length;
  }

  seal(plaintext, offset) {
    const ciphertext = this.cipher.encrypt(utf8Encode(plaintext), offset);
    const signature = this.privateKey.encrypt(
      this._recordDigest(this.outgoingDirection, offset, ciphertext)
    );
    return {
      ciphertext: encodeBase64(ciphertext),
      offset,
      direction: this.outgoingDirection,
      signature: encodeBase64(signature),
    };
  }

  /** Decrypt a record sent by either side (own records too, e.g. chat history). */
  open(record) {
    const { ciphertext: ctB64, offset, direction, signature } = record;
    if (direction !== 'c2s' && direction !== 's2c') throw invalidMessage('Invalid record direction');
    const ciphertext = decodeBase64(ctB64);
    const mine = direction === this.outgoingDirection;

    let signed;
    try {
      signed = mine
        ? HandshakeCrypto.fromCertificate(this.ownCertificate).decrypt(decodeBase64(signature))
        : this.peerCrypto.decrypt(decodeBase64(signature));
    } catch (error) {
      throw handshakeError('Record signature is invalid');
    }
    if (!HandshakeDigest.isEqual(signed, this._recordDigest(direction, offset, ciphertext))) {
      throw handshakeError('Record signature is invalid');
    }
    const plaintext = mine
      ? this.cipher.encrypt(ciphertext, offset) // CTR: same keystream decrypts
      : this.cipher.decrypt(ciphertext, offset);
    return utf8Decode(plaintext);
  }
}

export { CertificateValidationError, CryptoError };
