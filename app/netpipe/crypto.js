/**
 * JavaScript port of the NetPipe crypto package (se.ermia.netpipe.crypto).
 *
 * Same algorithms and byte formats as the Java classes, so values produced here
 * can be read by the Java implementation and vice versa (see
 * src/test/java/se/ermia/netpipe/interop/AppInteropTest.java):
 *   HandshakeCertificate  X.509, Base64 DER on the wire
 *   HandshakeCrypto       RSA with PKCS#1 v1.5 padding (Java's default "RSA" cipher)
 *   HandshakeDigest       SHA-256
 *   SessionKey            AES-128
 *   SessionCipher         AES-CTR, IV_c2s = IV, IV_s2c = IV with byte 0 XOR 0x80
 *
 * Byte arrays are forge "binary strings" (one char per byte).
 */
import forge from 'node-forge';
import { randomBytes } from './random.js';

export class CryptoError extends Error {
  constructor(message, cause) {
    super(message);
    this.name = 'CryptoError';
    if (cause) this.cause = cause;
  }
}

export class CertificateValidationError extends CryptoError {
  constructor(message, cause) {
    super(message, cause);
    this.name = 'CertificateValidationError';
  }
}

export const encodeBase64 = (bytes) => forge.util.encode64(bytes);
export const decodeBase64 = (text) => forge.util.decode64(text);
export const utf8Encode = (text) => forge.util.encodeUtf8(text);
export const utf8Decode = (bytes) => forge.util.decodeUtf8(bytes);

/** X.509 certificate handling (mirrors HandshakeCertificate.java). */
export class HandshakeCertificate {
  constructor(certificate) {
    this.certificate = certificate;
  }

  static fromPem(pem) {
    try {
      return new HandshakeCertificate(forge.pki.certificateFromPem(pem));
    } catch (error) {
      throw new CertificateValidationError('Could not parse PEM certificate', error);
    }
  }

  /** From DER bytes (binary string). */
  static fromBytes(der) {
    try {
      return new HandshakeCertificate(forge.pki.certificateFromAsn1(forge.asn1.fromDer(der)));
    } catch (error) {
      throw new CertificateValidationError('Could not parse DER certificate', error);
    }
  }

  /** Same as CryptoUtils.decodeCertificate in Java. */
  static fromBase64(base64) {
    return HandshakeCertificate.fromBytes(decodeBase64(base64));
  }

  /** DER bytes (binary string). */
  getBytes() {
    return forge.asn1.toDer(forge.pki.certificateToAsn1(this.certificate)).getBytes();
  }

  /** Same as CryptoUtils.encodeCertificate in Java. */
  toBase64() {
    return encodeBase64(this.getBytes());
  }

  toPem() {
    return forge.pki.certificateToPem(this.certificate);
  }

  /**
   * Check the signature against the CA certificate and that the certificate is
   * currently valid. A self-signed certificate is verified with itself as CA.
   */
  verify(caCert, now = new Date()) {
    try {
      if (!caCert.certificate.verify(this.certificate)) {
        throw new Error('signature mismatch');
      }
    } catch (error) {
      throw new CertificateValidationError('Certificate verification failed', error);
    }
    const { notBefore, notAfter } = this.certificate.validity;
    if (now < notBefore) {
      throw new CertificateValidationError(`Certificate is not yet valid: ${notBefore.toISOString()}`);
    }
    if (now > notAfter) {
      throw new CertificateValidationError(`Certificate has expired: ${notAfter.toISOString()}`);
    }
  }

  getCN() {
    return this.certificate.subject.getField('CN')?.value ?? null;
  }

  getEmail() {
    return this.certificate.subject.getField({ name: 'emailAddress' })?.value ?? null;
  }

  /** SHA-256 of the DER encoding, as upper-case hex. */
  fingerprint() {
    const md = forge.md.sha256.create();
    md.update(this.getBytes());
    return md.digest().toHex().toUpperCase();
  }

  equals(other) {
    return !!other && this.getBytes() === other.getBytes();
  }
}

/**
 * RSA with PKCS#1 v1.5 padding (mirrors HandshakeCrypto.java).
 * Public key: encrypt = block type 2, decrypt = "verify" of a block type 1.
 * Private key: encrypt = "sign" (block type 1), decrypt = block type 2.
 */
export class HandshakeCrypto {
  constructor({ publicKey = null, privateKey = null }) {
    this.publicKey = publicKey;
    this.privateKey = privateKey;
  }

  static fromCertificate(handshakeCertificate) {
    return new HandshakeCrypto({ publicKey: handshakeCertificate.certificate.publicKey });
  }

  /** From PKCS#8 DER bytes, like `new HandshakeCrypto(byte[])` in Java. */
  static fromPrivateKeyBytes(pkcs8Der) {
    try {
      const key = forge.pki.privateKeyFromAsn1(forge.asn1.fromDer(pkcs8Der));
      return new HandshakeCrypto({ privateKey: key });
    } catch (error) {
      throw new CryptoError('Failed to load RSA private key from PKCS8 bytes', error);
    }
  }

  static fromPrivateKeyPem(pem) {
    try {
      return new HandshakeCrypto({ privateKey: forge.pki.privateKeyFromPem(pem) });
    } catch (error) {
      throw new CryptoError('Failed to load RSA private key from PEM', error);
    }
  }

  encrypt(plaintext) {
    try {
      return this.publicKey
        ? forge.pki.rsa.encrypt(plaintext, this.publicKey, 0x02)
        : forge.pki.rsa.encrypt(plaintext, this.privateKey, 0x01);
    } catch (error) {
      throw new CryptoError('RSA encryption failed', error);
    }
  }

  decrypt(ciphertext) {
    try {
      return this.publicKey
        ? forge.pki.rsa.decrypt(ciphertext, this.publicKey, true)
        : forge.pki.rsa.decrypt(ciphertext, this.privateKey, false);
    } catch (error) {
      throw new CryptoError('RSA decryption failed', error);
    }
  }
}

/** SHA-256 (mirrors HandshakeDigest.java). */
export class HandshakeDigest {
  constructor() {
    this.md = forge.md.sha256.create();
  }

  update(bytes) {
    this.md.update(bytes);
  }

  /** Final digest (binary string); resets the digest like MessageDigest.digest(). */
  digest() {
    const result = this.md.digest().getBytes();
    this.md = forge.md.sha256.create();
    return result;
  }

  /** Constant-time comparison. */
  static isEqual(a, b) {
    if (typeof a !== 'string' || typeof b !== 'string' || a.length !== b.length) return false;
    let diff = 0;
    for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
    return diff === 0;
  }
}

/** AES key (mirrors SessionKey.java). */
export class SessionKey {
  constructor(keyBytes) {
    if (typeof keyBytes !== 'string' || ![16, 24, 32].includes(keyBytes.length)) {
      throw new CryptoError(
        `Invalid AES key length: ${keyBytes?.length ?? 'null'} bytes (must be 16, 24, or 32)`
      );
    }
    this.keyBytes = keyBytes;
  }

  static generate(lengthInBits = 128) {
    return new SessionKey(randomBytes(lengthInBits / 8));
  }

  getKeyBytes() {
    return this.keyBytes;
  }
}

const IV_LENGTH_BYTES = 16;
const BLOCK = 16;

const toByteArray = (binary) => Array.from(binary, (c) => c.charCodeAt(0));
const fromByteArray = (bytes) => String.fromCharCode.apply(null, bytes);

/** Add a non-negative integer to a 128-bit big-endian counter, in place. */
function addToCounter(counter, amount) {
  let carry = amount;
  for (let i = BLOCK - 1; i >= 0 && carry > 0; i--) {
    const sum = counter[i] + (carry % 256);
    counter[i] = sum & 0xff;
    carry = Math.floor(carry / 256) + (sum >> 8);
  }
}

/**
 * AES-CTR session cipher with directional IVs (mirrors SessionCipher.java).
 *
 * The Java class wraps socket streams. Chat messages are stored separately, so
 * here each piece of data is placed at an explicit byte offset of the same
 * directional stream: encrypting records at offsets 0, n1, n1+n2, ... produces
 * exactly the bytes a Java CipherOutputStream would produce for the
 * concatenated plaintext. Offsets must never be reused in one direction.
 */
export class SessionCipher {
  constructor(sessionKey, ivBytes, isServer = false) {
    if (typeof ivBytes !== 'string' || ivBytes.length !== IV_LENGTH_BYTES) {
      throw new CryptoError(`IV must be ${IV_LENGTH_BYTES} bytes, got ${ivBytes?.length ?? 'null'}`);
    }
    this.key = sessionKey;
    this.iv = ivBytes;
    this.isServer = isServer;

    const ivClientToServer = toByteArray(ivBytes);
    const ivServerToClient = toByteArray(ivBytes);
    ivServerToClient[0] ^= 0x80;
    this.encIV = isServer ? ivServerToClient : ivClientToServer;
    this.decIV = isServer ? ivClientToServer : ivServerToClient;
  }

  static generateIV() {
    return randomBytes(IV_LENGTH_BYTES);
  }

  getSessionKey() {
    return this.key;
  }

  getIVBytes() {
    return this.iv;
  }

  /** Encrypt bytes at `offset` of this endpoint's outgoing stream. */
  encrypt(plaintext, offset) {
    return this._xor(this.encIV, plaintext, offset);
  }

  /** Decrypt bytes found at `offset` of the peer's stream. */
  decrypt(ciphertext, offset) {
    return this._xor(this.decIV, ciphertext, offset);
  }

  _xor(iv, data, offset) {
    if (!Number.isSafeInteger(offset) || offset < 0) {
      throw new CryptoError(`Invalid stream offset: ${offset}`);
    }
    if (data.length === 0) return '';

    const skip = offset % BLOCK;
    const blocks = Math.ceil((skip + data.length) / BLOCK);
    const counter = iv.slice();
    addToCounter(counter, Math.floor(offset / BLOCK));

    const counters = forge.util.createBuffer();
    for (let i = 0; i < blocks; i++) {
      counters.putBytes(fromByteArray(counter));
      addToCounter(counter, 1);
    }
    // AES-CTR keystream = AES-ECB(counter blocks); input is block-aligned, so no padding.
    const ecb = forge.cipher.createCipher('AES-ECB', this.key.getKeyBytes());
    ecb.start();
    ecb.update(counters);
    const keystream = ecb.output.getBytes();

    let out = '';
    for (let i = 0; i < data.length; i++) {
      out += String.fromCharCode(data.charCodeAt(i) ^ keystream.charCodeAt(skip + i));
    }
    return out;
  }
}

/** RSA key generation: native (Node / WebCrypto) when available, else pure JS in small steps. */
export function generateRsaKeyPair(bits = 2048) {
  const hasNative = forge.util.isNodejs || typeof globalThis.crypto?.subtle?.generateKey === 'function';
  if (hasNative) {
    return new Promise((resolve, reject) =>
      forge.pki.rsa.generateKeyPair({ bits, e: 0x10001 }, (error, keys) =>
        error ? reject(error) : resolve(keys)
      )
    );
  }
  // React Native: no native RSA, so step the search to keep the UI responsive.
  const state = forge.pki.rsa.createKeyPairGenerationState(bits, 0x10001);
  return new Promise((resolve, reject) => {
    const step = () => {
      try {
        if (forge.pki.rsa.stepKeyPairGenerationState(state, 50)) resolve(state.keys);
        else setTimeout(step, 0);
      } catch (error) {
        reject(error);
      }
    };
    step();
  });
}

/**
 * Create a NetPipe identity for a user: RSA-2048 key pair plus a self-signed
 * X.509 certificate with CN and EMAILADDRESS set to the user's email.
 */
export async function createIdentity(email, { bits = 2048, validDays = 730 } = {}) {
  const keys = await generateRsaKeyPair(bits);
  const cert = forge.pki.createCertificate();
  cert.publicKey = keys.publicKey;

  const serial = toByteArray(randomBytes(16));
  serial[0] = (serial[0] & 0x7f) | 0x01; // positive and non-zero
  cert.serialNumber = forge.util.bytesToHex(fromByteArray(serial));

  const now = Date.now();
  cert.validity.notBefore = new Date(now - 10 * 60 * 1000);
  cert.validity.notAfter = new Date(now + validDays * 24 * 60 * 60 * 1000);

  const subject = [
    { name: 'commonName', value: email },
    { name: 'organizationName', value: 'NetPipe Chat' },
    { name: 'emailAddress', value: email },
  ];
  cert.setSubject(subject);
  cert.setIssuer(subject);
  cert.setExtensions([
    { name: 'basicConstraints', cA: true },
    { name: 'keyUsage', digitalSignature: true, keyEncipherment: true, keyCertSign: true },
  ]);
  cert.sign(keys.privateKey, forge.md.sha256.create());

  return {
    certificatePem: forge.pki.certificateToPem(cert),
    privateKeyPem: forge.pki.privateKeyInfoToPem(
      forge.pki.wrapRsaPrivateKey(forge.pki.privateKeyToAsn1(keys.privateKey))
    ),
  };
}

/** PKCS#8 DER bytes of a PEM private key (what the Java side loads). */
export function privateKeyPemToPkcs8(pem) {
  const key = forge.pki.privateKeyFromPem(pem);
  return forge.asn1.toDer(forge.pki.wrapRsaPrivateKey(forge.pki.privateKeyToAsn1(key))).getBytes();
}
