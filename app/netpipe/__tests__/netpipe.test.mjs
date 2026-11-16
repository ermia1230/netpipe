// Run with: npm run test:netpipe   (Node's built-in test runner, no extra deps)
import { test } from 'node:test';
import assert from 'node:assert/strict';
import nodeCrypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  HandshakeCertificate,
  HandshakeCrypto,
  HandshakeDigest,
  SessionCipher,
  SessionKey,
  createIdentity,
  decodeBase64,
} from '../crypto.js';
import {
  HandshakeMessage,
  MessageType,
  ProtocolState,
  ProtocolStateMachine,
  SecureChannel,
  clientFinishedSigns,
  createFinished,
  createHello,
  createSession,
  formatTimestamp,
  receiveHello,
  receiveSession,
  serverFinishedSigns,
  validateTimestamp,
  verifyFinished,
} from '../protocol.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const certsDir = path.resolve(here, '../../../src/test/resources/certs');
const readText = (name) => fs.readFileSync(path.join(certsDir, name), 'utf8');
const readBinary = (name) => fs.readFileSync(path.join(certsDir, name)).toString('binary');

const ca = HandshakeCertificate.fromPem(readText('ca.pem'));
const clientCert = HandshakeCertificate.fromPem(readText('client.pem'));
const serverCert = HandshakeCertificate.fromPem(readText('server.pem'));
const untrustedCert = HandshakeCertificate.fromPem(readText('untrusted.pem'));
const clientKey = HandshakeCrypto.fromPrivateKeyBytes(readBinary('client-private.der'));
const serverKey = HandshakeCrypto.fromPrivateKeyBytes(readBinary('server-private.der'));

const bin = (buf) => Buffer.from(buf).toString('binary');

test('AES-CTR matches OpenSSL, including full 128-bit counter carry', () => {
  const key = nodeCrypto.randomBytes(16);
  const ivs = [Buffer.alloc(16, 0xff), Buffer.from('00000000000000000000000000fffffffe'.slice(2), 'hex'), nodeCrypto.randomBytes(16)];
  for (const iv of ivs) {
    const plain = nodeCrypto.randomBytes(1000);
    const c = nodeCrypto.createCipheriv('aes-128-ctr', key, iv);
    const expected = Buffer.concat([c.update(plain), c.final()]);
    const cipher = new SessionCipher(new SessionKey(bin(key)), bin(iv), false);
    // Arbitrary, unaligned record boundaries must equal one continuous stream.
    let offset = 0;
    let out = '';
    for (const size of [1, 15, 16, 17, 100, 351, 500]) {
      out += cipher.encrypt(bin(plain.subarray(offset, offset + size)), offset);
      offset += size;
    }
    assert.equal(out, bin(expected));
  }
});

test('directional IVs: client and server streams differ and decrypt each other', () => {
  const key = SessionKey.generate(128);
  const iv = SessionCipher.generateIV();
  const client = new SessionCipher(key, iv, false);
  const server = new SessionCipher(key, iv, true);
  const msg = 'hello over netpipe';
  assert.equal(server.decrypt(client.encrypt(msg, 0), 0), msg);
  assert.equal(client.decrypt(server.encrypt(msg, 0), 0), msg);
  assert.notEqual(client.encrypt(msg, 0), server.encrypt(msg, 0)); // no two-time pad
});

test('X.509: Java test certificates verify against the CA; untrusted does not', () => {
  clientCert.verify(ca);
  serverCert.verify(ca);
  assert.throws(() => untrustedCert.verify(ca), /verification failed/);
  assert.equal(clientCert.getCN(), 'client.test.netpipe');
  assert.equal(HandshakeCertificate.fromBase64(clientCert.toBase64()).getBytes(), clientCert.getBytes());
});

test('RSA PKCS#1 v1.5 with the Java PKCS#8 keys, both directions', () => {
  const data = 'sixteen byte key';
  assert.equal(serverKey.decrypt(HandshakeCrypto.fromCertificate(serverCert).encrypt(data)), data);
  const signed = clientKey.encrypt(data);
  assert.equal(HandshakeCrypto.fromCertificate(clientCert).decrypt(signed), data);
  assert.throws(() => HandshakeCrypto.fromCertificate(serverCert).decrypt(signed));
});

test('HandshakeMessage: canonical encoding round-trips and rejects bad input', () => {
  const m = new HandshakeMessage(MessageType.SESSION);
  m.putParameter('SessionKey', 'b');
  m.putParameter('SessionIV', 'a');
  assert.equal(m.encode(), '{"MessageType":"SESSION","SessionIV":"a","SessionKey":"b"}');
  const decoded = HandshakeMessage.decode(m.encode(), MessageType.SESSION);
  assert.equal(decoded.getParameter('SessionKey'), 'b');
  assert.throws(() => HandshakeMessage.decode(m.encode(), MessageType.CLIENTHELLO), /Expected CLIENTHELLO/);
  assert.throws(() => HandshakeMessage.decode('{"MessageType":"EVIL"}'), /Unknown message type/);
  assert.throws(() => HandshakeMessage.decode('x'.repeat(70000)), /too large/);
});

test('state machine rejects out-of-order transitions', () => {
  const sm = new ProtocolStateMachine('client');
  assert.throws(() => sm.transition(ProtocolState.SESSION_SENT), /Invalid state transition/);
  sm.transition(ProtocolState.CLIENT_HELLO_SENT);
  sm.transition(ProtocolState.FAILED);
  assert.throws(() => sm.transition(ProtocolState.CLOSED));
});

test('timestamps: Java window and async window', () => {
  const now = Date.UTC(2026, 10, 16, 12, 0, 0);
  validateTimestamp(formatTimestamp(new Date(now - 299000)), { nowMs: now });
  assert.throws(() => validateTimestamp(formatTimestamp(new Date(now - 301000)), { nowMs: now }), /outside/);
  // Async: an hour-old Finished is fine if the handshake started before it.
  validateTimestamp(formatTimestamp(new Date(now - 3600000)), { nowMs: now, notBeforeMs: now - 3600000 });
  assert.throws(() => validateTimestamp('2026-02-30 10:00:00'), /Malformed/);
});

test('full handshake with Java test certificates, then signed records both ways', () => {
  const trustCa = (cert) => cert.verify(ca);
  const client = new ProtocolStateMachine('client');
  const server = new ProtocolStateMachine('server');

  const clientHello = createHello(MessageType.CLIENTHELLO, clientCert);
  client.transition(ProtocolState.CLIENT_HELLO_SENT);

  const ch = HandshakeMessage.decode(clientHello.encode(), MessageType.CLIENTHELLO);
  server.transition(ProtocolState.CLIENT_HELLO_RECEIVED);
  const seenClientCert = receiveHello(ch, trustCa);
  server.transition(ProtocolState.CERTIFICATE_VERIFIED);
  const serverHello = createHello(MessageType.SERVERHELLO, serverCert);
  server.transition(ProtocolState.SERVER_HELLO_SENT);

  const sh = HandshakeMessage.decode(serverHello.encode(), MessageType.SERVERHELLO);
  client.transition(ProtocolState.SERVER_HELLO_RECEIVED);
  const seenServerCert = receiveHello(sh, trustCa);
  client.transition(ProtocolState.CERTIFICATE_VERIFIED);
  const { message: session, sessionKey, iv } = createSession(seenServerCert);
  client.transition(ProtocolState.SESSION_SENT);

  const sess = HandshakeMessage.decode(session.encode(), MessageType.SESSION);
  const received = receiveSession(sess, serverKey);
  assert.equal(received.sessionKey.getKeyBytes(), sessionKey.getKeyBytes());
  assert.equal(received.iv, iv);
  server.transition(ProtocolState.SESSION_RECEIVED);
  const serverFinished = createFinished(MessageType.SERVERFINISHED, serverKey, serverFinishedSigns({ serverHello }));
  server.transition(ProtocolState.SERVER_FINISHED_SENT);

  verifyFinished(
    HandshakeMessage.decode(serverFinished.encode()),
    MessageType.SERVERFINISHED,
    seenServerCert,
    serverFinishedSigns({ serverHello: sh })
  );
  client.transition(ProtocolState.SERVER_FINISHED_VERIFIED);
  const clientFinished = createFinished(MessageType.CLIENTFINISHED, clientKey, clientFinishedSigns({ clientHello, session }));
  client.transition(ProtocolState.CLIENT_FINISHED_SENT);
  client.transition(ProtocolState.SECURE_CHANNEL_ESTABLISHED);

  const cf = HandshakeMessage.decode(clientFinished.encode());
  verifyFinished(cf, MessageType.CLIENTFINISHED, seenClientCert, clientFinishedSigns({ clientHello: ch, session: sess }));
  server.transition(ProtocolState.CLIENT_FINISHED_VERIFIED);
  server.transition(ProtocolState.SECURE_CHANNEL_ESTABLISHED);

  // A Finished signed over the wrong transcript is rejected.
  assert.throws(
    () => verifyFinished(cf, MessageType.CLIENTFINISHED, seenClientCert, clientFinishedSigns({ clientHello: ch, session: ch })),
    /Signature verification failed/
  );

  const clientChannel = new SecureChannel({
    sessionId: 's1', isServer: false, sessionKey, iv,
    privateKey: clientKey, ownCertificate: clientCert, peerCertificate: seenServerCert,
  });
  const serverChannel = new SecureChannel({
    sessionId: 's1', isServer: true, sessionKey: received.sessionKey, iv: received.iv,
    privateKey: serverKey, ownCertificate: serverCert, peerCertificate: seenClientCert,
  });

  const r1 = clientChannel.seal('Hej! 👋 secure sms', 0);
  const r2 = serverChannel.seal('{"type":"offer","sdp":"v=0..."}', 0);
  assert.equal(serverChannel.open(r1), 'Hej! 👋 secure sms');
  assert.equal(clientChannel.open(r2), '{"type":"offer","sdp":"v=0..."}');
  assert.equal(clientChannel.open(r1), 'Hej! 👋 secure sms'); // own history
  assert.notEqual(decodeBase64(r1.ciphertext), 'Hej! 👋 secure sms');

  // Tampering with ciphertext, offset or direction is detected.
  const flipped = Buffer.from(r1.ciphertext, 'base64');
  flipped[0] ^= 1;
  assert.throws(() => serverChannel.open({ ...r1, ciphertext: flipped.toString('base64') }), /signature/);
  assert.throws(() => serverChannel.open({ ...r1, offset: 16 }), /signature/);
  assert.throws(() => serverChannel.open({ ...r1, direction: 's2c' }), /signature/);
});

test('createIdentity: self-signed certificate usable as its own CA', async () => {
  const identity = await createIdentity('alice@example.com');
  const cert = HandshakeCertificate.fromPem(identity.certificatePem);
  cert.verify(cert);
  assert.equal(cert.getCN(), 'alice@example.com');
  assert.equal(cert.getEmail(), 'alice@example.com');
  const key = HandshakeCrypto.fromPrivateKeyPem(identity.privateKeyPem);
  assert.equal(key.decrypt(HandshakeCrypto.fromCertificate(cert).encrypt('k')), 'k');
  assert.equal(new HandshakeDigest().digest().length, 32);
});
