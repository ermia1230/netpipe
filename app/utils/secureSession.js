/**
 * NetPipe secure sessions for chats and calls, with Firestore as the transport.
 *
 * Every chat runs the NetPipe handshake (app/netpipe, a port of the Java
 * protocol) between its two participants. The handshake messages are stored in
 *
 *   chats/{chatId}/netpipe/{sessionId}
 *     clientId, serverId, startedAtMs
 *     state          last NetPipe ProtocolState reached by the sender
 *     clientHello, serverHello, session, serverFinished, clientFinished
 *                    encoded HandshakeMessages (exact bytes that are signed)
 *     offsets        { c2s, s2c }: next free byte in each AES-CTR direction
 *     failure        reason, if a check failed
 *
 *   chats/{chatId}.netpipeSession   id of the chat's current session
 *
 * Whoever opens a chat without a working session becomes the NetPipe client
 * and sends CLIENTHELLO; the other participant's app (on any screen) answers as
 * the server. Each side re-verifies the whole transcript (certificates, Finished
 * signatures) before it trusts a session, so a tampered document is rejected.
 *
 * Identities: each user has an RSA-2048 key pair and a self-signed X.509
 * certificate (CN = email) made on their device. The private key stays on the
 * device; the certificate is published in users/{uid}.certificate. There is no
 * CA, so users can compare the "safety code" shown in the chat to rule out a
 * swapped certificate.
 */
import * as ExpoCrypto from 'expo-crypto';
import {
  collection,
  doc,
  getDoc,
  onSnapshot,
  query,
  runTransaction,
  serverTimestamp,
  setDoc,
  where,
} from 'firebase/firestore';
import { auth, db } from '../config/firebaseInit';
import { getSecret, setSecret } from './keyStore';
import {
  CertificateValidationError,
  HandshakeCertificate,
  HandshakeCrypto,
  HandshakeDigest,
  SessionKey,
  createIdentity,
  decodeBase64,
  encodeBase64,
  utf8Encode,
} from '../netpipe/crypto.js';
import { hasSecureRandom, setRandomSource } from '../netpipe/random.js';
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
  receiveHello,
  receiveSession,
  serverFinishedSigns,
  verifyFinished,
} from '../netpipe/protocol.js';

// React Native has no crypto.getRandomValues; use the OS generator via expo-crypto.
if (!hasSecureRandom() && typeof ExpoCrypto.getRandomValues === 'function') {
  setRandomSource((array) => ExpoCrypto.getRandomValues(array));
}

/** Byte ranges reserved per Firestore transaction (fewer round trips for calls). */
const LEASE_BYTES = 8192;
const MAX_AUTO_RESTARTS = 2;

const S = ProtocolState;
const hex = (bytes) => Array.from(bytes, (c) => c.charCodeAt(0).toString(16).padStart(2, '0')).join('');
const sha256Hex = (text) => {
  const d = new HandshakeDigest();
  d.update(utf8Encode(text));
  return hex(d.digest());
};

// --- Identity -------------------------------------------------------------

let identityPromise = null;
let identityUid = null;

/** Load this user's NetPipe identity from the device, or create and publish one. */
export function ensureIdentity(user) {
  if (identityPromise && identityUid === user.uid) return identityPromise;
  identityUid = user.uid;
  identityPromise = loadOrCreateIdentity(user).catch((error) => {
    identityPromise = null;
    throw error;
  });
  return identityPromise;
}

async function loadOrCreateIdentity(user) {
  const email = user.email.toLowerCase();
  const prefix = `netpipe.${user.uid}`;
  let keyPem = await getSecret(`${prefix}.key`);
  let certPem = await getSecret(`${prefix}.cert`);

  let certificate = null;
  try {
    certificate = certPem ? HandshakeCertificate.fromPem(certPem) : null;
  } catch {
    certificate = null;
  }
  const usable =
    certificate &&
    keyPem &&
    certificate.getEmail()?.toLowerCase() === email &&
    certificate.certificate.validity.notAfter.getTime() > Date.now() + 24 * 3600 * 1000;

  if (!usable) {
    const created = await createIdentity(email);
    keyPem = created.privateKeyPem;
    certPem = created.certificatePem;
    await setSecret(`${prefix}.key`, keyPem);
    await setSecret(`${prefix}.cert`, certPem);
    certificate = HandshakeCertificate.fromPem(certPem);
  }

  // Publish the certificate so others can start handshakes with this device.
  await setDoc(
    doc(db, 'users', user.uid),
    { certificate: certificate.toBase64(), certificateFingerprint: certificate.fingerprint() },
    { merge: true }
  );

  return {
    uid: user.uid,
    email,
    certificate,
    privateKey: HandshakeCrypto.fromPrivateKeyPem(keyPem),
  };
}

async function publishedCertificate(uid) {
  const b64 = (await getDoc(doc(db, 'users', uid))).data()?.certificate;
  return b64 ? HandshakeCertificate.fromBase64(b64) : null;
}

/** Short code both users see identically; compare it in person or by phone. */
export function safetyCode(certA, certB) {
  const [a, b] = [certA.fingerprint(), certB.fingerprint()].sort();
  return sha256Hex(`${a}|${b}`).slice(0, 24).toUpperCase().match(/.{4}/g).join(' ');
}

// --- Handshake evaluation -------------------------------------------------

const peerOf = (chat, myUid) => {
  const index = chat.participants.findIndex((id) => id !== myUid);
  return { uid: chat.participants[index], email: (chat.participantNames?.[index] ?? '').toLowerCase() };
};

/** The peer's certificate must be valid, self-signed, and name the peer's account email. */
function verifyPeerCertificate(certificate, peer) {
  certificate.verify(certificate);
  const name = (certificate.getEmail() ?? certificate.getCN() ?? '').toLowerCase();
  if (!peer.email || name !== peer.email) {
    throw new CertificateValidationError(`Certificate is for "${name}", expected "${peer.email}"`);
  }
}

async function assertPublished(peer, certificate) {
  const published = await publishedCertificate(peer.uid);
  if (!published || !published.equals(certificate)) {
    throw new CertificateValidationError(`${peer.email}'s certificate does not match their published one`);
  }
}

const sessionSecretKey = (uid, sessionId, sessionMessage) =>
  `netpipe.${uid}.s.${sessionId}.${sha256Hex(sessionMessage).slice(0, 16)}`;

/** Advance the handshake document if it is still in the state we evaluated. */
const advance = (ref, precondition, update) =>
  runTransaction(db, async (tx) => {
    const snap = await tx.get(ref);
    if (!snap.exists() || !precondition(snap.data())) return false;
    tx.update(ref, { ...update, updatedAt: serverTimestamp() });
    return true;
  });

/**
 * Replay and verify the stored transcript from this user's point of view, with
 * the same state machine as the Java client/server.
 *
 * Returns { status: 'waiting' | 'action' | 'established' | 'stale' | 'failed', ... }.
 * 'action' carries a function that sends this user's next handshake message.
 */
async function evaluateSession({ chatId, sessionId, data, identity, peer }) {
  const ref = doc(db, 'chats', chatId, 'netpipe', sessionId);
  const isClient = data.clientId === identity.uid;
  if (!isClient && data.serverId !== identity.uid) return { status: 'failed', error: 'Not a participant' };
  if (data.state === S.FAILED) return { status: 'failed', error: data.failure ?? 'Handshake failed' };

  const sm = new ProtocolStateMachine(isClient ? 'client' : 'server');
  const freshness = { notBeforeMs: data.startedAtMs ?? 0 };
  const ownCertIn = (hello) => HandshakeCertificate.fromBase64(hello.getParameter('Certificate') ?? '');
  const result = (status, extra = {}) => ({ status, state: sm.getState(), isClient, ...extra });

  try {
    const clientHello = HandshakeMessage.decode(data.clientHello, MessageType.CLIENTHELLO);

    if (isClient) {
      if (!ownCertIn(clientHello).equals(identity.certificate)) return result('stale');
      sm.transition(S.CLIENT_HELLO_SENT);
      if (!data.serverHello) return result('waiting');

      const serverHello = HandshakeMessage.decode(data.serverHello, MessageType.SERVERHELLO);
      sm.transition(S.SERVER_HELLO_RECEIVED);
      const serverCert = receiveHello(serverHello, (c) => verifyPeerCertificate(c, peer));
      sm.transition(S.CERTIFICATE_VERIFIED);

      if (!data.session) {
        return result('action', {
          step: MessageType.SESSION,
          action: async () => {
            await assertPublished(peer, serverCert);
            const { message, sessionKey, iv } = createSession(serverCert);
            // Keep our copy of the key on this device before sending it.
            await setSecret(
              sessionSecretKey(identity.uid, sessionId, message.encode()),
              JSON.stringify({ key: encodeBase64(sessionKey.getKeyBytes()), iv: encodeBase64(iv) })
            );
            await advance(ref, (d) => !d.session && d.serverHello === data.serverHello, {
              session: message.encode(),
              state: S.SESSION_SENT,
            });
          },
        });
      }
      const session = HandshakeMessage.decode(data.session, MessageType.SESSION);
      sm.transition(S.SESSION_SENT);
      const stored = await getSecret(sessionSecretKey(identity.uid, sessionId, data.session));
      if (!stored) return result('stale'); // key made on another device or lost
      if (!data.serverFinished) return result('waiting');

      verifyFinished(
        HandshakeMessage.decode(data.serverFinished, MessageType.SERVERFINISHED),
        MessageType.SERVERFINISHED,
        serverCert,
        serverFinishedSigns({ serverHello }),
        freshness
      );
      sm.transition(S.SERVER_FINISHED_VERIFIED);

      if (!data.clientFinished) {
        return result('action', {
          step: MessageType.CLIENTFINISHED,
          action: () => {
            const finished = createFinished(
              MessageType.CLIENTFINISHED,
              identity.privateKey,
              clientFinishedSigns({ clientHello, session })
            );
            return advance(ref, (d) => !d.clientFinished && d.serverFinished === data.serverFinished, {
              clientFinished: finished.encode(),
              state: S.CLIENT_FINISHED_SENT,
            });
          },
        });
      }
      verifyFinished(
        HandshakeMessage.decode(data.clientFinished, MessageType.CLIENTFINISHED),
        MessageType.CLIENTFINISHED,
        identity.certificate,
        clientFinishedSigns({ clientHello, session }),
        false
      );
      sm.transition(S.CLIENT_FINISHED_SENT);
      sm.transition(S.SECURE_CHANNEL_ESTABLISHED);

      const { key, iv } = JSON.parse(stored);
      return result('established', {
        channel: new SecureChannel({
          sessionId,
          isServer: false,
          sessionKey: new SessionKey(decodeBase64(key)),
          iv: decodeBase64(iv),
          privateKey: identity.privateKey,
          ownCertificate: identity.certificate,
          peerCertificate: serverCert,
        }),
      });
    }

    // Server side
    sm.transition(S.CLIENT_HELLO_RECEIVED);
    const clientCert = receiveHello(clientHello, (c) => verifyPeerCertificate(c, peer));
    sm.transition(S.CERTIFICATE_VERIFIED);

    if (!data.serverHello) {
      return result('action', {
        step: MessageType.SERVERHELLO,
        action: async () => {
          await assertPublished(peer, clientCert);
          const hello = createHello(MessageType.SERVERHELLO, identity.certificate);
          await advance(ref, (d) => !d.serverHello && d.clientHello === data.clientHello, {
            serverHello: hello.encode(),
            state: S.SERVER_HELLO_SENT,
          });
        },
      });
    }
    const serverHello = HandshakeMessage.decode(data.serverHello, MessageType.SERVERHELLO);
    if (!ownCertIn(serverHello).equals(identity.certificate)) return result('stale');
    sm.transition(S.SERVER_HELLO_SENT);
    if (!data.session) return result('waiting');

    const session = HandshakeMessage.decode(data.session, MessageType.SESSION);
    const { sessionKey, iv } = receiveSession(session, identity.privateKey);
    sm.transition(S.SESSION_RECEIVED);

    if (!data.serverFinished) {
      return result('action', {
        step: MessageType.SERVERFINISHED,
        action: () => {
          const finished = createFinished(
            MessageType.SERVERFINISHED,
            identity.privateKey,
            serverFinishedSigns({ serverHello })
          );
          return advance(ref, (d) => !d.serverFinished && d.session === data.session, {
            serverFinished: finished.encode(),
            state: S.SERVER_FINISHED_SENT,
          });
        },
      });
    }
    sm.transition(S.SERVER_FINISHED_SENT);
    if (!data.clientFinished) return result('waiting');

    verifyFinished(
      HandshakeMessage.decode(data.clientFinished, MessageType.CLIENTFINISHED),
      MessageType.CLIENTFINISHED,
      clientCert,
      clientFinishedSigns({ clientHello, session }),
      freshness
    );
    sm.transition(S.CLIENT_FINISHED_VERIFIED);
    sm.transition(S.SECURE_CHANNEL_ESTABLISHED);

    if (data.state !== S.SECURE_CHANNEL_ESTABLISHED) {
      advance(ref, (d) => d.state === S.CLIENT_FINISHED_SENT, { state: S.SECURE_CHANNEL_ESTABLISHED }).catch(
        (error) => console.warn('[netpipe] could not mark session established:', error)
      );
    }
    return result('established', {
      channel: new SecureChannel({
        sessionId,
        isServer: true,
        sessionKey,
        iv,
        privateKey: identity.privateKey,
        ownCertificate: identity.certificate,
        peerCertificate: clientCert,
      }),
    });
  } catch (error) {
    // Any decode/verify error is a protocol failure: record it like the Java FAILED state.
    const reason = `${isClient ? 'client' : 'server'}: ${error.message}`;
    console.warn(`[netpipe] handshake ${sessionId} failed at ${sm.getState()}:`, error);
    advance(ref, (d) => d.state !== S.FAILED, { state: S.FAILED, failure: reason }).catch(() => {});
    return result('failed', { error: reason });
  }
}

// --- Per-chat session manager ----------------------------------------------

const STATUS_TEXT = {
  connecting: 'Connecting…',
  identity: 'Preparing your encryption keys…',
  none: 'No secure session yet',
  handshaking: 'Establishing secure session…',
  waiting: 'Waiting for the other person to come online…',
  established: 'End-to-end encrypted with NetPipe',
  failed: 'Secure session failed',
};

class ChatSession {
  constructor(chatId, user) {
    this.chatId = chatId;
    this.user = user;
    this.listeners = new Set();
    this.autoStartCount = 0;
    this.snapshot = { status: 'connecting', text: STATUS_TEXT.connecting };
    this.chat = null;
    this.sessionId = null;
    this.sessionData = undefined;
    this.channel = null;
    this.channels = new Map(); // sessionId -> Promise<SecureChannel | null>
    this.leases = new Map();
    this.restarts = 0;
    this.rekeyChecked = new Set();
    this.running = false;
    this.rerun = false;
  }

  subscribe(listener, { autoStart = false } = {}) {
    this.listeners.add(listener);
    if (autoStart) this.autoStartCount++;
    this._start();
    listener(this.snapshot);
    if (autoStart) this._schedule();
    return () => {
      this.listeners.delete(listener);
      if (autoStart) this.autoStartCount--;
    };
  }

  _set(update) {
    const status = update.status;
    this.snapshot = { ...update, text: update.text ?? STATUS_TEXT[status] };
    this.listeners.forEach((l) => l(this.snapshot));
  }

  _start() {
    if (this.unsubChat) return;
    this.unsubChat = onSnapshot(
      doc(db, 'chats', this.chatId),
      (snap) => {
        this.chat = snap.data() ?? null;
        const id = this.chat?.netpipeSession ?? null;
        if (id !== this.sessionId) {
          this.unsubSession?.();
          this.unsubSession = null;
          this.sessionId = id;
          this.sessionData = undefined;
          this.channel = null;
          if (id) {
            this.unsubSession = onSnapshot(
              doc(db, 'chats', this.chatId, 'netpipe', id),
              (s) => {
                this.sessionData = s.data() ?? null;
                this._schedule();
              },
              (error) => this._onListenError(error)
            );
          }
        }
        this._schedule();
      },
      (error) => this._onListenError(error)
    );
  }

  /** Firestore listeners stop after an error (e.g. a chat read before it exists); resubscribe. */
  _onListenError(error) {
    console.warn(`[netpipe] listener for chat ${this.chatId} failed, retrying:`, error.message);
    this.stop();
    this._set({ status: 'connecting' });
    clearTimeout(this.retryTimer);
    this.retryTimer = setTimeout(() => {
      if (this.listeners.size > 0) this._start();
    }, 2000);
  }

  stop() {
    clearTimeout(this.retryTimer);
    this.unsubChat?.();
    this.unsubSession?.();
    this.unsubChat = this.unsubSession = null;
    this.sessionId = null;
    this.sessionData = undefined;
    this.channel = null;
    this.verifiedTranscript = null;
  }

  _schedule() {
    if (this.running) {
      this.rerun = true;
      return;
    }
    this.running = true;
    this._run()
      .catch((error) => {
        console.warn('[netpipe]', error);
        this._set({ status: 'failed', text: error.message });
      })
      .finally(() => {
        this.running = false;
        if (this.rerun) {
          this.rerun = false;
          this._schedule();
        }
      });
  }

  async _run() {
    if (!this.chat) return;
    if (!identityPromise) this._set({ status: 'identity' });
    const identity = await ensureIdentity(this.user);
    const peer = peerOf(this.chat, identity.uid);
    const autoStart = this.autoStartCount > 0;

    if (!this.sessionId) {
      if (autoStart) await this._startSession(null, identity, peer);
      else this._set({ status: 'none' });
      return;
    }
    if (this.sessionData === undefined) return; // still loading
    const sessionId = this.sessionId;

    // Chat/offset updates don't change the transcript; skip re-verifying it.
    const d = this.sessionData ?? {};
    const transcriptKey = [sessionId, d.state, d.clientHello, d.serverHello, d.session, d.serverFinished, d.clientFinished]
      .map((v) => v ?? '')
      .join('\u0000');
    if (this.channel && this.verifiedTranscript === transcriptKey) return;

    const result = this.sessionData
      ? await evaluateSession({ chatId: this.chatId, sessionId, data: this.sessionData, identity, peer })
      : { status: 'stale' };
    if (sessionId !== this.sessionId) return; // changed meanwhile; a rerun is scheduled

    const base = { sessionId, protocolState: result.state, isClient: result.isClient };
    switch (result.status) {
      case 'established': {
        this.channel = result.channel;
        this.verifiedTranscript = transcriptKey;
        this.restarts = 0;
        this.channels.set(sessionId, Promise.resolve(result.channel));
        this._set({
          ...base,
          status: 'established',
          safetyCode: safetyCode(identity.certificate, result.channel.peerCertificate),
        });
        // If the other person got new keys (new device), they can't read this session any more.
        if (autoStart && !this.rekeyChecked.has(sessionId)) {
          this.rekeyChecked.add(sessionId);
          const published = await publishedCertificate(peer.uid);
          if (published && !published.equals(result.channel.peerCertificate)) {
            await this._startSession(sessionId, identity, peer);
          }
        }
        return;
      }
      case 'action':
        this._set({ ...base, status: 'handshaking', text: `Establishing secure session… (sending ${result.step})` });
        await result.action(); // the snapshot listener re-evaluates afterwards
        return;
      case 'waiting':
        this._set({ ...base, status: 'waiting' });
        return;
      case 'stale':
      case 'failed':
        if (autoStart && this.restarts < MAX_AUTO_RESTARTS) {
          await this._startSession(sessionId, identity, peer);
        } else {
          this._set({ ...base, status: 'failed', text: result.error ? `Secure session failed (${result.error})` : undefined });
        }
        return;
      default:
    }
  }

  /** Become the NetPipe client: create a session with CLIENTHELLO and make it current. */
  async _startSession(previousId, identity, peer) {
    this.restarts++;
    this._set({ status: 'handshaking', text: 'Establishing secure session… (sending CLIENTHELLO)' });
    const chatRef = doc(db, 'chats', this.chatId);
    const sessionRef = doc(collection(db, 'chats', this.chatId, 'netpipe'));
    const clientHello = createHello(MessageType.CLIENTHELLO, identity.certificate);
    await runTransaction(db, async (tx) => {
      const snap = await tx.get(chatRef);
      if ((snap.data()?.netpipeSession ?? null) !== previousId) return; // someone else already did
      tx.set(sessionRef, {
        clientId: identity.uid,
        serverId: peer.uid,
        clientEmail: identity.email,
        serverEmail: peer.email,
        startedAtMs: Date.now(),
        state: S.CLIENT_HELLO_SENT,
        clientHello: clientHello.encode(),
        offsets: { c2s: 0, s2c: 0 },
        createdAt: serverTimestamp(),
      });
      tx.update(chatRef, { netpipeSession: sessionRef.id });
    });
  }

  retry() {
    this.restarts = 0;
    if (!this.chat) return;
    ensureIdentity(this.user)
      .then((identity) => this._startSession(this.sessionId, identity, peerOf(this.chat, identity.uid)))
      .catch((error) => this._set({ status: 'failed', text: error.message }));
  }

  /** Channel for any (also older) session of this chat, after full verification. */
  getChannel(sessionId) {
    if (!this.channels.has(sessionId)) {
      const promise = (async () => {
        const identity = await ensureIdentity(this.user);
        const chat = this.chat ?? (await getDoc(doc(db, 'chats', this.chatId))).data();
        const data = (await getDoc(doc(db, 'chats', this.chatId, 'netpipe', sessionId))).data();
        if (!chat || !data) return null;
        const result = await evaluateSession({
          chatId: this.chatId,
          sessionId,
          data,
          identity,
          peer: peerOf(chat, identity.uid),
        });
        return result.status === 'established' ? result.channel : null;
      })();
      this.channels.set(sessionId, promise);
      // Retry later instead of caching a failure forever.
      promise.then((c) => !c && this.channels.delete(sessionId)).catch(() => this.channels.delete(sessionId));
    }
    return this.channels.get(sessionId);
  }

  /**
   * Reserve `length` bytes of this endpoint's CTR stream. Offsets are never reused:
   * Firestore hands out ranges in a transaction, and a high-water mark kept on the
   * device stops a tampered counter from making us reuse keystream.
   */
  async reserve(channel, length) {
    const direction = channel.outgoingDirection;
    const leaseKey = `${channel.sessionId}.${direction}`;
    let lease = this.leases.get(leaseKey);
    if (!lease || lease.next + length > lease.end) {
      const size = Math.max(length, LEASE_BYTES);
      const markKey = `netpipe.${this.user.uid}.hw.${leaseKey}`;
      const mark = Number((await getSecret(markKey)) ?? 0);
      const ref = doc(db, 'chats', this.chatId, 'netpipe', channel.sessionId);
      const start = await runTransaction(db, async (tx) => {
        const current = (await tx.get(ref)).data()?.offsets?.[direction] ?? 0;
        const from = Math.max(current, mark);
        tx.update(ref, { [`offsets.${direction}`]: from + size });
        return from;
      });
      await setSecret(markKey, String(start + size));
      lease = { next: start, end: start + size };
      this.leases.set(leaseKey, lease);
    }
    const offset = lease.next;
    lease.next += length;
    return offset;
  }
}

let currentUser = null;
const sessions = new Map();

function getChatSession(chatId) {
  const user = currentUser ?? auth.currentUser;
  if (!user) throw new Error('Not signed in');
  let session = sessions.get(chatId);
  if (!session) {
    session = new ChatSession(chatId, user);
    sessions.set(chatId, session);
  }
  return session;
}

// --- Public API -------------------------------------------------------------

/**
 * Start NetPipe for the signed-in user: make/publish the identity and answer
 * handshakes for all their chats in the background. Returns a stop function.
 */
export function startSecureSessions(user) {
  currentUser = user;
  ensureIdentity(user).catch((error) => console.error('[netpipe] identity setup failed:', error));

  const subscriptions = new Map();
  const unsubscribe = onSnapshot(
    query(collection(db, 'chats'), where('participants', 'array-contains', user.uid)),
    (snapshot) => {
      const ids = new Set(snapshot.docs.map((d) => d.id));
      ids.forEach((id) => {
        if (!subscriptions.has(id)) subscriptions.set(id, getChatSession(id).subscribe(() => {}));
      });
      subscriptions.forEach((unsub, id) => {
        if (!ids.has(id)) {
          unsub();
          subscriptions.delete(id);
        }
      });
    },
    (error) => console.error('[netpipe] chat listener failed:', error)
  );

  return () => {
    unsubscribe();
    subscriptions.forEach((unsub) => unsub());
    sessions.forEach((s) => s.stop());
    sessions.clear();
    currentUser = null;
    identityPromise = null;
    identityUid = null;
  };
}

/** Follow a chat's secure-session status; starts a handshake if there is none. */
export function watchSecureSession(chatId, listener) {
  return getChatSession(chatId).subscribe(listener, { autoStart: true });
}

export function retrySecureSession(chatId) {
  getChatSession(chatId).retry();
}

/** Wait until the chat's session is established (starting one if needed). */
export function waitForSecureChannel(chatId, timeoutMs = 20000) {
  return new Promise((resolve, reject) => {
    let unsubscribe = () => {};
    const timer = setTimeout(() => {
      unsubscribe();
      reject(new Error('Could not establish a secure NetPipe session in time. Both people need to have the app open.'));
    }, timeoutMs);
    const session = getChatSession(chatId);
    unsubscribe = session.subscribe(
      (snapshot) => {
        if (snapshot.status === 'established' && session.channel) {
          clearTimeout(timer);
          setTimeout(() => unsubscribe(), 0);
          resolve(session.channel);
        }
      },
      { autoStart: true }
    );
  });
}

/** Encrypt and sign text in the chat's current session. */
export async function sealText(chatId, plaintext) {
  const session = getChatSession(chatId);
  const channel = session.channel;
  if (!channel) throw new Error('The secure session is not established yet.');
  const offset = await session.reserve(channel, SecureChannel.byteLength(plaintext));
  return { session: channel.sessionId, ...channel.seal(plaintext, offset) };
}

/** Verify and decrypt a record of this chat (from either participant). */
export async function openRecord(chatId, record, { fromPeerOnly = false } = {}) {
  if (!record?.session) throw new Error('Not a NetPipe record');
  const channel = await getChatSession(chatId).getChannel(record.session);
  if (!channel) throw new Error('No verified NetPipe session for this record');
  if (fromPeerOnly && record.direction !== channel.incomingDirection) {
    throw new Error('Record was not sent by the other participant');
  }
  return channel.open(record);
}
