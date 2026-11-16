/**
 * Audio/video calls using WebRTC, with Firestore as the signaling channel.
 *
 * calls/{callId}
 *   callerId, callerEmail, calleeId, calleeEmail, chatId, video
 *   status: 'ringing' | 'accepted' | 'declined' | 'missed' | 'ended'
 *   session                 NetPipe session of the chat that protects this call
 *   offer, answer           SDP descriptions as NetPipe records (encrypted + signed)
 *   callerCandidates/{id}   { netpipe: record } ICE candidates from the caller
 *   calleeCandidates/{id}   { netpipe: record } ICE candidates from the callee
 *
 * Security: the audio/video itself is encrypted by WebRTC (DTLS-SRTP). The keys
 * for that are bound to fingerprints inside the SDP, so the SDP and candidates
 * are sent through the chat's NetPipe session: encrypted with AES-CTR and
 * signed with the sender's RSA key. Firestore can therefore neither read the
 * call setup (IP addresses) nor swap in its own fingerprint to intercept media.
 *
 * Uses the browser's built-in WebRTC, so it works on web only for now.
 * Native phones need react-native-webrtc and a custom dev build.
 */
import {
  addDoc,
  collection,
  doc,
  getDoc,
  onSnapshot,
  serverTimestamp,
  setDoc,
  updateDoc,
} from 'firebase/firestore';
import { db } from '../config/firebaseInit';
import { openRecord, sealText, waitForSecureChannel } from './secureSession';

const ICE_SERVERS = {
  iceServers: [{ urls: ['stun:stun.l.google.com:19302', 'stun:stun1.l.google.com:19302'] }],
};

export const isCallingSupported = () =>
  typeof window !== 'undefined' &&
  typeof window.RTCPeerConnection === 'function' &&
  !!navigator.mediaDevices?.getUserMedia;

export const getLocalMedia = (video) =>
  navigator.mediaDevices.getUserMedia({
    audio: true,
    video: video ? { width: { ideal: 640 }, height: { ideal: 480 } } : false,
  });

export const setCallStatus = (callId, status) =>
  updateDoc(doc(db, 'calls', callId), { status, [`${status}At`]: serverTimestamp() });

export const watchCall = (callId, onUpdate) =>
  onSnapshot(doc(db, 'calls', callId), (snap) => snap.exists() && onUpdate(snap.data()));

/** Peer connection that queues remote ICE candidates until the remote description is set. */
function createPeer(localStream, onRemoteStream, onConnectionState) {
  const pc = new RTCPeerConnection(ICE_SERVERS);
  localStream.getTracks().forEach((track) => pc.addTrack(track, localStream));
  pc.ontrack = (event) => onRemoteStream(event.streams[0]);
  pc.onconnectionstatechange = () => onConnectionState(pc.connectionState);

  const pending = [];
  const addRemoteCandidate = (candidate) => {
    if (pc.remoteDescription) pc.addIceCandidate(candidate).catch(console.warn);
    else pending.push(candidate);
  };
  const setRemote = async (description) => {
    await pc.setRemoteDescription(description);
    pending.splice(0).forEach((c) => pc.addIceCandidate(c).catch(console.warn));
  };

  return { pc, addRemoteCandidate, setRemote };
}

const sealJson = (chatId, value) => sealText(chatId, JSON.stringify(value));

/** Decrypt a record from the other participant; anything else is rejected. */
const openJson = async (chatId, record) =>
  JSON.parse(await openRecord(chatId, record, { fromPeerOnly: true }));

const listenForCandidates = (chatId, collectionRef, addRemoteCandidate) =>
  onSnapshot(collectionRef, (snap) =>
    snap.docChanges().forEach((change) => {
      if (change.type !== 'added') return;
      openJson(chatId, change.doc.data().netpipe)
        .then(addRemoteCandidate)
        .catch((error) => console.warn('[netpipe] rejected ICE candidate:', error.message));
    })
  );

/** Caller side: create the call document with an offer and wait for an answer. */
export async function startCall({
  caller,
  callee,
  chatId,
  video,
  localStream,
  onRemoteStream,
  onConnectionState,
  onUpdate,
}) {
  const channel = await waitForSecureChannel(chatId);
  const { pc, addRemoteCandidate, setRemote } = createPeer(localStream, onRemoteStream, onConnectionState);
  const callRef = doc(collection(db, 'calls'));
  const candidatesRef = collection(callRef, 'callerCandidates');
  const sendCandidate = async (c) => addDoc(candidatesRef, { netpipe: await sealJson(chatId, c) });

  // Candidates can appear before the call document exists; hold them until it does.
  let callCreated = false;
  const earlyCandidates = [];
  pc.onicecandidate = ({ candidate }) => {
    if (!candidate) return;
    if (callCreated) sendCandidate(candidate.toJSON()).catch(console.warn);
    else earlyCandidates.push(candidate.toJSON());
  };

  const offer = await pc.createOffer();
  await pc.setLocalDescription(offer);
  const sealedOffer = await sealJson(chatId, { type: offer.type, sdp: offer.sdp });

  await setDoc(callRef, {
    callerId: caller.uid,
    callerEmail: caller.email,
    calleeId: callee.uid,
    calleeEmail: callee.email,
    chatId,
    video: !!video,
    status: 'ringing',
    session: channel.sessionId,
    offer: sealedOffer,
    createdAt: serverTimestamp(),
    createdAtMs: Date.now(),
  });
  callCreated = true;
  earlyCandidates.splice(0).forEach((c) => sendCandidate(c).catch(console.warn));

  let answerHandled = false;
  const unsubscribers = [
    onSnapshot(callRef, (snap) => {
      const data = snap.data();
      if (!data) return;
      if (data.answer && !answerHandled) {
        answerHandled = true;
        openJson(chatId, data.answer)
          .then(setRemote)
          .catch((error) => {
            console.error('[netpipe] rejected call answer:', error);
            onConnectionState('failed');
          });
      }
      onUpdate(data);
    }),
    listenForCandidates(chatId, collection(callRef, 'calleeCandidates'), addRemoteCandidate),
  ];

  return { callId: callRef.id, pc, cleanup: () => unsubscribers.forEach((u) => u()) };
}

/** Callee side: answer an incoming call. */
export async function answerCall({ callId, localStream, onRemoteStream, onConnectionState, onUpdate }) {
  const callRef = doc(db, 'calls', callId);
  const snap = await getDoc(callRef);
  const call = snap.data();
  if (!call || call.status !== 'ringing') throw new Error('This call is no longer available.');
  const { chatId } = call;

  // Verify the caller's signed offer before using it (throws if tampered).
  const offer = await openJson(chatId, call.offer);
  await waitForSecureChannel(chatId);

  const { pc, addRemoteCandidate, setRemote } = createPeer(localStream, onRemoteStream, onConnectionState);
  const candidatesRef = collection(callRef, 'calleeCandidates');
  pc.onicecandidate = ({ candidate }) => {
    if (!candidate) return;
    sealJson(chatId, candidate.toJSON())
      .then((record) => addDoc(candidatesRef, { netpipe: record }))
      .catch(console.warn);
  };

  await setRemote(offer);
  const answer = await pc.createAnswer();
  await pc.setLocalDescription(answer);
  await updateDoc(callRef, {
    answer: await sealJson(chatId, { type: answer.type, sdp: answer.sdp }),
    status: 'accepted',
    acceptedAt: serverTimestamp(),
  });

  const unsubscribers = [
    listenForCandidates(chatId, collection(callRef, 'callerCandidates'), addRemoteCandidate),
    onSnapshot(callRef, (s) => s.exists() && onUpdate(s.data())),
  ];

  return { pc, cleanup: () => unsubscribers.forEach((u) => u()) };
}
