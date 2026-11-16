import React, { useCallback, useEffect, useRef, useState } from 'react';
import { View, Text, TouchableOpacity, StyleSheet } from 'react-native';
import { Ionicons } from '@expo/vector-icons';
import { doc, getDoc } from 'firebase/firestore';
import { db, auth } from '../config/firebaseInit';
import VideoView from '../components/VideoView';
import {
  answerCall,
  getLocalMedia,
  isCallingSupported,
  setCallStatus,
  startCall,
  watchCall,
} from '../utils/callService';

const RING_TIMEOUT_MS = 30000;

const STATUS_TEXT = {
  starting: 'Securing call with NetPipe...',
  ringing: 'Ringing...',
  incoming: 'Incoming call',
  connecting: 'Connecting...',
  connected: '',
  declined: 'Call declined',
  missed: 'No answer',
  ended: 'Call ended',
  unsupported: 'Calling currently works in the web version only.',
  error: 'Call failed',
};

const formatDuration = (seconds) =>
  `${String(Math.floor(seconds / 60)).padStart(2, '0')}:${String(seconds % 60).padStart(2, '0')}`;

/**
 * Route params:
 *   outgoing: { mode: 'outgoing', chatId, userName, video }
 *   incoming: { mode: 'incoming', callId, userName, video }
 */
export default function CallScreen({ route, navigation }) {
  const { mode = 'outgoing', chatId, userName, video = false } = route.params;
  const [status, setStatus] = useState(
    !isCallingSupported() ? 'unsupported' : mode === 'incoming' ? 'incoming' : 'starting'
  );
  const [errorMessage, setErrorMessage] = useState('');
  const [localStream, setLocalStream] = useState(null);
  const [remoteStream, setRemoteStream] = useState(null);
  const [isMuted, setIsMuted] = useState(false);
  const [isCameraOff, setIsCameraOff] = useState(false);
  const [seconds, setSeconds] = useState(0);

  const callIdRef = useRef(route.params.callId ?? null);
  const pcRef = useRef(null);
  const localStreamRef = useRef(null);
  const cleanupsRef = useRef([]);
  const finishedRef = useRef(false);
  const ringTimerRef = useRef(null);

  const isFinal = ['declined', 'missed', 'ended', 'error', 'unsupported'].includes(status);

  // Stop media, close the connection and unsubscribe from Firestore.
  const teardown = useCallback(() => {
    cleanupsRef.current.splice(0).forEach((fn) => fn());
    pcRef.current?.close();
    pcRef.current = null;
    localStreamRef.current?.getTracks().forEach((t) => t.stop());
    localStreamRef.current = null;
  }, []);

  const close = useCallback(() => {
    if (navigation.canGoBack()) navigation.goBack();
  }, [navigation]);

  // Move to a final state, tear down, and leave the screen shortly after.
  const finish = useCallback(
    (finalStatus, { notify = false, delay = 1200 } = {}) => {
      if (finishedRef.current) return;
      finishedRef.current = true;
      if (notify && callIdRef.current) setCallStatus(callIdRef.current, finalStatus).catch(console.warn);
      teardown();
      setStatus(finalStatus);
      setTimeout(close, delay);
    },
    [teardown, close]
  );

  // React to the other side changing the call document.
  const handleCallUpdate = useCallback(
    (call) => {
      if (call.status === 'accepted') {
        clearTimeout(ringTimerRef.current);
        setStatus((s) => (s === 'connected' ? s : 'connecting'));
      }
      if (['declined', 'missed', 'ended'].includes(call.status)) finish(call.status);
    },
    [finish]
  );

  const handleConnectionState = useCallback(
    (state) => {
      if (state === 'connected') setStatus('connected');
      if (state === 'failed') finish('error', { notify: true });
    },
    [finish]
  );

  const fail = useCallback(
    (error) => {
      console.error('Call error:', error);
      setErrorMessage(
        error?.name === 'NotAllowedError'
          ? 'Microphone/camera access was blocked. Allow it in your browser and try again.'
          : error?.message ?? String(error)
      );
      finish('error', { notify: true, delay: 3000 });
    },
    [finish]
  );

  const openMedia = async () => {
    const stream = await getLocalMedia(video);
    localStreamRef.current = stream;
    setLocalStream(stream);
    return stream;
  };

  // Outgoing: place the call as soon as the screen opens.
  useEffect(() => {
    if (mode !== 'outgoing' || !isCallingSupported()) return;
    let cancelled = false;

    (async () => {
      try {
        const me = auth.currentUser;
        const chat = (await getDoc(doc(db, 'chats', chatId))).data();
        const index = chat.participants.findIndex((id) => id !== me.uid);
        const callee = { uid: chat.participants[index], email: chat.participantNames?.[index] ?? userName };

        const stream = await openMedia();
        if (cancelled) return;

        const call = await startCall({
          caller: { uid: me.uid, email: me.email },
          callee,
          chatId,
          video,
          localStream: stream,
          onRemoteStream: setRemoteStream,
          onConnectionState: handleConnectionState,
          onUpdate: handleCallUpdate,
        });
        callIdRef.current = call.callId;
        pcRef.current = call.pc;
        cleanupsRef.current.push(call.cleanup);
        if (cancelled) return;
        setStatus('ringing');

        ringTimerRef.current = setTimeout(() => finish('missed', { notify: true }), RING_TIMEOUT_MS);
        cleanupsRef.current.push(() => clearTimeout(ringTimerRef.current));
      } catch (error) {
        if (!cancelled) fail(error);
      }
    })();

    return () => {
      cancelled = true;
    };
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  // Incoming: watch for the caller hanging up before we answer.
  useEffect(() => {
    if (mode !== 'incoming' || !isCallingSupported()) return;
    const unsubscribe = watchCall(callIdRef.current, (call) => {
      if (call.status !== 'ringing' && call.status !== 'accepted') finish(call.status);
    });
    cleanupsRef.current.push(unsubscribe);
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  // Call duration timer.
  useEffect(() => {
    if (status !== 'connected') return;
    const interval = setInterval(() => setSeconds((s) => s + 1), 1000);
    return () => clearInterval(interval);
  }, [status]);

  // Leaving the screen (back button, etc.) ends an active call.
  useEffect(
    () => () => {
      if (!finishedRef.current && callIdRef.current) {
        setCallStatus(callIdRef.current, mode === 'incoming' && !pcRef.current ? 'declined' : 'ended').catch(
          console.warn
        );
      }
      teardown();
    },
    [] // eslint-disable-line react-hooks/exhaustive-deps
  );

  const accept = async () => {
    setStatus('connecting');
    try {
      const stream = await openMedia();
      const call = await answerCall({
        callId: callIdRef.current,
        localStream: stream,
        onRemoteStream: setRemoteStream,
        onConnectionState: handleConnectionState,
        onUpdate: handleCallUpdate,
      });
      pcRef.current = call.pc;
      cleanupsRef.current.push(call.cleanup);
    } catch (error) {
      fail(error);
    }
  };

  const decline = () => finish('declined', { notify: true, delay: 0 });
  const hangUp = () => finish('ended', { notify: true, delay: 600 });

  const toggleMute = () => {
    localStreamRef.current?.getAudioTracks().forEach((t) => (t.enabled = isMuted));
    setIsMuted(!isMuted);
  };

  const toggleCamera = () => {
    localStreamRef.current?.getVideoTracks().forEach((t) => (t.enabled = isCameraOff));
    setIsCameraOff(!isCameraOff);
  };

  const showRemoteVideo = video && remoteStream && status === 'connected';
  const statusText =
    status === 'connected' ? formatDuration(seconds) : errorMessage || STATUS_TEXT[status];

  return (
    <View style={styles.container}>
      {/* Remote video fills the screen; for audio calls it's an invisible element that plays sound. */}
      {remoteStream && (
        <VideoView
          stream={remoteStream}
          style={showRemoteVideo ? webStyles.remoteVideo : webStyles.hiddenMedia}
        />
      )}

      {video && localStream && !isFinal && (
        <VideoView stream={localStream} muted mirror style={webStyles.localVideo} />
      )}

      <View style={styles.userInfo}>
        {!showRemoteVideo && (
          <View style={styles.avatar}>
            <Text style={styles.avatarText}>{userName?.[0]?.toUpperCase()}</Text>
          </View>
        )}
        <Text style={styles.userName}>{userName}</Text>
        <Text style={styles.callType}>{video ? 'Video call' : 'Voice call'}</Text>
        <Text style={styles.secureLabel}>🔒 Call setup encrypted and signed with NetPipe</Text>
        <Text style={styles.callStatus} testID="call-status">
          {statusText}
        </Text>
      </View>

      <View style={styles.controls}>
        {status === 'incoming' ? (
          <View style={styles.controlsRow}>
            <View style={styles.labeledButton}>
              <TouchableOpacity style={[styles.roundButton, styles.declineButton]} onPress={decline}>
                <Ionicons name="close" size={34} color="#fff" />
              </TouchableOpacity>
              <Text style={styles.buttonLabel}>Decline</Text>
            </View>
            <View style={styles.labeledButton}>
              <TouchableOpacity style={[styles.roundButton, styles.acceptButton]} onPress={accept}>
                <Ionicons name={video ? 'videocam' : 'call'} size={30} color="#fff" />
              </TouchableOpacity>
              <Text style={styles.buttonLabel}>Accept</Text>
            </View>
          </View>
        ) : isFinal ? (
          <TouchableOpacity style={styles.closeButton} onPress={close}>
            <Text style={styles.closeText}>Close</Text>
          </TouchableOpacity>
        ) : (
          <>
            <View style={styles.controlsRow}>
              <View style={styles.labeledButton}>
                <TouchableOpacity
                  style={[styles.controlButton, isMuted && styles.controlButtonActive]}
                  onPress={toggleMute}
                >
                  <Ionicons name={isMuted ? 'mic-off' : 'mic'} size={30} color="#fff" />
                </TouchableOpacity>
                <Text style={styles.buttonLabel}>{isMuted ? 'Unmute' : 'Mute'}</Text>
              </View>
              {video && (
                <View style={styles.labeledButton}>
                  <TouchableOpacity
                    style={[styles.controlButton, isCameraOff && styles.controlButtonActive]}
                    onPress={toggleCamera}
                  >
                    <Ionicons name={isCameraOff ? 'videocam-off' : 'videocam'} size={30} color="#fff" />
                  </TouchableOpacity>
                  <Text style={styles.buttonLabel}>{isCameraOff ? 'Camera on' : 'Camera off'}</Text>
                </View>
              )}
            </View>
            <View style={styles.labeledButton}>
              <TouchableOpacity style={[styles.roundButton, styles.declineButton]} onPress={hangUp}>
                <Ionicons name="call" size={30} color="#fff" style={styles.hangUpIcon} />
              </TouchableOpacity>
              <Text style={styles.buttonLabel}>End</Text>
            </View>
          </>
        )}
      </View>
    </View>
  );
}

// Plain objects for the DOM <video> elements (web only).
const webStyles = {
  remoteVideo: { position: 'absolute', top: 0, left: 0, width: '100%', height: '100%' },
  localVideo: {
    position: 'absolute',
    top: 20,
    right: 20,
    width: 110,
    height: 150,
    borderRadius: 12,
    zIndex: 2,
    border: '2px solid rgba(255,255,255,0.6)',
  },
  hiddenMedia: { position: 'absolute', width: 0, height: 0, opacity: 0 },
};

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: '#1a1a1a',
    justifyContent: 'space-between',
    paddingVertical: 60,
    overflow: 'hidden',
  },
  userInfo: {
    alignItems: 'center',
    marginTop: 60,
    zIndex: 1,
  },
  avatar: {
    width: 120,
    height: 120,
    borderRadius: 60,
    backgroundColor: '#007AFF',
    justifyContent: 'center',
    alignItems: 'center',
    marginBottom: 20,
  },
  avatarText: {
    color: '#fff',
    fontSize: 48,
    fontWeight: 'bold',
  },
  userName: {
    fontSize: 28,
    fontWeight: '600',
    color: '#fff',
    marginBottom: 6,
    textShadowColor: 'rgba(0,0,0,0.6)',
    textShadowRadius: 4,
  },
  callType: {
    fontSize: 14,
    color: '#bbb',
    marginBottom: 6,
  },
  secureLabel: {
    fontSize: 12,
    color: '#7fd18b',
    marginBottom: 6,
  },
  callStatus: {
    fontSize: 16,
    color: '#ddd',
    textAlign: 'center',
    paddingHorizontal: 30,
  },
  controls: {
    alignItems: 'center',
    zIndex: 1,
  },
  controlsRow: {
    flexDirection: 'row',
    justifyContent: 'center',
    marginBottom: 30,
  },
  labeledButton: {
    alignItems: 'center',
    marginHorizontal: 22,
  },
  buttonLabel: {
    color: '#ddd',
    fontSize: 13,
    marginTop: 8,
  },
  controlButton: {
    width: 60,
    height: 60,
    borderRadius: 30,
    backgroundColor: 'rgba(255,255,255,0.18)',
    justifyContent: 'center',
    alignItems: 'center',
  },
  controlButtonActive: {
    backgroundColor: '#fff',
    opacity: 0.6,
  },
  roundButton: {
    width: 70,
    height: 70,
    borderRadius: 35,
    justifyContent: 'center',
    alignItems: 'center',
  },
  acceptButton: {
    backgroundColor: '#34c759',
  },
  declineButton: {
    backgroundColor: '#ff3b30',
  },
  hangUpIcon: {
    transform: [{ rotate: '135deg' }],
  },
  closeButton: {
    paddingHorizontal: 40,
    paddingVertical: 14,
    borderRadius: 25,
    backgroundColor: '#333',
  },
  closeText: {
    color: '#fff',
    fontSize: 16,
    fontWeight: '600',
  },
});
