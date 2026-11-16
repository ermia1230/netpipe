import React, { useState, useEffect, useRef } from 'react';
import {
  View,
  Text,
  TextInput,
  TouchableOpacity,
  FlatList,
  StyleSheet,
  KeyboardAvoidingView,
  Platform,
} from 'react-native';
import {
  collection,
  addDoc,
  query,
  orderBy,
  onSnapshot,
  serverTimestamp,
  doc,
  setDoc,
} from 'firebase/firestore';
import { db, auth } from '../config/firebaseInit';
import { Ionicons } from '@expo/vector-icons';
import { showAlert } from '../utils/alert';
import {
  openRecord,
  retrySecureSession,
  sealText,
  watchSecureSession,
} from '../utils/secureSession';

// Stored in place of the text so the chat list never holds plaintext.
export const ENCRYPTED_PREVIEW = '🔒 Encrypted message';

export default function ChatScreen({ route, navigation }) {
  const { chatId, userName } = route.params;
  const [messages, setMessages] = useState([]);
  const [newMessage, setNewMessage] = useState('');
  const [secure, setSecure] = useState({ status: 'connecting', text: 'Connecting…' });
  const [decrypted, setDecrypted] = useState({}); // message id -> { text } | { error }
  const [sending, setSending] = useState(false);
  const flatListRef = useRef();
  const decryptingRef = useRef(new Set());

  // NetPipe handshake for this chat (starts one if needed).
  useEffect(() => watchSecureSession(chatId, setSecure), [chatId]);

  useEffect(() => {
    const messagesRef = collection(db, 'chats', chatId, 'messages');
    const q = query(messagesRef, orderBy('timestamp', 'asc'));

    const unsubscribe = onSnapshot(q, (snapshot) => {
      const messagesList = snapshot.docs.map((doc) => ({
        id: doc.id,
        ...doc.data(),
      }));
      setMessages(messagesList);
    });

    return () => unsubscribe();
  }, [chatId]);

  // Verify and decrypt NetPipe records. Retried when the session state changes,
  // e.g. a message arrives before this device has verified its session.
  useEffect(() => {
    messages.forEach((message) => {
      if (!message.netpipe || decrypted[message.id]?.text !== undefined) return;
      if (decryptingRef.current.has(message.id)) return;
      decryptingRef.current.add(message.id);
      openRecord(chatId, message.netpipe)
        .then((text) => ({ text }))
        .catch((error) => ({ error: error.message }))
        .then((result) => {
          decryptingRef.current.delete(message.id);
          setDecrypted((prev) => ({ ...prev, [message.id]: result }));
        });
    });
  }, [messages, chatId, secure.status]); // eslint-disable-line react-hooks/exhaustive-deps

  const isSecure = secure.status === 'established';

  const sendMessage = async () => {
    const text = newMessage.trim();
    if (!text || !isSecure || sending) return;

    const currentUser = auth.currentUser;
    const messagesRef = collection(db, 'chats', chatId, 'messages');
    setSending(true);

    try {
      // Encrypt + sign with the NetPipe session; only ciphertext reaches Firestore.
      const record = await sealText(chatId, text);
      const sent = await addDoc(messagesRef, {
        netpipe: record,
        senderId: currentUser.uid,
        senderEmail: currentUser.email,
        timestamp: serverTimestamp(),
      });
      setDecrypted((prev) => ({ ...prev, [sent.id]: { text } }));

      // Update chat metadata
      const chatRef = doc(db, 'chats', chatId);
      await setDoc(
        chatRef,
        {
          lastMessage: ENCRYPTED_PREVIEW,
          lastMessageTime: serverTimestamp(),
        },
        { merge: true }
      );

      setNewMessage('');
    } catch (error) {
      console.error('Error sending message:', error);
      showAlert('Message not sent', error.message);
    }
    setSending(false);
  };

  const showSecurityInfo = () => {
    if (!isSecure) {
      showAlert('Secure session', secure.text);
      return;
    }
    showAlert(
      'End-to-end encrypted',
      `Messages and calls with ${userName} use the NetPipe protocol: X.509 certificates, ` +
        `RSA key exchange, AES-128-CTR with separate key streams per direction, and RSA-signed records.\n\n` +
        `Safety code:\n${secure.safetyCode}\n\n` +
        `Compare this code with ${userName} (in person or on a call). If it matches, nobody is in between.`
    );
  };

  const renderMessage = ({ item }) => {
    const isMyMessage = item.senderId === auth.currentUser?.uid;
    const result = decrypted[item.id];
    let body = item.text; // messages sent before NetPipe was added
    let note = item.netpipe ? null : 'Not encrypted (sent before NetPipe)';
    if (item.netpipe) {
      if (result?.text !== undefined) body = result.text;
      else if (result?.error) {
        body = '🔒 Could not decrypt this message';
        note = result.error;
      } else body = '🔒 Decrypting…';
    }

    return (
      <View
        style={[
          styles.messageContainer,
          isMyMessage ? styles.myMessage : styles.theirMessage,
        ]}
      >
        <Text
          style={[
            styles.messageText,
            isMyMessage ? styles.myMessageText : styles.theirMessageText,
          ]}
        >
          {body}
        </Text>
        {note && <Text style={styles.note}>{note}</Text>}
        <Text style={styles.timestamp}>
          {item.timestamp?.toDate().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
        </Text>
      </View>
    );
  };

  return (
    <KeyboardAvoidingView
      behavior={Platform.OS === 'ios' ? 'padding' : undefined}
      style={styles.container}
      keyboardVerticalOffset={90}
    >
      <View style={styles.header}>
        <TouchableOpacity onPress={() => navigation.goBack()}>
          <Ionicons name="chevron-back" size={28} color="#007AFF" />
        </TouchableOpacity>
        <View style={styles.headerInfo}>
          <Text style={styles.headerTitle}>{userName}</Text>
          <TouchableOpacity onPress={showSecurityInfo} style={styles.secureRow} testID="secure-status">
            <Ionicons
              name={isSecure ? 'lock-closed' : secure.status === 'failed' ? 'warning-outline' : 'sync-outline'}
              size={12}
              color={isSecure ? '#34a853' : secure.status === 'failed' ? '#d93025' : '#666'}
            />
            <Text style={[styles.headerSubtitle, isSecure && styles.secureText]} numberOfLines={1}>
              {' '}
              {secure.text}
            </Text>
          </TouchableOpacity>
        </View>
        <TouchableOpacity
          accessibilityLabel="Video call"
          style={{ marginRight: 18 }}
          onPress={() => navigation.navigate('Call', { mode: 'outgoing', userName, chatId, video: true })}
        >
          <Ionicons name="videocam-outline" size={26} color="#007AFF" />
        </TouchableOpacity>
        <TouchableOpacity
          accessibilityLabel="Voice call"
          onPress={() => navigation.navigate('Call', { mode: 'outgoing', userName, chatId, video: false })}
        >
          <Ionicons name="call-outline" size={24} color="#007AFF" />
        </TouchableOpacity>
      </View>

      <FlatList
        ref={flatListRef}
        data={messages}
        renderItem={renderMessage}
        keyExtractor={(item) => item.id}
        contentContainerStyle={styles.messagesList}
        onContentSizeChange={() => flatListRef.current?.scrollToEnd()}
      />

      {!isSecure && (
        <View style={styles.banner}>
          <Text style={styles.bannerText}>
            {secure.status === 'failed'
              ? secure.text
              : `${secure.text} Messages can be sent once the NetPipe handshake with ${userName} is done.`}
          </Text>
          {secure.status === 'failed' && (
            <TouchableOpacity onPress={() => retrySecureSession(chatId)}>
              <Text style={styles.bannerAction}>Retry</Text>
            </TouchableOpacity>
          )}
        </View>
      )}

      <View style={styles.inputContainer}>
        <TextInput
          style={styles.input}
          placeholder={isSecure ? 'Encrypted message...' : 'Waiting for secure session...'}
          value={newMessage}
          onChangeText={setNewMessage}
          multiline
        />
        <TouchableOpacity
          style={[styles.sendButton, (!isSecure || sending) && styles.sendDisabled]}
          onPress={sendMessage}
          disabled={!isSecure || sending}
          accessibilityLabel="Send"
        >
          <Ionicons name="send" size={24} color="#007AFF" />
        </TouchableOpacity>
      </View>
    </KeyboardAvoidingView>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: '#fff',
  },
  header: {
    flexDirection: 'row',
    alignItems: 'center',
    paddingHorizontal: 15,
    paddingTop: 60,
    paddingBottom: 15,
    borderBottomWidth: 1,
    borderBottomColor: '#f0f0f0',
  },
  headerInfo: {
    flex: 1,
    marginLeft: 10,
  },
  headerTitle: {
    fontSize: 18,
    fontWeight: '600',
  },
  headerSubtitle: {
    fontSize: 12,
    color: '#666',
    marginTop: 2,
  },
  messagesList: {
    padding: 15,
  },
  messageContainer: {
    maxWidth: '75%',
    padding: 12,
    borderRadius: 18,
    marginBottom: 10,
  },
  myMessage: {
    alignSelf: 'flex-end',
    backgroundColor: '#007AFF',
  },
  theirMessage: {
    alignSelf: 'flex-start',
    backgroundColor: '#f0f0f0',
  },
  messageText: {
    fontSize: 16,
    marginBottom: 4,
  },
  myMessageText: {
    color: '#fff',
  },
  theirMessageText: {
    color: '#000',
  },
  timestamp: {
    fontSize: 10,
    color: '#999',
    alignSelf: 'flex-end',
  },
  inputContainer: {
    flexDirection: 'row',
    padding: 10,
    borderTopWidth: 1,
    borderTopColor: '#f0f0f0',
    alignItems: 'center',
  },
  input: {
    flex: 1,
    backgroundColor: '#f5f5f5',
    borderRadius: 20,
    paddingHorizontal: 15,
    paddingVertical: 10,
    marginRight: 10,
    maxHeight: 100,
  },
  sendButton: {
    padding: 10,
  },
  sendDisabled: {
    opacity: 0.3,
  },
  secureRow: {
    flexDirection: 'row',
    alignItems: 'center',
    marginTop: 2,
  },
  secureText: {
    color: '#34a853',
  },
  note: {
    fontSize: 10,
    fontStyle: 'italic',
    color: '#999',
    marginBottom: 2,
  },
  banner: {
    flexDirection: 'row',
    alignItems: 'center',
    backgroundColor: '#fff8e1',
    paddingHorizontal: 15,
    paddingVertical: 8,
  },
  bannerText: {
    flex: 1,
    fontSize: 12,
    color: '#6d5c00',
  },
  bannerAction: {
    marginLeft: 10,
    color: '#007AFF',
    fontWeight: '600',
  },
});
