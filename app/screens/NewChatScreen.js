import React, { useState } from 'react';
import {
  View,
  Text,
  TextInput,
  TouchableOpacity,
  StyleSheet,
} from 'react-native';
import { showAlert } from '../utils/alert';
import { collection, query, where, getDocs } from 'firebase/firestore';
import { createOrGetChat } from '../utils/chatUtils';
import { db, auth } from '../config/firebaseInit';
import { Ionicons } from '@expo/vector-icons';

// Firestore retries forever when the database is unreachable; fail visibly instead.
const withTimeout = (promise, ms = 15000) =>
  Promise.race([
    promise,
    new Promise((_, reject) =>
      setTimeout(
        () => reject(new Error('Could not reach the database. Make sure Firestore is enabled in the Firebase console.')),
        ms
      )
    ),
  ]);

export default function NewChatScreen({ navigation }) {
  const [email, setEmail] = useState('');
  const [loading, setLoading] = useState(false);

  const startChat = async () => {
    const otherEmail = email.trim().toLowerCase();
    if (!otherEmail) {
      showAlert('Error', 'Please enter an email address');
      return;
    }

    const currentUser = auth.currentUser;
    if (otherEmail === currentUser.email.toLowerCase()) {
      showAlert('Error', "You can't chat with yourself!");
      return;
    }

    setLoading(true);

    try {
      // Look the other person up in the users directory to get their user ID.
      const usersQuery = query(collection(db, 'users'), where('email', '==', otherEmail));
      const userSnapshot = await withTimeout(getDocs(usersQuery));

      if (userSnapshot.empty) {
        showAlert('User not found', `No account uses ${otherEmail}. They need to sign up first.`);
        setLoading(false);
        return;
      }

      const otherUserId = userSnapshot.docs[0].id;
      const chatId = await withTimeout(
        createOrGetChat(currentUser.uid, otherUserId, currentUser.email.toLowerCase(), otherEmail)
      );

      navigation.navigate('Chat', { chatId, userName: otherEmail });
    } catch (error) {
      showAlert('Error', error.message);
    }

    setLoading(false);
  };

  return (
    <View style={styles.container}>
      <View style={styles.header}>
        <TouchableOpacity onPress={() => navigation.goBack()}>
          <Ionicons name="close" size={28} color="#007AFF" />
        </TouchableOpacity>
        <Text style={styles.headerTitle}>New Chat</Text>
        <View style={{ width: 28 }} />
      </View>

      <View style={styles.content}>
        <Text style={styles.label}>Enter email to start a chat</Text>
        <TextInput
          style={styles.input}
          placeholder="user@example.com"
          value={email}
          onChangeText={setEmail}
          autoCapitalize="none"
          keyboardType="email-address"
          autoFocus
        />
        
        <TouchableOpacity
          style={[styles.button, loading && styles.buttonDisabled]}
          onPress={startChat}
          disabled={loading}
        >
          <Text style={styles.buttonText}>
            {loading ? 'Starting Chat...' : 'Start Chat'}
          </Text>
        </TouchableOpacity>

        <View style={styles.note}>
          <Ionicons name="information-circle-outline" size={20} color="#666" />
          <Text style={styles.noteText}>
            Note: This is a simplified version. In a full app, you'd search for users by email or username.
          </Text>
        </View>
      </View>
    </View>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: '#fff',
  },
  header: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    paddingHorizontal: 20,
    paddingTop: 60,
    paddingBottom: 20,
    borderBottomWidth: 1,
    borderBottomColor: '#f0f0f0',
  },
  headerTitle: {
    fontSize: 18,
    fontWeight: '600',
  },
  content: {
    padding: 20,
  },
  label: {
    fontSize: 16,
    fontWeight: '500',
    marginBottom: 10,
    color: '#333',
  },
  input: {
    backgroundColor: '#f5f5f5',
    padding: 15,
    borderRadius: 10,
    fontSize: 16,
    marginBottom: 20,
  },
  button: {
    backgroundColor: '#007AFF',
    padding: 15,
    borderRadius: 10,
    alignItems: 'center',
  },
  buttonDisabled: {
    opacity: 0.6,
  },
  buttonText: {
    color: '#fff',
    fontSize: 16,
    fontWeight: '600',
  },
  note: {
    flexDirection: 'row',
    marginTop: 30,
    padding: 15,
    backgroundColor: '#f9f9f9',
    borderRadius: 10,
  },
  noteText: {
    flex: 1,
    marginLeft: 10,
    fontSize: 14,
    color: '#666',
    lineHeight: 20,
  },
});
