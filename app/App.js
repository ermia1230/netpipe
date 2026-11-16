import React, { useState, useEffect } from 'react';
import { NavigationContainer, createNavigationContainerRef } from '@react-navigation/native';
import { createStackNavigator } from '@react-navigation/stack';
import { onAuthStateChanged } from 'firebase/auth';
import { collection, doc, onSnapshot, query, setDoc, where } from 'firebase/firestore';
import { auth, db } from './config/firebaseInit';
import { startSecureSessions } from './utils/secureSession';

// Screens
import LoginScreen from './screens/LoginScreen';
import ChatsListScreen from './screens/ChatsListScreen';
import ChatScreen from './screens/ChatScreen';
import CallScreen from './screens/CallScreen';
import NewChatScreen from './screens/NewChatScreen';

const Stack = createStackNavigator();
const navigationRef = createNavigationContainerRef();

// Ignore ringing calls older than this (e.g. left over after a crash).
const STALE_CALL_MS = 45000;

export default function App() {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const unsubscribe = onAuthStateChanged(auth, (currentUser) => {
      if (currentUser) {
        // Keep a users/{uid} entry so others can find this user by email.
        setDoc(
          doc(db, 'users', currentUser.uid),
          { uid: currentUser.uid, email: currentUser.email.toLowerCase() },
          { merge: true }
        ).catch((error) => console.error('Failed to save user profile:', error));
      }
      setUser(currentUser);
      setLoading(false);
    });

    return unsubscribe;
  }, []);

  // NetPipe: create/publish this user's keys and answer handshakes for all their chats.
  useEffect(() => {
    if (!user) return;
    return startSecureSessions(user);
  }, [user]);

  // Open the call screen whenever someone starts calling the signed-in user.
  useEffect(() => {
    if (!user) return;
    const incomingCalls = query(
      collection(db, 'calls'),
      where('calleeId', '==', user.uid),
      where('status', '==', 'ringing')
    );
    return onSnapshot(
      incomingCalls,
      (snapshot) => {
        snapshot.docChanges().forEach((change) => {
          if (change.type !== 'added') return;
          const call = change.doc.data();
          if (Date.now() - (call.createdAtMs ?? 0) > STALE_CALL_MS) return;
          if (!navigationRef.isReady()) return;
          navigationRef.navigate('Call', {
            mode: 'incoming',
            callId: change.doc.id,
            userName: call.callerEmail,
            video: !!call.video,
          });
        });
      },
      (error) => console.error('Incoming call listener failed:', error)
    );
  }, [user]);

  if (loading) {
    return null; // You can add a loading screen here
  }

  return (
    <NavigationContainer ref={navigationRef}>
      <Stack.Navigator screenOptions={{ headerShown: false }}>
        {!user ? (
          <Stack.Screen name="Login" component={LoginScreen} />
        ) : (
          <>
            <Stack.Screen name="ChatsList" component={ChatsListScreen} />
            <Stack.Screen name="NewChat" component={NewChatScreen} />
            <Stack.Screen name="Chat" component={ChatScreen} />
            <Stack.Screen name="Call" component={CallScreen} />
          </>
        )}
      </Stack.Navigator>
    </NavigationContainer>
  );
}
