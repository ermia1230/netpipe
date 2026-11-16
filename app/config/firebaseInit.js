import { Platform } from 'react-native';
import Constants from 'expo-constants';
import { initializeApp } from 'firebase/app';
import { getAuth, connectAuthEmulator } from 'firebase/auth';
import { getFirestore, connectFirestoreEmulator } from 'firebase/firestore';
import { firebaseConfig } from './firebase';

// Set by `npm run start:local` to use the Firebase emulators on this computer
// instead of the real Firebase project.
export const USE_EMULATOR = process.env.EXPO_PUBLIC_USE_FIREBASE_EMULATOR === 'true';

// "demo-" project IDs are special: the emulators never contact real Firebase for them.
const EMULATOR_PROJECT_ID = 'demo-chat-call-app';

const app = initializeApp(
  USE_EMULATOR ? { ...firebaseConfig, projectId: EMULATOR_PROJECT_ID } : firebaseConfig
);

export const auth = getAuth(app);
export const db = getFirestore(app);

if (USE_EMULATOR) {
  // Web: the page's own host. Phone/simulator: the computer running Metro.
  const host =
    Platform.OS === 'web'
      ? window.location.hostname
      : Constants.expoConfig?.hostUri?.split(':')[0] ?? 'localhost';

  connectAuthEmulator(auth, `http://${host}:9099`, { disableWarnings: true });
  connectFirestoreEmulator(db, host, 8080);
  console.log(`[firebase] Using local emulators at ${host}`);
}

export default app;
