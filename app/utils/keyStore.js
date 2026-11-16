/**
 * Local storage for NetPipe secrets (the user's RSA private key and the AES
 * session keys this device created). These never leave the device.
 *
 * Phones: expo-secure-store (Keychain / Keystore). Web: localStorage.
 */
import { Platform } from 'react-native';
import * as SecureStore from 'expo-secure-store';

const safeKey = (key) => key.replace(/[^\w.-]/g, '_');

export async function getSecret(key) {
  if (Platform.OS === 'web') {
    try {
      return window.localStorage.getItem(safeKey(key));
    } catch {
      return null;
    }
  }
  return SecureStore.getItemAsync(safeKey(key));
}

export async function setSecret(key, value) {
  if (Platform.OS === 'web') {
    window.localStorage.setItem(safeKey(key), value);
    return;
  }
  await SecureStore.setItemAsync(safeKey(key), value);
}
