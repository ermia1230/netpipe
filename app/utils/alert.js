import { Alert, Platform } from 'react-native';

/**
 * Cross-platform alert. React Native's Alert.alert is a no-op on web,
 * so fall back to the browser's window.alert there.
 */
export function showAlert(title, message, buttons) {
  if (Platform.OS !== 'web') {
    Alert.alert(title, message, buttons);
    return;
  }

  window.alert(message ? `${title}\n\n${message}` : title);

  // window.alert has a single OK button: run the first non-cancel button's handler.
  const button = buttons?.find((b) => b.style !== 'cancel') ?? buttons?.[0];
  button?.onPress?.();
}
