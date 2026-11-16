/**
 * Secure randomness for the NetPipe port.
 *
 * node-forge falls back to weak (time/Math.random based) seeding when the
 * runtime has no `crypto.getRandomValues` — which is the case in React Native.
 * Every random byte NetPipe uses (session keys, IVs, RSA padding, key
 * generation) is routed through one source here, and if no secure source is
 * available we fail closed instead of generating weak keys.
 */
import forge from 'node-forge';

let source =
  typeof globalThis.crypto?.getRandomValues === 'function'
    ? (array) => globalThis.crypto.getRandomValues(array)
    : null;

/** Random bytes as a forge binary string. */
export function randomBytes(count) {
  if (!source) {
    throw new Error('No secure random number generator is available on this device.');
  }
  const out = new Uint8Array(count);
  // getRandomValues is limited to 65536 bytes per call.
  for (let i = 0; i < count; i += 65536) {
    source(out.subarray(i, Math.min(count, i + 65536)));
  }
  let binary = '';
  for (let i = 0; i < out.length; i += 8192) {
    binary += String.fromCharCode.apply(null, out.subarray(i, i + 8192));
  }
  return binary;
}

/** Make forge (RSA padding, blinding, prime search) draw from the secure source. */
function installForgeRandom() {
  forge.random.getBytesSync = (count) => randomBytes(count);
  forge.random.getBytes = (count, callback) => {
    if (!callback) return randomBytes(count);
    let bytes;
    try {
      bytes = randomBytes(count);
    } catch (error) {
      callback(error);
      return undefined;
    }
    callback(null, bytes);
    return undefined;
  };
}

/** Use a different secure source, e.g. expo-crypto's getRandomValues on native. */
export function setRandomSource(getRandomValues) {
  source = getRandomValues;
  installForgeRandom();
}

export const hasSecureRandom = () => source !== null;

installForgeRandom();
