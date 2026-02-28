/**
 * Base64 and string encoding utilities.
 * Uses btoa/atob and TextEncoder/TextDecoder for browser compatibility.
 */

/**
 * Encode a Uint8Array to a standard base64 string.
 */
export function base64Encode(bytes: Uint8Array): string {
  let binary = '';
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

/**
 * Decode a standard base64 string to a Uint8Array.
 */
export function base64Decode(str: string): Uint8Array {
  const binary = atob(str);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

/**
 * Encode a UTF-8 string to bytes.
 */
export function strToBytes(s: string): Uint8Array {
  return new TextEncoder().encode(s);
}

/**
 * Decode bytes to a UTF-8 string.
 */
export function bytesToStr(b: Uint8Array): string {
  return new TextDecoder().decode(b);
}
