/**
 * Pure utility functions — no external dependencies.
 * All must work in browser (no Node.js Buffer or crypto).
 */

/**
 * I2OSP: Integer-to-Octet-String Primitive (RFC 8017 §4.1).
 * Serializes a non-negative integer as a big-endian byte array of the given length.
 */
export function i2osp(value: number | bigint, length: number): Uint8Array {
  const result = new Uint8Array(length);
  let v = BigInt(value);
  for (let i = length - 1; i >= 0; i--) {
    result[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  if (v !== 0n) {
    throw new Error(`i2osp: value ${value} overflows ${length} bytes`);
  }
  return result;
}

/**
 * Concatenate multiple Uint8Arrays into one.
 */
export function concat(...arrays: Uint8Array[]): Uint8Array {
  const totalLength = arrays.reduce((sum, a) => sum + a.length, 0);
  const result = new Uint8Array(totalLength);
  let offset = 0;
  for (const a of arrays) {
    result.set(a, offset);
    offset += a.length;
  }
  return result;
}

/**
 * XOR two byte arrays of equal length.
 */
export function xor(a: Uint8Array, b: Uint8Array): Uint8Array {
  if (a.length !== b.length) {
    throw new Error(`xor: length mismatch (${a.length} vs ${b.length})`);
  }
  const result = new Uint8Array(a.length);
  for (let i = 0; i < a.length; i++) {
    result[i] = a[i] ^ b[i];
  }
  return result;
}

/**
 * Constant-time equality check. Accumulates XOR differences so no early exit.
 */
export function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a[i] ^ b[i];
  }
  return diff === 0;
}

/**
 * Decode a hex string to a Uint8Array.
 */
export function fromHex(hex: string): Uint8Array {
  if (hex.length % 2 !== 0) {
    throw new Error(`fromHex: odd-length hex string`);
  }
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

/**
 * Encode a Uint8Array to a lowercase hex string.
 */
export function toHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}
