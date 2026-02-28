/**
 * OPRF client-side operations (RFC 9497 §3).
 *
 * The top-level exports below default to the P-256/SHA-256 suite for backward
 * compatibility.  Pass an explicit CipherSuite to use P-384 or P-521.
 */
import { fromHex } from '../crypto/primitives.js';
import { type CipherSuite, P256_SHA256 } from './suite.js';

// Re-export CipherSuite so callers can import it from here if convenient.
export type { CipherSuite };

/**
 * Generate a random OPRF blind scalar using the P-256 suite (backward compat).
 * For other suites call suite.randomScalar() directly.
 */
export function randomScalar(): bigint {
  return P256_SHA256.randomScalar();
}

/**
 * Client blinding step (RFC 9497 §3.3.2).
 *
 * @param input   The OPRF input (e.g. password bytes).
 * @param blind   Optional fixed blind scalar (for testing; random if omitted).
 * @param suite   Cipher suite (defaults to P-256/SHA-256).
 */
export function blind(
  input: Uint8Array,
  blind?: bigint,
  suite: CipherSuite = P256_SHA256,
): { blind: bigint; blindedElement: Uint8Array } {
  return suite.blind(input, blind);
}

/**
 * Client finalization step (RFC 9497 §3.3.2).
 *
 * @param input             The original OPRF input.
 * @param blindScalar       The blind scalar used during blinding.
 * @param evaluatedElement  The compressed evaluated element from the server.
 * @param suite             Cipher suite (defaults to P-256/SHA-256).
 * @returns                 The Nh-byte OPRF output.
 */
export function finalize(
  input: Uint8Array,
  blindScalar: bigint,
  evaluatedElement: Uint8Array,
  suite: CipherSuite = P256_SHA256,
): Uint8Array {
  return suite.finalize(input, blindScalar, evaluatedElement);
}

/**
 * hashToScalar: reduce an expand_message_xmd output mod the curve order.
 *
 * @param suite Cipher suite (defaults to P-256/SHA-256).
 */
export function hashToScalar(
  input: Uint8Array,
  dst: Uint8Array,
  suite: CipherSuite = P256_SHA256,
): bigint {
  return suite.hashToScalar(input, dst);
}

/**
 * DeriveKeyPair (RFC 9497 §3.3.1).
 * Returns the private scalar for the given seed and info.
 *
 * @param suite Cipher suite (defaults to P-256/SHA-256).
 */
export function deriveKeyPair(
  seed: Uint8Array,
  info: Uint8Array,
  dst?: Uint8Array,
  suite: CipherSuite = P256_SHA256,
): bigint {
  return suite.deriveKeyPair(seed, info, dst);
}

/**
 * Convert bigint to 32-byte big-endian (P-256 scalar bytes).
 * @deprecated Use suite.bigintToBytes() for non-P-256 suites.
 */
export function bigintToBytes32(n: bigint): Uint8Array {
  const hex = n.toString(16).padStart(64, '0');
  return fromHex(hex);
}
