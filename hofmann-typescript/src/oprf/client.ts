/**
 * OPRF client-side operations (RFC 9497 §3).
 * P-256/SHA-256 suite only.
 */
import { p256, hashToCurve } from '@noble/curves/p256';
import { sha256 } from '@noble/hashes/sha256';
import { expand_message_xmd } from '@noble/curves/abstract/hash-to-curve';
import { concat, i2osp, fromHex } from '../crypto/primitives.js';
import { strToBytes } from '../crypto/encoding.js';
import {
  HASH_TO_GROUP_DST,
  DERIVE_KEY_PAIR_DST,
} from './suite.js';

const ORDER = p256.CURVE.n;

/**
 * Generate a random OPRF blind scalar.
 */
export function randomScalar(): bigint {
  return p256.utils.normPrivateKeyToScalar(p256.utils.randomPrivateKey());
}

/**
 * Client blinding step (RFC 9497 §3.3.2).
 *
 * @param input   The OPRF input (e.g., password bytes).
 * @param blind   Optional fixed blind scalar (for testing; random if omitted).
 * @returns       The blind scalar and the 33-byte compressed blinded element.
 */
export function blind(
  input: Uint8Array,
  blind?: bigint
): { blind: bigint; blindedElement: Uint8Array } {
  const r = blind ?? randomScalar();
  // hashToGroup: map input to a P-256 point using RFC 9380 hash-to-curve
  const H2Cpoint = hashToCurve(input, { DST: HASH_TO_GROUP_DST });
  // Cast to ProjectivePoint — H2CPoint is structurally compatible at runtime
  const P = p256.ProjectivePoint.fromAffine(H2Cpoint.toAffine());
  // blindedElement = r * P
  const blindedPoint = P.multiply(r);
  return {
    blind: r,
    blindedElement: blindedPoint.toRawBytes(true), // 33-byte compressed SEC1
  };
}

/**
 * Client finalization step (RFC 9497 §3.3.2).
 *
 * @param input             The original OPRF input.
 * @param blindScalar       The blind scalar used during blinding.
 * @param evaluatedElement  The 33-byte compressed evaluated element from the server.
 * @returns                 The 32-byte OPRF output.
 */
export function finalize(
  input: Uint8Array,
  blindScalar: bigint,
  evaluatedElement: Uint8Array
): Uint8Array {
  // Unblind: multiply evaluated element by inverse of blind scalar
  const Z = p256.ProjectivePoint.fromHex(evaluatedElement);
  const inverseBlind = modInverse(blindScalar, ORDER);
  const N = Z.multiply(inverseBlind);
  const unblinded = N.toRawBytes(true); // 33 bytes compressed — critical

  // hashInput = I2OSP(len(input), 2) || input || I2OSP(33, 2) || unblinded || "Finalize"
  const hashInput = concat(
    i2osp(input.length, 2),
    input,
    i2osp(33, 2),
    unblinded,
    strToBytes('Finalize')
  );
  return sha256(hashInput);
}

/**
 * hashToScalar: reduce an expand_message_xmd output (48 bytes) mod the curve order.
 * Used internally for deriveKeyPair.
 */
export function hashToScalar(input: Uint8Array, dst: Uint8Array): bigint {
  // expand to 48 bytes (L = ceil((log2(p) + k) / 8) for P-256, k=128 → 48)
  const uniform = expand_message_xmd(input, dst, 48, sha256);
  return os2ip(uniform) % ORDER;
}

/**
 * DeriveKeyPair (RFC 9497 §3.3.1).
 * Returns the private scalar for the given seed and info.
 */
export function deriveKeyPair(
  seed: Uint8Array,
  info: Uint8Array,
  dst?: Uint8Array
): bigint {
  const deriveDst = dst ?? DERIVE_KEY_PAIR_DST;
  // deriveInput = seed || I2OSP(len(info), 2) || info
  const deriveInput = concat(seed, i2osp(info.length, 2), info);
  let counter = 0;
  while (counter <= 255) {
    const candidate = concat(deriveInput, i2osp(counter, 1));
    const sk = hashToScalar(candidate, deriveDst);
    if (sk !== 0n) return sk;
    counter++;
  }
  throw new Error('deriveKeyPair: could not find valid scalar after 256 iterations');
}

// ── Helpers ────────────────────────────────────────────────────────────────

/** Modular inverse via Fermat's little theorem (p is prime). */
function modInverse(a: bigint, p: bigint): bigint {
  return modPow(a, p - 2n, p);
}

function modPow(base: bigint, exp: bigint, mod: bigint): bigint {
  let result = 1n;
  base = ((base % mod) + mod) % mod;
  while (exp > 0n) {
    if (exp & 1n) result = (result * base) % mod;
    exp >>= 1n;
    base = (base * base) % mod;
  }
  return result;
}

/** OS2IP: big-endian bytes to bigint. */
function os2ip(bytes: Uint8Array): bigint {
  let result = 0n;
  for (const b of bytes) {
    result = (result << 8n) | BigInt(b);
  }
  return result;
}

/** Convert bigint to 32-byte big-endian (for use as a private key). */
export function bigintToBytes32(n: bigint): Uint8Array {
  const hex = n.toString(16).padStart(64, '0');
  return fromHex(hex);
}
