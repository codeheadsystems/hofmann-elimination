/**
 * HKDF wrappers over @noble/hashes (RFC 5869).
 *
 * The hash function is an explicit parameter: OPAQUE/OPRF use SHA-256 for the
 * P-256 suite but SHA-384/SHA-512 for P-384/P-521/ristretto255, and using the
 * wrong hash silently produces incompatible, truncated key material. Prefer the
 * suite-aware `CipherSuite.hkdf*` methods; these standalone helpers exist for
 * callers that need HKDF directly and must pass the matching hash.
 */
import { extract, expand } from '@noble/hashes/hkdf.js';
import { concat, i2osp } from './primitives.js';
import { strToBytes } from './encoding.js';

// Structural type for a @noble/hashes hash constructor (sha256/sha384/sha512).
// eslint-disable-next-line @typescript-eslint/no-explicit-any
export type HashFn = any;

/**
 * HKDF-Extract (RFC 5869 §2.2).
 * @param hash  Hash function matching the cipher suite (e.g. sha256 for P-256).
 * @param salt  Optional salt. If empty/undefined, the RFC specifies a zero-filled key of hash length.
 * @param ikm   Input keying material.
 */
export function hkdfExtract(hash: HashFn, salt: Uint8Array | undefined, ikm: Uint8Array): Uint8Array {
  // noble extract accepts undefined salt → uses HashLen zeros (RFC-correct)
  return extract(hash, ikm, salt && salt.length > 0 ? salt : undefined);
}

/**
 * HKDF-Expand (RFC 5869 §2.3).
 * @param hash  Hash function matching the cipher suite.
 */
export function hkdfExpand(hash: HashFn, prk: Uint8Array, info: Uint8Array, length: number): Uint8Array {
  return expand(hash, prk, info, length);
}

/**
 * HKDF-Expand-Label as used in OPAQUE-3DH (RFC 9807).
 *
 * info = I2OSP(length, 2)
 *      || I2OSP(len("OPAQUE-" + label), 1) || "OPAQUE-" + label
 *      || I2OSP(len(context), 1) || context
 *
 * @param hash  Hash function matching the cipher suite.
 */
export function hkdfExpandLabel(
  hash: HashFn,
  secret: Uint8Array,
  label: string,
  context: Uint8Array,
  length: number
): Uint8Array {
  const labelBytes = strToBytes('OPAQUE-' + label);
  const info = concat(
    i2osp(length, 2),
    i2osp(labelBytes.length, 1),
    labelBytes,
    i2osp(context.length, 1),
    context
  );
  return hkdfExpand(hash, secret, info, length);
}
