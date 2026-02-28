/**
 * HKDF wrappers over @noble/hashes (RFC 5869).
 */
import { extract, expand } from '@noble/hashes/hkdf';
import { sha256 } from '@noble/hashes/sha256';
import { concat, i2osp } from './primitives.js';
import { strToBytes } from './encoding.js';

/**
 * HKDF-Extract (RFC 5869 §2.2).
 * @param salt  Optional salt. If empty/undefined, the RFC specifies a zero-filled key of hash length.
 * @param ikm   Input keying material.
 */
export function hkdfExtract(salt: Uint8Array | undefined, ikm: Uint8Array): Uint8Array {
  // noble extract accepts undefined salt → uses HashLen zeros (RFC-correct)
  return extract(sha256, ikm, salt && salt.length > 0 ? salt : undefined);
}

/**
 * HKDF-Expand (RFC 5869 §2.3).
 */
export function hkdfExpand(prk: Uint8Array, info: Uint8Array, length: number): Uint8Array {
  return expand(sha256, prk, info, length);
}

/**
 * HKDF-Expand-Label as used in OPAQUE-3DH (RFC 9807).
 *
 * info = I2OSP(length, 2)
 *      || I2OSP(len("OPAQUE-" + label), 1) || "OPAQUE-" + label
 *      || I2OSP(len(context), 1) || context
 */
export function hkdfExpandLabel(
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
  return hkdfExpand(secret, info, length);
}
