/**
 * OPRF cipher suite definitions for P-256/SHA-256, P-384/SHA-384, and P-521/SHA-512
 * (RFC 9497 §4.1).
 *
 * Each suite encapsulates all curve-specific constants and operations so that the
 * rest of the library can be written generically against the CipherSuite interface.
 */
import { p256, hashToCurve as p256HashToCurve } from '@noble/curves/p256';
import { p384, hashToCurve as p384HashToCurve } from '@noble/curves/p384';
import { p521, hashToCurve as p521HashToCurve } from '@noble/curves/p521';
import { sha256 } from '@noble/hashes/sha256';
import { sha384, sha512 } from '@noble/hashes/sha512';
import { hmac as nobleHmac } from '@noble/hashes/hmac';
import { extract, expand } from '@noble/hashes/hkdf';
import { expand_message_xmd } from '@noble/curves/abstract/hash-to-curve';
import { concat, i2osp, fromHex } from '../crypto/primitives.js';
import { strToBytes } from '../crypto/encoding.js';

// ── CipherSuite interface ────────────────────────────────────────────────────

/**
 * All cipher suite operations and constants for a specific RFC 9497 suite.
 * Implementations are available as P256_SHA256, P384_SHA384, and P521_SHA512.
 */
export interface CipherSuite {
  /** Suite name string, e.g. "P256-SHA256". Also the curve-name segment of the contextString. */
  readonly name: string;

  // Size constants (RFC 9807 Table 2)
  /** Hash output length in bytes (32 / 48 / 64). */
  readonly Nh: number;
  /** Compressed public key size in bytes (33 / 49 / 67). */
  readonly Npk: number;
  /** Scalar (private key) size in bytes (32 / 48 / 66). */
  readonly Nsk: number;
  /** Nonce size in bytes — always 32 across all suites. */
  readonly Nn: number;
  /** MAC size in bytes — equals Nh. */
  readonly Nm: number;
  /** expand_message_xmd output length used for hashToScalar. */
  readonly L: number;

  // DST constants
  readonly CONTEXT_STRING: Uint8Array;
  readonly HASH_TO_GROUP_DST: Uint8Array;
  readonly HASH_TO_SCALAR_DST: Uint8Array;
  readonly DERIVE_KEY_PAIR_DST: Uint8Array;

  // OPRF operations
  /** Generate a random scalar in [1, order). */
  randomScalar(): bigint;
  /** Blind an OPRF input (RFC 9497 §3.3.2). Optional fixed scalar for testing. */
  blind(input: Uint8Array, scalar?: bigint): { blind: bigint; blindedElement: Uint8Array };
  /** Finalize the OPRF (RFC 9497 §3.3.2) — returns Nh-byte output. */
  finalize(input: Uint8Array, blindScalar: bigint, evaluatedElement: Uint8Array): Uint8Array;
  /** Reduce expand_message_xmd output mod the group order. */
  hashToScalar(input: Uint8Array, dst: Uint8Array): bigint;
  /** Derive a key pair scalar from seed and info (RFC 9497 §3.3.1). */
  deriveKeyPair(seed: Uint8Array, info: Uint8Array, dst?: Uint8Array): bigint;

  // EC helpers
  /** Derive compressed public key from private scalar (Npk bytes). */
  getPublicKey(sk: bigint): Uint8Array;
  /** Multiply a compressed point by a scalar; return compressed result. */
  dhMultiply(pointBytes: Uint8Array, scalar: bigint): Uint8Array;
  /** Encode a scalar as Nsk big-endian bytes. */
  bigintToBytes(n: bigint): Uint8Array;

  // Hash / MAC
  hash(data: Uint8Array): Uint8Array;
  hmac(key: Uint8Array, data: Uint8Array): Uint8Array;

  // HKDF
  hkdfExtract(salt: Uint8Array | undefined, ikm: Uint8Array): Uint8Array;
  hkdfExpand(prk: Uint8Array, info: Uint8Array, length: number): Uint8Array;
  /** HKDF-Expand-Label as used by OPAQUE-3DH (RFC 9807). */
  hkdfExpandLabel(secret: Uint8Array, label: string, context: Uint8Array, length: number): Uint8Array;
}

// ── Internal helpers ─────────────────────────────────────────────────────────

function buildContextString(curveName: string): Uint8Array {
  return concat(
    strToBytes('OPRFV1-'),
    new Uint8Array([0x00]),    // mode = 0 (OPRF)
    strToBytes(`-${curveName}`)
  );
}

function buildDsts(cs: Uint8Array) {
  return {
    HASH_TO_GROUP_DST:   concat(strToBytes('HashToGroup-'),  cs),
    HASH_TO_SCALAR_DST:  concat(strToBytes('HashToScalar-'), cs),
    DERIVE_KEY_PAIR_DST: concat(strToBytes('DeriveKeyPair'), cs),
  };
}

function os2ip(bytes: Uint8Array): bigint {
  let r = 0n;
  for (const b of bytes) r = (r << 8n) | BigInt(b);
  return r;
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

// Structural type for noble/curves Weierstrass curve instances.
// eslint-disable-next-line @typescript-eslint/no-explicit-any
type AnyCurve = any;
// eslint-disable-next-line @typescript-eslint/no-explicit-any
type AnyHashToCurveFn = (msg: Uint8Array, opts: { DST: Uint8Array }) => any;
// Noble hash function type (sha256, sha384, sha512 all satisfy this).
// eslint-disable-next-line @typescript-eslint/no-explicit-any
type HashFn = any;

// ── Suite factory ────────────────────────────────────────────────────────────

function createSuite(
  name: string,
  nh: number,
  npk: number,
  nsk: number,
  l: number,
  curve: AnyCurve,
  hashToCurveFn: AnyHashToCurveFn,
  hashFn: HashFn,
): CipherSuite {
  const contextString = buildContextString(name);
  const { HASH_TO_GROUP_DST, HASH_TO_SCALAR_DST, DERIVE_KEY_PAIR_DST } = buildDsts(contextString);
  const ORDER: bigint = curve.CURVE.n;

  function bigintToBytes(n: bigint): Uint8Array {
    const hex = n.toString(16).padStart(nsk * 2, '0');
    return fromHex(hex);
  }

  function modInverse(a: bigint): bigint {
    return modPow(a, ORDER - 2n, ORDER);
  }

  function hashToScalar(input: Uint8Array, dst: Uint8Array): bigint {
    const uniform = expand_message_xmd(input, dst, l, hashFn);
    return os2ip(uniform) % ORDER;
  }

  function hkdfExpand(prk: Uint8Array, info: Uint8Array, length: number): Uint8Array {
    return expand(hashFn, prk, info, length);
  }

  const suite: CipherSuite = {
    name,
    Nh: nh, Npk: npk, Nsk: nsk, Nn: 32, Nm: nh, L: l,
    CONTEXT_STRING: contextString,
    HASH_TO_GROUP_DST,
    HASH_TO_SCALAR_DST,
    DERIVE_KEY_PAIR_DST,

    randomScalar(): bigint {
      return curve.utils.normPrivateKeyToScalar(curve.utils.randomPrivateKey());
    },

    blind(input: Uint8Array, r?: bigint): { blind: bigint; blindedElement: Uint8Array } {
      const scalar = r ?? suite.randomScalar();
      const h2c = hashToCurveFn(input, { DST: HASH_TO_GROUP_DST });
      // fromAffine: H2CPoint is structurally compatible with AffinePoint at runtime
      const P = curve.ProjectivePoint.fromAffine(h2c.toAffine());
      const blindedPoint = P.multiply(scalar);
      return { blind: scalar, blindedElement: blindedPoint.toRawBytes(true) };
    },

    finalize(input: Uint8Array, blindScalar: bigint, evaluatedElement: Uint8Array): Uint8Array {
      const Z = curve.ProjectivePoint.fromHex(evaluatedElement);
      const N = Z.multiply(modInverse(blindScalar));
      const unblinded = N.toRawBytes(true); // Npk bytes compressed
      const hashInput = concat(
        i2osp(input.length, 2),
        input,
        i2osp(npk, 2),
        unblinded,
        strToBytes('Finalize'),
      );
      return hashFn(hashInput);
    },

    hashToScalar,

    deriveKeyPair(seed: Uint8Array, info: Uint8Array, dst?: Uint8Array): bigint {
      const deriveDst = dst ?? DERIVE_KEY_PAIR_DST;
      const deriveInput = concat(seed, i2osp(info.length, 2), info);
      for (let counter = 0; counter <= 255; counter++) {
        const candidate = concat(deriveInput, i2osp(counter, 1));
        const sk = hashToScalar(candidate, deriveDst);
        if (sk !== 0n) return sk;
      }
      throw new Error('deriveKeyPair: no valid scalar after 256 iterations');
    },

    getPublicKey(sk: bigint): Uint8Array {
      return curve.getPublicKey(bigintToBytes(sk), true);
    },

    dhMultiply(pointBytes: Uint8Array, scalar: bigint): Uint8Array {
      return curve.ProjectivePoint.fromHex(pointBytes).multiply(scalar).toRawBytes(true);
    },

    bigintToBytes,

    hash(data: Uint8Array): Uint8Array {
      return hashFn(data);
    },

    hmac(key: Uint8Array, data: Uint8Array): Uint8Array {
      return nobleHmac(hashFn, key, data);
    },

    hkdfExtract(salt: Uint8Array | undefined, ikm: Uint8Array): Uint8Array {
      return extract(hashFn, ikm, salt && salt.length > 0 ? salt : undefined);
    },

    hkdfExpand,

    hkdfExpandLabel(secret: Uint8Array, label: string, context: Uint8Array, length: number): Uint8Array {
      const labelBytes = strToBytes('OPAQUE-' + label);
      const info = concat(
        i2osp(length, 2),
        i2osp(labelBytes.length, 1),
        labelBytes,
        i2osp(context.length, 1),
        context,
      );
      return hkdfExpand(secret, info, length);
    },
  };

  return suite;
}

// ── Public cipher suite constants ────────────────────────────────────────────

/**
 * P-256 / SHA-256 cipher suite (RFC 9497 §4.1).
 * contextString = "OPRFV1-\x00-P256-SHA256"
 * L=48, Nh=32, Npk=33, Nsk=32
 */
export const P256_SHA256: CipherSuite = createSuite(
  'P256-SHA256', 32, 33, 32, 48,
  p256, p256HashToCurve, sha256,
);

/**
 * P-384 / SHA-384 cipher suite (RFC 9497 §4.1).
 * contextString = "OPRFV1-\x00-P384-SHA384"
 * L=72, Nh=48, Npk=49, Nsk=48
 */
export const P384_SHA384: CipherSuite = createSuite(
  'P384-SHA384', 48, 49, 48, 72,
  p384, p384HashToCurve, sha384,
);

/**
 * P-521 / SHA-512 cipher suite (RFC 9497 §4.1).
 * contextString = "OPRFV1-\x00-P521-SHA512"
 * L=98, Nh=64, Npk=67, Nsk=66
 */
export const P521_SHA512: CipherSuite = createSuite(
  'P521-SHA512', 64, 67, 66, 98,
  p521, p521HashToCurve, sha512,
);

/**
 * Resolve a cipher suite by the name returned in server config responses.
 * Accepts "P256_SHA256", "P384_SHA384", or "P521_SHA512".
 */
export function getCipherSuite(name: string): CipherSuite {
  switch (name) {
    case 'P256_SHA256': return P256_SHA256;
    case 'P384_SHA384': return P384_SHA384;
    case 'P521_SHA512': return P521_SHA512;
    default: throw new Error(`Unknown cipher suite: "${name}". Expected P256_SHA256, P384_SHA384, or P521_SHA512.`);
  }
}

// ── Backward-compatible P-256 exports ────────────────────────────────────────
// These re-export the P-256 constants under their original names so existing
// code that imports them directly continues to compile without changes.

export const CONTEXT_STRING    = P256_SHA256.CONTEXT_STRING;
export const HASH_TO_GROUP_DST = P256_SHA256.HASH_TO_GROUP_DST;
export const HASH_TO_SCALAR_DST = P256_SHA256.HASH_TO_SCALAR_DST;
export const DERIVE_KEY_PAIR_DST = P256_SHA256.DERIVE_KEY_PAIR_DST;
export const Nh  = 32;
export const Npk = 33;
export const Nsk = 32;
export const Nn  = 32;
export const Nm  = 32;
