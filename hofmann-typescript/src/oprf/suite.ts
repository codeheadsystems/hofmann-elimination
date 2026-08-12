/**
 * OPRF cipher suite definitions for P-256/SHA-256, P-384/SHA-384, and P-521/SHA-512
 * (RFC 9497 §4.1).
 *
 * Each suite encapsulates all curve-specific constants and operations so that the
 * rest of the library can be written generically against the CipherSuite interface.
 */
import { p256, p256_hasher, p384, p384_hasher, p521, p521_hasher } from '@noble/curves/nist.js';
import { ristretto255, ristretto255_hasher } from '@noble/curves/ed25519.js';
import { numberToBytesLE, bytesToNumberLE, bytesToNumberBE } from '@noble/curves/utils.js';
import { invert } from '@noble/curves/abstract/modular.js';
import { sha256, sha384, sha512 } from '@noble/hashes/sha2.js';
import { hmac as nobleHmac } from '@noble/hashes/hmac.js';
import { extract, expand } from '@noble/hashes/hkdf.js';
import { expand_message_xmd } from '@noble/curves/abstract/hash-to-curve.js';

const p256HashToCurve = p256_hasher.hashToCurve;
const p384HashToCurve = p384_hasher.hashToCurve;
const p521HashToCurve = p521_hasher.hashToCurve;
import { concat, i2osp, fromHex } from '../crypto/primitives.js';
import { strToBytes } from '../crypto/encoding.js';

// ── Protocol mode ────────────────────────────────────────────────────────────

/**
 * RFC 9497 §3.1 protocol mode.
 *
 * The mode byte goes into the contextString, and therefore into every
 * domain-separation tag derived from it. A suite built for the wrong mode does
 * not fail — it computes a different function, and the mistake surfaces as an
 * interop failure or an unverifiable stored hash. `assertMode` exists so it
 * fails instead.
 *
 * One key must not serve two modes, for the same reason: the same secret under
 * two tag sets is two different functions, and RFC 9497 §7.2.3's static
 * Diffie-Hellman budget is per-key.
 */
export const OprfMode = {
  /** Base mode (0x00) — no proof. What OPAQUE and the plain OPRF use. */
  OPRF: 0x00,
  /** Verifiable OPRF (0x01) — the server proves it used its committed key. */
  VOPRF: 0x01,
  /** Partially-oblivious OPRF (0x02) — VOPRF plus a public input. */
  POPRF: 0x02,
} as const;

/** One of the RFC 9497 protocol modes. */
export type OprfMode = typeof OprfMode[keyof typeof OprfMode];

/** Human-readable mode name, for error messages. */
function modeName(mode: OprfMode): string {
  switch (mode) {
    case OprfMode.OPRF: return 'OPRF';
    case OprfMode.VOPRF: return 'VOPRF';
    case OprfMode.POPRF: return 'POPRF';
    default: return `unknown(0x${(mode as number).toString(16)})`;
  }
}

/**
 * Throws unless the suite is configured for one of the given modes.
 *
 * Called from the constructor of every mode-specific client. Without it,
 * handing a base-mode suite to a VOPRF client is silent.
 */
export function assertMode(suite: CipherSuite, ...allowed: OprfMode[]): void {
  if (!allowed.includes(suite.mode)) {
    throw new Error(
      `Cipher suite is configured for ${modeName(suite.mode)} but this operation requires one of ` +
      `[${allowed.map(modeName).join(', ')}]; the mode byte changes every domain-separation tag, ` +
      `so the mismatch would silently compute a different function`,
    );
  }
}

// ── CipherSuite interface ────────────────────────────────────────────────────

/**
 * All cipher suite operations and constants for a specific RFC 9497 suite.
 * Implementations are available as P256_SHA256, P384_SHA384, and P521_SHA512.
 */
export interface CipherSuite {
  /** Suite name string, e.g. "P256-SHA256". Also the curve-name segment of the contextString. */
  readonly name: string;

  /** The RFC 9497 protocol mode this suite is built for. */
  readonly mode: OprfMode;

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

  // ── Verifiable-mode primitives (VOPRF / POPRF) ─────────────────────────────
  // These exist for the DLEQ proof layer and the POPRF tweaked key. They are on
  // the interface rather than inside the suite closure because both need group
  // and scalar arithmetic that the base-mode operations never exposed.

  /** The group order. Scalar arithmetic is plain bigint mod this. */
  readonly ORDER: bigint;
  /** Serialized group element size in bytes. Same value as Npk, named for what it is. */
  readonly Ne: number;
  /** Serialized scalar size in bytes. Same value as Nsk. */
  readonly Ns: number;

  /** The group generator, serialized. */
  generator(): Uint8Array;

  /**
   * Serialize a scalar in this suite's canonical encoding — big-endian for the
   * NIST curves, little-endian for ristretto255. Getting this wrong produces a
   * proof that verifies against itself and against nothing else, which is the
   * exact trap `ristretto255.md` documents.
   */
  serializeScalar(s: bigint): Uint8Array;

  /**
   * The inverse of `serializeScalar`, rejecting a non-canonical encoding.
   *
   * The range check is what makes a proof non-malleable: without it `c` and
   * `c + ORDER` are distinct byte strings that both verify. It passes every
   * positive test vector either way, so it needs its own negative test.
   */
  deserializeScalar(b: Uint8Array): bigint;

  /**
   * Throws unless the bytes are a valid, canonical, non-identity element.
   *
   * Identity handling is asymmetric across the curves this library supports:
   * the NIST identity has no compressed SEC1 encoding and noble rejects it at
   * `fromBytes`, while the ristretto255 identity encodes as 32 zero bytes and
   * decodes happily. Both are rejected here so the guarantee is uniform.
   */
  validateElement(e: Uint8Array): void;

  /** Multiply a serialized element by a scalar, rejecting an identity result. */
  scalarMultiplyElement(e: Uint8Array, s: bigint): Uint8Array;

  /**
   * Multi-scalar multiplication: sum of `scalars[i] * elements[i]`.
   *
   * One operation rather than a composition of multiply-then-add, because the
   * composed form hands `add` an identity encoding when a scalar is zero and
   * reports it as a malformed element rather than as the identity result
   * RFC 9497 §3.3.3 asks the client to detect.
   */
  linearCombination(scalars: bigint[], elements: Uint8Array[]): Uint8Array;

  /**
   * RFC 9497 §3.3.3 POPRF Finalize — as `finalize`, but with the public input in
   * the transcript.
   *
   * Deliberately a separate method rather than an optional `info` parameter on
   * `finalize`. POPRF emits `I2OSP(len(info), 2)` even when `info` is empty,
   * where the base and verifiable modes omit it entirely, so an API where absent
   * and empty differ would be one cleanup away from a silent output change — and
   * `finalize` is what every stored OPAQUE credential depends on.
   */
  finalizeWithInfo(
    input: Uint8Array,
    info: Uint8Array,
    blindScalar: bigint,
    evaluatedElement: Uint8Array,
  ): Uint8Array;
}

// ── Internal helpers ─────────────────────────────────────────────────────────

function buildContextString(curveName: string, mode: OprfMode): Uint8Array {
  // RFC 9497 §3.1: "OPRFV1-" || I2OSP(mode, 1) || "-" || identifier
  return concat(
    strToBytes('OPRFV1-'),
    new Uint8Array([mode]),
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

/**
 * The RFC 9497 §3.3.3 POPRF Finalize transcript.
 *
 * The `I2OSP(len(info), 2)` is emitted even when `info` is empty, where the base
 * and verifiable modes omit the field entirely. A port that reuses the base-mode
 * transcript with an empty info silently computes base mode, and every
 * self-consistent round trip still passes.
 */
function poprfFinalizeTranscript(
  input: Uint8Array,
  info: Uint8Array,
  ne: number,
  unblinded: Uint8Array,
): Uint8Array {
  return concat(
    i2osp(input.length, 2),
    input,
    i2osp(info.length, 2),
    info,
    i2osp(ne, 2),
    unblinded,
    strToBytes('Finalize'),
  );
}

function os2ip(bytes: Uint8Array): bigint {
  let r = 0n;
  for (const b of bytes) r = (r << 8n) | BigInt(b);
  return r;
}

/**
 * True if every byte is zero.
 *
 * The ristretto255 identity (neutral) element is the all-zero 32-byte encoding,
 * and any group element multiplied down to the identity also serializes to all
 * zeros. We use this to reject the identity element on server-supplied points,
 * mirroring the checks in the Rust/Java implementations.
 */
function isAllZero(bytes: Uint8Array): boolean {
  for (const b of bytes) {
    if (b !== 0) return false;
  }
  return true;
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
  mode: OprfMode = OprfMode.OPRF,
): CipherSuite {
  const contextString = buildContextString(name, mode);
  const { HASH_TO_GROUP_DST, HASH_TO_SCALAR_DST, DERIVE_KEY_PAIR_DST } = buildDsts(contextString);
  const ORDER: bigint = curve.Point.Fn.ORDER;

  function bigintToBytes(n: bigint): Uint8Array {
    const hex = n.toString(16).padStart(nsk * 2, '0');
    return fromHex(hex);
  }

  function hashToScalar(input: Uint8Array, dst: Uint8Array): bigint {
    const uniform = expand_message_xmd(input, dst, l, hashFn);
    return os2ip(uniform) % ORDER;
  }

  function hkdfExpand(prk: Uint8Array, info: Uint8Array, length: number): Uint8Array {
    return expand(hashFn, prk, info, length);
  }

  function validateElement(e: Uint8Array): void {
    // Exactly Ne bytes with a 0x02/0x03 prefix. RFC 9497 §2.1 requires
    // DeserializeElement to be the inverse of SerializeElement; accepting the
    // uncompressed (0x04) and hybrid encodings would let a re-encoding bypass
    // anything keyed on the encoded element rather than the point it denotes,
    // and here specifically it would produce a proof transcript over different
    // bytes than the peer hashed.
    if (e.length !== npk || (e[0] !== 0x02 && e[0] !== 0x03)) {
      throw new Error(
        `validateElement: expected ${npk} bytes with a 0x02/0x03 prefix (RFC 9497 §2.1)`);
    }
    if (isAllZero(e)) {
      throw new Error('validateElement: identity element rejected (RFC 9497 §2.1)');
    }
    curve.Point.fromBytes(e); // throws on off-curve or non-canonical
  }

  const suite: CipherSuite = {
    name,
    mode,
    Nh: nh, Npk: npk, Nsk: nsk, Nn: 32, Nm: nh, L: l,
    ORDER,
    Ne: npk,
    Ns: nsk,
    CONTEXT_STRING: contextString,
    HASH_TO_GROUP_DST,
    HASH_TO_SCALAR_DST,
    DERIVE_KEY_PAIR_DST,

    randomScalar(): bigint {
      return bytesToNumberBE(curve.utils.randomSecretKey()) % ORDER || 1n;
    },

    generator(): Uint8Array {
      return curve.Point.BASE.toBytes(true);
    },

    serializeScalar: bigintToBytes,

    deserializeScalar(b: Uint8Array): bigint {
      if (b.length !== nsk) {
        throw new Error(`deserializeScalar: expected ${nsk} bytes, got ${b.length}`);
      }
      const n = bytesToNumberBE(b);
      // Without this, c and c + ORDER are distinct byte strings that both
      // verify, so a proof is malleable. Every positive vector passes either way.
      if (n >= ORDER) {
        throw new Error('deserializeScalar: scalar is not canonical (>= group order)');
      }
      return n;
    },

    validateElement,

    scalarMultiplyElement(e: Uint8Array, s: bigint): Uint8Array {
      validateElement(e);
      const result = curve.Point.fromBytes(e).multiplyUnsafe(s % ORDER);
      if (result.is0()) {
        throw new Error('scalarMultiplyElement: identity result rejected (RFC 9497 §2.1)');
      }
      return result.toBytes(true);
    },

    linearCombination(scalars: bigint[], elements: Uint8Array[]): Uint8Array {
      if (scalars.length !== elements.length || scalars.length === 0) {
        throw new Error('linearCombination: scalars and elements must be the same non-zero length');
      }
      let acc = curve.Point.ZERO;
      for (let i = 0; i < scalars.length; i++) {
        validateElement(elements[i]);
        acc = acc.add(curve.Point.fromBytes(elements[i]).multiplyUnsafe(scalars[i] % ORDER));
      }
      if (acc.is0()) {
        throw new Error('linearCombination: identity result rejected (RFC 9497 §2.1)');
      }
      return acc.toBytes(true);
    },

    finalizeWithInfo(
      input: Uint8Array,
      info: Uint8Array,
      blindScalar: bigint,
      evaluatedElement: Uint8Array,
    ): Uint8Array {
      if (isAllZero(evaluatedElement)) {
        throw new Error('finalizeWithInfo: identity evaluated element rejected (RFC 9497 §2.1)');
      }
      const unblinded = curve.Point.fromBytes(evaluatedElement)
        .multiply(invert(blindScalar, ORDER)).toBytes(true);
      return hashFn(poprfFinalizeTranscript(input, info, npk, unblinded));
    },

    blind(input: Uint8Array, r?: bigint): { blind: bigint; blindedElement: Uint8Array } {
      const scalar = r ?? suite.randomScalar();
      const h2c = hashToCurveFn(input, { DST: HASH_TO_GROUP_DST });
      // fromAffine: H2CPoint is structurally compatible with AffinePoint at runtime
      const P = curve.Point.fromAffine(h2c.toAffine());
      const blindedPoint = P.multiply(scalar);
      return { blind: scalar, blindedElement: blindedPoint.toBytes(true) };
    },

    finalize(input: Uint8Array, blindScalar: bigint, evaluatedElement: Uint8Array): Uint8Array {
      // RFC 9497 §2.1: DeserializeElement MUST reject the identity element.
      // For NIST suites noble already rejects it at fromBytes (the identity has
      // no valid compressed SEC1 encoding), but we reject the all-zero encoding
      // explicitly so the guarantee is uniform and cannot regress.
      if (isAllZero(evaluatedElement)) {
        throw new Error('finalize: identity evaluated element rejected (RFC 9497 §2.1)');
      }
      const Z = curve.Point.fromBytes(evaluatedElement);
      const N = Z.multiply(invert(blindScalar, ORDER));
      const unblinded = N.toBytes(true); // Npk bytes compressed
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
      // RFC 9807 §6.3: reject the identity element as a peer DH contribution.
      // NIST suites reject it at fromBytes; the explicit checks make the
      // guarantee uniform and also cover a result that collapses to identity.
      if (isAllZero(pointBytes)) {
        throw new Error('dhMultiply: identity element rejected (RFC 9807 §6.3)');
      }
      const result = curve.Point.fromBytes(pointBytes).multiply(scalar).toBytes(true);
      if (isAllZero(result)) {
        throw new Error('dhMultiply: identity DH result rejected (RFC 9807 §6.3)');
      }
      return result;
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

// ── Ristretto255 suite factory ────────────────────────────────────────────────

function createRistrettoSuite(mode: OprfMode = OprfMode.OPRF): CipherSuite {
  const name = 'ristretto255-SHA512';
  const nh = 64, npk = 32, nsk = 32, l = 64;
  const hashFn = sha512;
  const contextString = buildContextString(name, mode);
  const { HASH_TO_GROUP_DST, HASH_TO_SCALAR_DST, DERIVE_KEY_PAIR_DST } = buildDsts(contextString);
  const ORDER: bigint = ristretto255.Point.Fn.ORDER;

  function bigintToBytes(n: bigint): Uint8Array {
    return numberToBytesLE(n, nsk);
  }

  function hashToScalar(input: Uint8Array, dst: Uint8Array): bigint {
    return ristretto255_hasher.hashToScalar(input, { DST: dst });
  }

  function hkdfExpandFn(prk: Uint8Array, info: Uint8Array, length: number): Uint8Array {
    return expand(hashFn, prk, info, length);
  }

  function validateElement(e: Uint8Array): void {
    // noble's ristretto255 ACCEPTS the all-zero (identity) encoding, unlike the
    // NIST curves where the identity has no compressed encoding at all. That
    // asymmetry is why this check is explicit rather than left to fromBytes.
    if (e.length !== npk) {
      throw new Error(`validateElement: expected ${npk} bytes (RFC 9497 §2.1)`);
    }
    if (isAllZero(e)) {
      throw new Error('validateElement: identity element rejected (RFC 9497 §2.1)');
    }
    ristretto255.Point.fromBytes(e); // throws on a non-canonical encoding
  }

  const suite: CipherSuite = {
    name,
    mode,
    Nh: nh, Npk: npk, Nsk: nsk, Nn: 32, Nm: nh, L: l,
    ORDER,
    Ne: npk,
    Ns: nsk,
    CONTEXT_STRING: contextString,
    HASH_TO_GROUP_DST,
    HASH_TO_SCALAR_DST,
    DERIVE_KEY_PAIR_DST,

    randomScalar(): bigint {
      const bytes = new Uint8Array(64);
      crypto.getRandomValues(bytes);
      return ristretto255.Point.Fn.create(bytesToNumberLE(bytes));
    },

    generator(): Uint8Array {
      return ristretto255.Point.BASE.toBytes();
    },

    serializeScalar: bigintToBytes,

    deserializeScalar(b: Uint8Array): bigint {
      if (b.length !== nsk) {
        throw new Error(`deserializeScalar: expected ${nsk} bytes, got ${b.length}`);
      }
      // Little-endian here and big-endian on the NIST curves. This is the exact
      // divergence ristretto255.md was written about, and the proof bytes are a
      // new code path over it.
      const n = bytesToNumberLE(b);
      if (n >= ORDER) {
        throw new Error('deserializeScalar: scalar is not canonical (>= group order)');
      }
      return n;
    },

    validateElement,

    scalarMultiplyElement(e: Uint8Array, s: bigint): Uint8Array {
      validateElement(e);
      const result = ristretto255.Point.fromBytes(e).multiplyUnsafe(s % ORDER).toBytes();
      if (isAllZero(result)) {
        throw new Error('scalarMultiplyElement: identity result rejected (RFC 9497 §2.1)');
      }
      return result;
    },

    linearCombination(scalars: bigint[], elements: Uint8Array[]): Uint8Array {
      if (scalars.length !== elements.length || scalars.length === 0) {
        throw new Error('linearCombination: scalars and elements must be the same non-zero length');
      }
      let acc = ristretto255.Point.ZERO;
      for (let i = 0; i < scalars.length; i++) {
        validateElement(elements[i]);
        acc = acc.add(ristretto255.Point.fromBytes(elements[i]).multiplyUnsafe(scalars[i] % ORDER));
      }
      const result = acc.toBytes();
      // The identity serializes to 32 zero bytes here rather than failing, so
      // the check is on the encoding.
      if (isAllZero(result)) {
        throw new Error('linearCombination: identity result rejected (RFC 9497 §2.1)');
      }
      return result;
    },

    finalizeWithInfo(
      input: Uint8Array,
      info: Uint8Array,
      blindScalar: bigint,
      evaluatedElement: Uint8Array,
    ): Uint8Array {
      if (isAllZero(evaluatedElement)) {
        throw new Error('finalizeWithInfo: identity evaluated element rejected (RFC 9497 §2.1)');
      }
      const unblinded = ristretto255.Point.fromBytes(evaluatedElement)
        .multiply(invert(blindScalar, ORDER)).toBytes();
      return hashFn(poprfFinalizeTranscript(input, info, npk, unblinded));
    },

    blind(input: Uint8Array, r?: bigint): { blind: bigint; blindedElement: Uint8Array } {
      const scalar = r ?? suite.randomScalar();
      // hashToCurve returns a RistrettoPoint at runtime (toBytes/multiply); H2CPoint typedef lacks these
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const P = ristretto255_hasher.hashToCurve(input, { DST: HASH_TO_GROUP_DST }) as any;
      const blindedPoint = P.multiply(scalar);
      return { blind: scalar, blindedElement: blindedPoint.toBytes() };
    },

    finalize(input: Uint8Array, blindScalar: bigint, evaluatedElement: Uint8Array): Uint8Array {
      // RFC 9497 §2.1: DeserializeElement MUST reject the identity element.
      // noble's ristretto255 ACCEPTS the all-zero (identity) encoding, so we
      // must reject it here — otherwise a malicious server returning identity
      // collapses the unblinded element to a fixed value and the OPRF output
      // degrades to an unsalted hash of the input, independent of the key.
      if (isAllZero(evaluatedElement)) {
        throw new Error('finalize: identity evaluated element rejected (RFC 9497 §2.1)');
      }
      const Z = ristretto255.Point.fromBytes(evaluatedElement);
      const N = Z.multiply(invert(blindScalar, ORDER));
      const unblinded = N.toBytes();
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
      return ristretto255.Point.BASE.multiply(sk).toBytes();
    },

    dhMultiply(pointBytes: Uint8Array, scalar: bigint): Uint8Array {
      // RFC 9807 §6.3: reject the identity element as a peer DH contribution.
      // noble's ristretto255 ACCEPTS the all-zero (identity) encoding and
      // multiplying it yields the all-zero result, stripping that peer's
      // contribution from the transcript — so reject it on input and output.
      if (isAllZero(pointBytes)) {
        throw new Error('dhMultiply: identity element rejected (RFC 9807 §6.3)');
      }
      const result = ristretto255.Point.fromBytes(pointBytes).multiply(scalar).toBytes();
      if (isAllZero(result)) {
        throw new Error('dhMultiply: identity DH result rejected (RFC 9807 §6.3)');
      }
      return result;
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

    hkdfExpand: hkdfExpandFn,

    hkdfExpandLabel(secret: Uint8Array, label: string, context: Uint8Array, length: number): Uint8Array {
      const labelBytes = strToBytes('OPAQUE-' + label);
      const info = concat(
        i2osp(length, 2),
        i2osp(labelBytes.length, 1),
        labelBytes,
        i2osp(context.length, 1),
        context,
      );
      return hkdfExpandFn(secret, info, length);
    },
  };

  return suite;
}

/**
 * ristretto255 / SHA-512 cipher suite (RFC 9497 §4.1).
 * contextString = "OPRFV1-\x00-ristretto255-SHA512"
 * L=64, Nh=64, Npk=32, Nsk=32
 */
export const RISTRETTO255_SHA512: CipherSuite = createRistrettoSuite();

// ── Mode-aware suite resolution ──────────────────────────────────────────────

/**
 * Cache of built suites, keyed by `name|mode`.
 *
 * Seeded with the four exported base-mode constants so `getCipherSuite` keeps
 * returning those exact objects. OPAQUE imports `P256_SHA256` directly and the
 * cross-client harness consumes the built `dist`, so a second, equal-but-distinct
 * base-mode instance would be a silent behavioural change looking for somewhere
 * to happen.
 */
const SUITE_CACHE = new Map<string, CipherSuite>();

function suiteKey(name: string, mode: OprfMode): string {
  return `${name}|${mode}`;
}

function buildSuite(name: string, mode: OprfMode): CipherSuite {
  switch (name) {
    case 'P256_SHA256':
      return createSuite('P256-SHA256', 32, 33, 32, 48, p256, p256HashToCurve, sha256, mode);
    case 'P384_SHA384':
      return createSuite('P384-SHA384', 48, 49, 48, 72, p384, p384HashToCurve, sha384, mode);
    case 'P521_SHA512':
      return createSuite('P521-SHA512', 64, 67, 66, 98, p521, p521HashToCurve, sha512, mode);
    case 'RISTRETTO255_SHA512':
      return createRistrettoSuite(mode);
    default:
      throw new Error(`Unknown cipher suite: "${name}". Expected P256_SHA256, P384_SHA384, P521_SHA512, or RISTRETTO255_SHA512.`);
  }
}

/**
 * Resolve a cipher suite by config name and RFC 9497 mode.
 *
 * A VOPRF or POPRF client needs a suite built for its mode; the base-mode suite
 * a client already holds computes a different function under a different set of
 * domain-separation tags.
 */
export function getCipherSuiteForMode(name: string, mode: OprfMode): CipherSuite {
  const key = suiteKey(name, mode);
  const cached = SUITE_CACHE.get(key);
  if (cached) return cached;
  const built = buildSuite(name, mode);
  SUITE_CACHE.set(key, built);
  return built;
}

/**
 * Resolve a base-mode cipher suite by the name returned in server config responses.
 * Accepts "P256_SHA256", "P384_SHA384", "P521_SHA512", or "RISTRETTO255_SHA512".
 */
export function getCipherSuite(name: string): CipherSuite {
  return getCipherSuiteForMode(name, OprfMode.OPRF);
}

SUITE_CACHE.set(suiteKey('P256_SHA256', OprfMode.OPRF), P256_SHA256);
SUITE_CACHE.set(suiteKey('P384_SHA384', OprfMode.OPRF), P384_SHA384);
SUITE_CACHE.set(suiteKey('P521_SHA512', OprfMode.OPRF), P521_SHA512);
SUITE_CACHE.set(suiteKey('RISTRETTO255_SHA512', OprfMode.OPRF), RISTRETTO255_SHA512);

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
