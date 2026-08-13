/**
 * RFC 9497 §2.2 discrete-log-equality proofs, the layer VOPRF and POPRF share.
 *
 * A proof lets a client check that the server evaluated with the key it publicly
 * committed to. `verifyProof` is what a client needs; `generateProof` is here for
 * the tests and is deliberately not re-exported from the package entry point —
 * see its own comment.
 *
 * Every detail in this file is one a port can get wrong in a way that stays
 * self-consistent. A prover and verifier that agree on the wrong field order,
 * the wrong scalar order, or the wrong hash interoperate perfectly with each
 * other and fail only against the RFC's Appendix A vectors. That is why the
 * tests assert proof *bytes* and not just round trips.
 */
import { concat, i2osp } from '../crypto/primitives.js';
import { strToBytes } from '../crypto/encoding.js';
import { type CipherSuite, OprfMode, assertMode } from './suite.js';

/** A DLEQ proof: the challenge scalar and the response scalar. */
export interface DleqProof {
  readonly c: bigint;
  readonly s: bigint;
}

/**
 * Encoding-level ceiling on the batch size. The composite transcript writes the
 * index as `I2OSP(i, 2)`, so this is what the encoding can represent — not an
 * operational cap, which belongs at the transport layer where request size and
 * tail latency are the governing concerns.
 */
const MAX_BATCH = 65535;

// ── Serialization ────────────────────────────────────────────────────────────

/**
 * Serializes as `SerializeScalar(c) || SerializeScalar(s)`, exactly `2 * Ns` bytes.
 *
 * The order is `c` then `s`, per §2.2.1's `return [c, s]` and the `Proof` field
 * in the Appendix A vectors. Nothing in a round trip catches a reversal.
 */
export function serializeProof(suite: CipherSuite, proof: DleqProof): Uint8Array {
  return concat(suite.serializeScalar(proof.c), suite.serializeScalar(proof.s));
}

/**
 * Parses a proof from its wire encoding.
 *
 * Both scalars go through `deserializeScalar`, which rejects a non-canonical
 * encoding. That is what stops a proof being malleable: without it `c` and
 * `c + ORDER` are distinct byte strings that verify identically.
 */
export function deserializeProof(suite: CipherSuite, bytes: Uint8Array): DleqProof {
  const ns = suite.Ns;
  if (bytes.length !== 2 * ns) {
    throw new Error(`deserializeProof: expected ${2 * ns} bytes, got ${bytes.length}`);
  }
  return {
    c: suite.deserializeScalar(bytes.subarray(0, ns)),
    s: suite.deserializeScalar(bytes.subarray(ns, 2 * ns)),
  };
}

// ── Composites (§2.2.1 / §2.2.2) ─────────────────────────────────────────────

function validateBatch(c: Uint8Array[], d: Uint8Array[]): void {
  if (!c || !d) {
    throw new Error('Batch element lists are required');
  }
  if (c.length !== d.length) {
    throw new Error(`Batch element lists must be the same length: ${c.length} vs ${d.length}`);
  }
  if (c.length === 0) {
    throw new Error('Batch must contain at least one element pair');
  }
  if (c.length > MAX_BATCH) {
    throw new Error(`Batch of ${c.length} exceeds the maximum encodable size of ${MAX_BATCH}`);
  }
}

/**
 * Derives the `d_i` coefficient for each batch entry.
 *
 * Two details are easy to get subtly wrong here. First, `seedDST` is transcript
 * *data*, length-prefixed like any other field — it is not used as a
 * domain-separation tag. Second, `seed` is the suite's plain hash of that
 * transcript, not a hash-to-scalar; only `d_i` is a hash-to-scalar, and it uses
 * the ordinary suite DST rather than any proof-specific tag.
 */
function coefficients(
  suite: CipherSuite,
  b: Uint8Array,
  c: Uint8Array[],
  d: Uint8Array[],
): bigint[] {
  validateBatch(c, d);

  const seedDst = concat(strToBytes('Seed-'), suite.CONTEXT_STRING);
  const seed = suite.hash(concat(
    i2osp(b.length, 2), b,
    i2osp(seedDst.length, 2), seedDst,
  ));

  const out: bigint[] = [];
  for (let i = 0; i < c.length; i++) {
    const transcript = concat(
      i2osp(seed.length, 2), seed,
      i2osp(i, 2),
      i2osp(c[i].length, 2), c[i],
      i2osp(d[i].length, 2), d[i],
      strToBytes('Composite'),
    );
    out.push(suite.hashToScalar(transcript, suite.HASH_TO_SCALAR_DST));
  }
  return out;
}

interface Composites {
  m: Uint8Array;
  z: Uint8Array;
}

/** Verifier-side fold (§2.2.2): accumulate both composites, having no key to shortcut with. */
function computeComposites(
  suite: CipherSuite,
  b: Uint8Array,
  c: Uint8Array[],
  d: Uint8Array[],
): Composites {
  const coeffs = coefficients(suite, b, c, d);
  return {
    m: suite.linearCombination(coeffs, c),
    z: suite.linearCombination(coeffs, d),
  };
}

/** Prover-side fold (§2.2.1): `Z = k * M` straight from the key, which is the "fast" part. */
function computeCompositesFast(
  suite: CipherSuite,
  k: bigint,
  b: Uint8Array,
  c: Uint8Array[],
  d: Uint8Array[],
): Composites {
  const m = suite.linearCombination(coefficients(suite, b, c, d), c);
  return { m, z: suite.scalarMultiplyElement(m, k) };
}

// ── Challenge ────────────────────────────────────────────────────────────────

/**
 * The challenge transcript, shared by `generateProof` and `verifyProof` so the
 * two cannot drift.
 *
 * Note what is *not* in it: `A`, the generator. Binding comes instead from the
 * verifier recomputing `t2 = s*A + c*B` with its own `A`. A port that includes
 * the generator self-interoperates and fails every vector.
 */
function challenge(
  suite: CipherSuite,
  b: Uint8Array,
  composites: Composites,
  t2: Uint8Array,
  t3: Uint8Array,
): bigint {
  const transcript = concat(
    i2osp(b.length, 2), b,
    i2osp(composites.m.length, 2), composites.m,
    i2osp(composites.z.length, 2), composites.z,
    i2osp(t2.length, 2), t2,
    i2osp(t3.length, 2), t3,
    strToBytes('Challenge'),
  );
  return suite.hashToScalar(transcript, suite.HASH_TO_SCALAR_DST);
}

// ── Verify (§2.2.2) ──────────────────────────────────────────────────────────

/**
 * Verifies a proof over a batch.
 *
 * Returns a boolean rather than throwing, for *every* attacker-influenced
 * failure. A proof that fails because an element computed to the identity, or
 * because a supplied element was not a valid encoding, must be
 * indistinguishable to the caller from one that simply did not verify — an
 * error escaping here would let a remote party tell those cases apart, and
 * would push callers into rendering a bad proof as a server error rather than a
 * rejected response.
 *
 * A length-mismatched or empty batch does throw. That is a caller bug — most
 * likely a client that failed to check the server returned as many evaluated
 * elements as it sent — and swallowing it as "did not verify" would hide the
 * very defect the mismatch represents.
 */
export function verifyProof(
  suite: CipherSuite,
  b: Uint8Array,
  c: Uint8Array[],
  d: Uint8Array[],
  proof: DleqProof,
): boolean {
  assertMode(suite, OprfMode.VOPRF, OprfMode.POPRF);
  if (!proof) return false;
  validateBatch(c, d);
  try {
    const composites = computeComposites(suite, b, c, d);

    // Neither term may be computed separately: a remote party can set s = 0,
    // which makes s*G the identity, and the identity has no Ne-byte encoding to
    // hand to an add().
    const scalars = [proof.s, proof.c];
    const t2 = suite.linearCombination(scalars, [suite.generator(), b]);
    const t3 = suite.linearCombination(scalars, [composites.m, composites.z]);

    const expected = challenge(suite, b, composites, t2, t3);
    return constantTimeScalarEquals(suite, expected, proof.c);
  } catch {
    return false;
  }
}

/**
 * Compares two scalars as fixed-width encodings without an early exit.
 *
 * Stated honestly: no known attack needs this. The expected challenge is a
 * function *of* the submitted `c` — through `t2` and `t3` — so each trial yields
 * a fresh, unrelated expected value and a partial-match oracle gives no way to
 * extend a match incrementally. Defence in depth at zero cost, not a fix for a
 * demonstrated break.
 */
function constantTimeScalarEquals(suite: CipherSuite, a: bigint, b: bigint): boolean {
  const x = suite.serializeScalar(a);
  const y = suite.serializeScalar(b);
  if (x.length !== y.length) return false;
  let diff = 0;
  for (let i = 0; i < x.length; i++) diff |= x[i] ^ y[i];
  return diff === 0;
}

// ── Prove (§2.2.1) ───────────────────────────────────────────────────────────

/**
 * Generates a proof.
 *
 * **A client never calls this**, and it is not re-exported from `index.ts`. It
 * exists so the verifier can be tested against proofs this library did not
 * itself produce fixtures for — the Appendix A vectors alone would not catch a
 * verifier that returns true for inputs outside the vector set, and they cover
 * only batch sizes 1 and 2. Java keeps its equivalent package-private for the
 * same reason.
 *
 * `r` is the proof randomness. Supplying it is what lets a test reproduce the
 * vectors' fixed `ProofRandomScalar`, and is otherwise the one input whose reuse
 * or bias hands over the server's long-term key.
 */
export function generateProof(
  suite: CipherSuite,
  k: bigint,
  b: Uint8Array,
  c: Uint8Array[],
  d: Uint8Array[],
  r?: bigint,
): DleqProof {
  assertMode(suite, OprfMode.VOPRF, OprfMode.POPRF);
  const n = suite.ORDER;
  const rand = r ?? suite.randomScalar();
  if (rand <= 0n || rand >= n) {
    throw new Error('Proof randomness must be a scalar in [1, n-1]');
  }

  const composites = computeCompositesFast(suite, k, b, c, d);
  const t2 = suite.scalarMultiplyElement(suite.generator(), rand);
  const t3 = suite.scalarMultiplyElement(composites.m, rand);

  const ch = challenge(suite, b, composites, t2, t3);
  // The mod is not optional: r - c*k is negative for the common case c*k > r,
  // which serializeScalar rejects outright on the Weierstrass curves.
  const s = ((rand - ch * k) % n + n) % n;

  return { c: ch, s };
}
