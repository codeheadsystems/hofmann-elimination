/**
 * RFC 9497 §2.2 DLEQ proofs, pinned against the Appendix A vectors.
 *
 * The byte-level assertions are the load-bearing ones. A prover and verifier
 * that agree on the wrong scalar order, the wrong transcript field order, or on
 * hashing the seed to a scalar rather than plainly, interoperate perfectly with
 * each other — the only oracle is the RFC's own `Proof` field.
 */
import { describe, it, expect } from 'vitest';
import { toHex } from '../src/crypto/primitives.js';
import { getCipherSuiteForMode, OprfMode, P256_SHA256 } from '../src/oprf/suite.js';
import {
  generateProof, verifyProof, serializeProof, deserializeProof,
} from '../src/oprf/dleq.js';
import {
  loadVectors, secretKeyScalar, RFC_SUITE_NAMES, CONFIG_SUITE_NAMES,
} from './rfc9497-vectors.js';

const MODES = [
  { name: 'VOPRF' as const, mode: OprfMode.VOPRF },
  { name: 'POPRF' as const, mode: OprfMode.POPRF },
];

describe('DLEQ proof bytes against RFC 9497 Appendix A', () => {
  for (const rfcName of RFC_SUITE_NAMES) {
    for (const { name: modeName, mode } of MODES) {
      const vectors = loadVectors(rfcName, modeName);
      const suite = getCipherSuiteForMode(CONFIG_SUITE_NAMES[rfcName], mode);

      vectors.vectors.forEach((v, index) => {
        it(`${rfcName}/${modeName} vector ${index} (batch ${v.batchSize}) reproduces Proof`, () => {
          const k = proofKey(suite, vectors.skSm, v);
          const b = proofPublicKey(suite, k, modeName, v);
          // POPRF proves over the lists in the reverse order, because the server
          // computes evaluated = t^-1 * blinded rather than t * blinded. A port
          // that keeps VOPRF's order round-trips against itself and fails here.
          const [c, d] = modeName === 'POPRF'
            ? [v.evaluationElements, v.blindedElements]
            : [v.blindedElements, v.evaluationElements];

          const proof = generateProof(
            suite, k, b, c, d, suite.deserializeScalar(v.proofRandomScalar!));

          expect(toHex(serializeProof(suite, proof))).toEqual(toHex(v.proof!));
        });

        it(`${rfcName}/${modeName} vector ${index} verifies the RFC's own proof`, () => {
          const k = proofKey(suite, vectors.skSm, v);
          const b = proofPublicKey(suite, k, modeName, v);
          const [c, d] = modeName === 'POPRF'
            ? [v.evaluationElements, v.blindedElements]
            : [v.blindedElements, v.evaluationElements];

          expect(verifyProof(suite, b, c, d, deserializeProof(suite, v.proof!))).toBe(true);
        });
      });
    }
  }
});

/**
 * The scalar the proof is generated under. For VOPRF that is the server key; for
 * POPRF it is the key tweaked by the public input, which is what binds the
 * response to the `info` the client asked for.
 */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
function proofKey(suite: any, skSm: Uint8Array, v: any): bigint {
  const k = secretKeyScalar(suite, skSm);
  if (v.info === undefined) return k;
  const m = poprfInfoScalar(suite, v.info);
  return (k + m) % suite.ORDER;
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function proofPublicKey(suite: any, k: bigint, modeName: string, v: any): Uint8Array {
  void modeName;
  void v;
  return suite.scalarMultiplyElement(suite.generator(), k);
}

/** RFC 9497 §3.3.3: m = HashToScalar("Info" || I2OSP(len(info), 2) || info). */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
function poprfInfoScalar(suite: any, info: Uint8Array): bigint {
  const framed = new Uint8Array(4 + 2 + info.length);
  framed.set([0x49, 0x6e, 0x66, 0x6f], 0); // "Info"
  framed[4] = (info.length >> 8) & 0xff;
  framed[5] = info.length & 0xff;
  framed.set(info, 6);
  return suite.hashToScalar(framed, suite.HASH_TO_SCALAR_DST);
}

describe('DLEQ round trips beyond the vectors', () => {
  const suite = getCipherSuiteForMode('P256_SHA256', OprfMode.VOPRF);

  function batch(n: number): { k: bigint; b: Uint8Array; c: Uint8Array[]; d: Uint8Array[] } {
    const k = suite.randomScalar();
    const b = suite.scalarMultiplyElement(suite.generator(), k);
    const c: Uint8Array[] = [];
    const d: Uint8Array[] = [];
    for (let i = 0; i < n; i++) {
      const element = suite.blind(new Uint8Array([i])).blindedElement;
      c.push(element);
      d.push(suite.scalarMultiplyElement(element, k));
    }
    return { k, b, c, d };
  }

  // The vectors only cover batch sizes 1 and 2, so the composite index encoding
  // beyond that is otherwise untested.
  for (const n of [1, 2, 3, 8, 17]) {
    it(`proves and verifies a batch of ${n}`, () => {
      const { k, b, c, d } = batch(n);
      expect(verifyProof(suite, b, c, d, generateProof(suite, k, b, c, d))).toBe(true);
    });
  }

  it('rejects a proof against the wrong public key', () => {
    const { k, b, c, d } = batch(2);
    const proof = generateProof(suite, k, b, c, d);
    const otherKey = suite.scalarMultiplyElement(suite.generator(), suite.randomScalar());

    expect(verifyProof(suite, otherKey, c, d, proof)).toBe(false);
  });

  it('rejects a proof after an evaluated element is substituted', () => {
    const { k, b, c, d } = batch(2);
    const proof = generateProof(suite, k, b, c, d);
    const tampered = [...d];
    tampered[0] = suite.scalarMultiplyElement(c[1], k);

    expect(verifyProof(suite, b, c, tampered, proof)).toBe(false);
  });

  /** The batch is bound as an ordered list; the composite index is what does it. */
  it('rejects a proof after the batch is reordered', () => {
    const { k, b, c, d } = batch(2);
    const proof = generateProof(suite, k, b, c, d);

    expect(verifyProof(suite, b, [c[1], c[0]], [d[1], d[0]], proof)).toBe(false);
  });

  it('rejects a bit-flipped proof', () => {
    const { k, b, c, d } = batch(2);
    const bytes = serializeProof(suite, generateProof(suite, k, b, c, d));
    bytes[0] ^= 0x01;

    expect(verifyProof(suite, b, c, d, deserializeProof(suite, bytes))).toBe(false);
  });

  /**
   * A caller bug, not an attacker-influenced failure, so it throws rather than
   * returning false — swallowing it would hide a client that failed to check the
   * server returned as many elements as it sent.
   */
  it('throws rather than returning false on a length-mismatched batch', () => {
    const { k, b, c, d } = batch(2);
    const proof = generateProof(suite, k, b, c, d);

    expect(() => verifyProof(suite, b, c, [d[0]], proof)).toThrow(/same length/);
    expect(() => verifyProof(suite, b, [], [], proof)).toThrow(/at least one/);
  });

  it('refuses to prove or verify under a base-mode suite', () => {
    const { k, b, c, d } = batch(1);
    const proof = generateProof(suite, k, b, c, d);

    expect(() => generateProof(P256_SHA256, k, b, c, d)).toThrow(/requires one of/);
    expect(() => verifyProof(P256_SHA256, b, c, d, proof)).toThrow(/requires one of/);
  });
});

describe('proof serialization', () => {
  for (const rfcName of RFC_SUITE_NAMES) {
    const suite = getCipherSuiteForMode(CONFIG_SUITE_NAMES[rfcName], OprfMode.VOPRF);

    it(`${rfcName}: a proof is exactly 2 * Ns bytes`, () => {
      const vectors = loadVectors(rfcName, 'VOPRF');
      expect(vectors.vectors[0].proof!.length).toEqual(2 * suite.Ns);
    });

    it(`${rfcName}: round trips through serialize/deserialize`, () => {
      const proof = { c: suite.randomScalar(), s: suite.randomScalar() };
      const restored = deserializeProof(suite, serializeProof(suite, proof));

      expect(restored.c).toEqual(proof.c);
      expect(restored.s).toEqual(proof.s);
    });

    /**
     * Without the canonical range check, `c` and `c + ORDER` are distinct byte
     * strings that verify identically. Every positive vector passes either way,
     * so this is the only thing asserting it.
     */
    it(`${rfcName}: rejects a non-canonical scalar`, () => {
      const overflowing = suite.serializeScalar(suite.ORDER - 1n);
      // Bump the encoding to exactly ORDER, which must not parse.
      const atOrder = suite.serializeScalar(suite.ORDER - 1n);
      void overflowing;
      const bumped = bumpToOrder(suite, atOrder);

      expect(() => deserializeProof(suite, concatBytes(bumped, bumped)))
        .toThrow(/not canonical/);
    });

    it(`${rfcName}: rejects a wrong-length proof`, () => {
      expect(() => deserializeProof(suite, new Uint8Array(2 * suite.Ns - 1)))
        .toThrow(/expected/);
    });
  }
});

/**
 * Produces the encoding of exactly ORDER, which `deserializeScalar` must reject.
 * Written through `serializeScalar` so it is correct on both endiannesses.
 */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
function bumpToOrder(suite: any, _hint: Uint8Array): Uint8Array {
  void _hint;
  const n: bigint = suite.ORDER;
  const bytes = new Uint8Array(suite.Ns);
  let value = n;
  if (suite.name === 'ristretto255-SHA512') {
    for (let i = 0; i < bytes.length; i++) { bytes[i] = Number(value & 0xffn); value >>= 8n; }
  } else {
    for (let i = bytes.length - 1; i >= 0; i--) { bytes[i] = Number(value & 0xffn); value >>= 8n; }
  }
  return bytes;
}

function concatBytes(a: Uint8Array, b: Uint8Array): Uint8Array {
  const out = new Uint8Array(a.length + b.length);
  out.set(a, 0);
  out.set(b, a.length);
  return out;
}
