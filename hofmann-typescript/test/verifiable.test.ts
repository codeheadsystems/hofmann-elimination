/**
 * VOPRF and POPRF clients end to end, against the RFC 9497 Appendix A vectors.
 *
 * The server side is simulated here from the vectors' own `skSm`, so what is
 * being asserted is that this client, given the RFC's blinds and the RFC's
 * server key, verifies the RFC's proof and produces the RFC's `Output`. A
 * self-consistent implementation that happens to compute a different function
 * fails at the `Output` comparison.
 */
import { describe, it, expect } from 'vitest';
import { toHex, fromHex, concat, i2osp } from '../src/crypto/primitives.js';
import { strToBytes } from '../src/crypto/encoding.js';
import { getCipherSuiteForMode, OprfMode, P256_SHA256 } from '../src/oprf/suite.js';
import { generateProof, serializeProof } from '../src/oprf/dleq.js';
import {
  VoprfClient, PoprfClient,
  type VoprfClientContext, type PoprfClientContext,
  type VoprfResponseDto, type PoprfResponseDto,
} from '../src/oprf/verifiable.js';
import {
  loadVectors, RFC_SUITE_NAMES, CONFIG_SUITE_NAMES, type RfcSuiteName,
} from './rfc9497-vectors.js';

// ── A server, built from a vector's own key ──────────────────────────────────

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function voprfServer(suite: any, skSm: Uint8Array) {
  const k = suite.deserializeScalar(skSm);
  const pk = suite.scalarMultiplyElement(suite.generator(), k);
  return {
    publicKey: pk as Uint8Array,
    evaluate(blindedHex: string[], r?: bigint): VoprfResponseDto {
      const blinded = blindedHex.map(fromHex);
      const evaluated = blinded.map((e: Uint8Array) => suite.scalarMultiplyElement(e, k));
      const proof = generateProof(suite, k, pk, blinded, evaluated, r);
      return {
        evaluatedElements: evaluated.map(toHex),
        proof: toHex(serializeProof(suite, proof)),
        processIdentifier: 'test-processor',
      };
    },
  };
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function poprfServer(suite: any, skSm: Uint8Array) {
  const k = suite.deserializeScalar(skSm);
  return {
    publicKey: suite.scalarMultiplyElement(suite.generator(), k) as Uint8Array,
    evaluate(blindedHex: string[], info: Uint8Array, r?: bigint): PoprfResponseDto {
      const m = suite.hashToScalar(
        concat(strToBytes('Info'), i2osp(info.length, 2), info), suite.HASH_TO_SCALAR_DST);
      const t = (k + m) % suite.ORDER;
      const tweakedPk = suite.scalarMultiplyElement(suite.generator(), t);
      const tInv = modInverse(t, suite.ORDER);
      const blinded = blindedHex.map(fromHex);
      // The POPRF asymmetry: evaluated = t^-1 * blinded, so the prover sees the
      // lists reversed relative to VOPRF.
      const evaluated = blinded.map((e: Uint8Array) => suite.scalarMultiplyElement(e, tInv));
      const proof = generateProof(suite, t, tweakedPk, evaluated, blinded, r);
      return {
        evaluatedElements: evaluated.map(toHex),
        proof: toHex(serializeProof(suite, proof)),
        processIdentifier: 'test-processor',
      };
    },
  };
}

function modInverse(a: bigint, n: bigint): bigint {
  let [old_r, r] = [((a % n) + n) % n, n];
  let [old_s, s] = [1n, 0n];
  while (r !== 0n) {
    const q = old_r / r;
    [old_r, r] = [r, old_r - q * r];
    [old_s, s] = [s, old_s - q * s];
  }
  return ((old_s % n) + n) % n;
}

/** Rebuilds a context from a vector's fixed blinds rather than fresh randomness. */
function contextFromVector(
  requestId: string,
  inputs: Uint8Array[],
  blinds: bigint[],
  blindedElements: Uint8Array[],
): VoprfClientContext {
  return { requestId, inputs, blinds, blindedElements };
}

// ── VOPRF against the vectors ────────────────────────────────────────────────

describe('VoprfClient against RFC 9497 Appendix A', () => {
  for (const rfcName of RFC_SUITE_NAMES) {
    const suite = getCipherSuiteForMode(CONFIG_SUITE_NAMES[rfcName], OprfMode.VOPRF);
    const vectors = loadVectors(rfcName, 'VOPRF');
    const server = voprfServer(suite, vectors.skSm);

    it(`${rfcName}: the derived public key matches the vector's pkSm`, () => {
      expect(toHex(server.publicKey)).toEqual(toHex(vectors.pkSm!));
    });

    vectors.vectors.forEach((v, index) => {
      it(`${rfcName}: vector ${index} (batch ${v.batchSize}) verifies and produces Output`, () => {
        const client = new VoprfClient(suite, server.publicKey);
        const ctx = contextFromVector(
          'req', v.inputs, v.blinds.map((b) => suite.deserializeScalar(b)), v.blindedElements);

        // The blinded elements the client would have produced must match the RFC's.
        v.inputs.forEach((input, i) => {
          expect(toHex(suite.blind(input, ctx.blinds[i]).blindedElement))
            .toEqual(toHex(v.blindedElements[i]));
        });

        const response = server.evaluate(
          v.blindedElements.map(toHex), suite.deserializeScalar(v.proofRandomScalar!));
        expect(response.proof).toEqual(toHex(v.proof!));

        const outputs = client.finalizeBatch(ctx, response);

        expect(outputs.map(toHex)).toEqual(v.outputs.map(toHex));
      });
    });
  }
});

// ── POPRF against the vectors ────────────────────────────────────────────────

describe('PoprfClient against RFC 9497 Appendix A', () => {
  for (const rfcName of RFC_SUITE_NAMES) {
    const suite = getCipherSuiteForMode(CONFIG_SUITE_NAMES[rfcName], OprfMode.POPRF);
    const vectors = loadVectors(rfcName, 'POPRF');
    const server = poprfServer(suite, vectors.skSm);

    vectors.vectors.forEach((v, index) => {
      it(`${rfcName}: vector ${index} (batch ${v.batchSize}) verifies and produces Output`, () => {
        const client = new PoprfClient(suite, server.publicKey);
        const blinds = v.blinds.map((b) => suite.deserializeScalar(b));
        const ctx: PoprfClientContext = {
          ...contextFromVector('req', v.inputs, blinds, v.blindedElements),
          info: v.info!,
          tweakedKey: client.blindBatch([new Uint8Array([0])], v.info!).tweakedKey,
        };

        const response = server.evaluate(
          v.blindedElements.map(toHex), v.info!, suite.deserializeScalar(v.proofRandomScalar!));
        expect(response.proof).toEqual(toHex(v.proof!));

        const outputs = client.finalizeBatch(ctx, response);

        expect(outputs.map(toHex)).toEqual(v.outputs.map(toHex));
      });
    });
  }
});

// ── Behaviour beyond the vectors ─────────────────────────────────────────────

describe('VoprfClient behaviour', () => {
  const suite = getCipherSuiteForMode('P256_SHA256', OprfMode.VOPRF);
  const skSm = loadVectors('P256-SHA256', 'VOPRF').skSm;
  const server = voprfServer(suite, skSm);

  function client(): VoprfClient {
    return new VoprfClient(suite, server.publicKey);
  }

  it('round trips a fresh batch', () => {
    const c = client();
    const ctx = c.blindBatch([strToBytes('alpha'), strToBytes('beta')]);
    const outputs = c.finalizeBatch(ctx, server.evaluate(c.request(ctx).blindedElements));

    expect(outputs).toHaveLength(2);
    expect(toHex(outputs[0])).not.toEqual(toHex(outputs[1]));
  });

  it('is deterministic across independent blinds', () => {
    const c = client();
    const run = (): string => {
      const ctx = c.blindBatch([strToBytes('stable')]);
      return toHex(c.finalizeBatch(ctx, server.evaluate(c.request(ctx).blindedElements))[0]);
    };

    expect(run()).toEqual(run());
  });

  it('refuses a base-mode suite at construction', () => {
    expect(() => new VoprfClient(P256_SHA256, server.publicKey)).toThrow(/requires one of/);
  });

  it('refuses an identity public key at construction', () => {
    expect(() => new VoprfClient(suite, new Uint8Array(suite.Ne))).toThrow(/identity|0x02/);
  });

  it('rejects a response evaluated under a different key', () => {
    const impostor = voprfServer(suite, loadVectors('P256-SHA256', 'POPRF').skSm);
    const c = client();
    const ctx = c.blindBatch([strToBytes('alpha')]);

    expect(() => c.finalizeBatch(ctx, impostor.evaluate(c.request(ctx).blindedElements)))
      .toThrow(/did not verify/);
  });

  it('rejects a bit-flipped proof', () => {
    const c = client();
    const ctx = c.blindBatch([strToBytes('alpha')]);
    const response = server.evaluate(c.request(ctx).blindedElements);
    const proof = fromHex(response.proof);
    proof[0] ^= 0x01;

    expect(() => c.finalizeBatch(ctx, { ...response, proof: toHex(proof) }))
      .toThrow(/did not verify/);
  });

  it('rejects a response with the wrong number of elements', () => {
    const c = client();
    const ctx = c.blindBatch([strToBytes('alpha'), strToBytes('beta')]);
    const response = server.evaluate(c.request(ctx).blindedElements);

    expect(() => c.finalizeBatch(ctx, {
      ...response, evaluatedElements: [response.evaluatedElements[0]],
    })).toThrow(/evaluated elements for/);
  });

  it('rejects an empty batch', () => {
    expect(() => client().blindBatch([])).toThrow(/At least one input/);
  });
});

describe('PoprfClient behaviour', () => {
  const suite = getCipherSuiteForMode('P256_SHA256', OprfMode.POPRF);
  const skSm = loadVectors('P256-SHA256', 'POPRF').skSm;
  const server = poprfServer(suite, skSm);

  function client(): PoprfClient {
    return new PoprfClient(suite, server.publicKey);
  }

  function evaluate(c: PoprfClient, inputs: Uint8Array[], info: Uint8Array): Uint8Array[] {
    const ctx = c.blindBatch(inputs, info);
    return c.finalizeBatch(ctx, server.evaluate(c.request(ctx).blindedElements, info));
  }

  it('round trips a batch under a public input', () => {
    const outputs = evaluate(client(), [strToBytes('alpha'), strToBytes('beta')], strToBytes('t1'));

    expect(outputs).toHaveLength(2);
    expect(toHex(outputs[0])).not.toEqual(toHex(outputs[1]));
  });

  it('gives unrelated outputs under different public inputs', () => {
    const c = client();

    expect(toHex(evaluate(c, [strToBytes('alpha')], strToBytes('t1'))[0]))
      .not.toEqual(toHex(evaluate(c, [strToBytes('alpha')], strToBytes('t2'))[0]));
  });

  /**
   * Empty is a public input, not the absence of one. POPRF Finalize emits the
   * two-byte length prefix even when info is empty, where base mode omits the
   * field entirely — reusing the base-mode transcript here silently computes
   * base mode and every self-consistent round trip still passes.
   */
  it('treats an empty public input as a real and distinct one', () => {
    const c = client();
    const empty = evaluate(c, [strToBytes('alpha')], new Uint8Array(0));

    expect(empty[0]).not.toHaveLength(0);
    expect(toHex(empty[0]))
      .not.toEqual(toHex(evaluate(c, [strToBytes('alpha')], strToBytes('t1'))[0]));
  });

  /** The proof is graded against the tweaked key, which is what binds it to `info`. */
  it('rejects a response computed under a different public input', () => {
    const c = client();
    const ctx = c.blindBatch([strToBytes('alpha')], strToBytes('asked-for'));
    const substituted = server.evaluate(c.request(ctx).blindedElements, strToBytes('served'));

    expect(() => c.finalizeBatch(ctx, substituted)).toThrow(/did not verify/);
  });

  it('refuses a VOPRF-mode suite at construction', () => {
    const voprfSuite = getCipherSuiteForMode('P256_SHA256', OprfMode.VOPRF);
    expect(() => new PoprfClient(voprfSuite, server.publicKey)).toThrow(/requires one of/);
  });

  it('sends info as hex, with empty meaning no public input', () => {
    const c = client();

    expect(c.request(c.blindBatch([strToBytes('a')], new Uint8Array(0))).info).toEqual('');
    expect(c.request(c.blindBatch([strToBytes('a')], strToBytes('hi'))).info).toEqual('6869');
  });
});
