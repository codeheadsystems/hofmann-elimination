/**
 * The pinned-key cross-check, and the verifiable HTTP paths driven against a
 * stubbed `fetch`.
 *
 * `assertPinnedKeyMatches` implements the same rule as Java's
 * `OprfClientConfig.assertMatches`, and the two are meant to be diffable side by
 * side — so the cases here mirror that test class deliberately.
 */
import { describe, it, expect, vi, afterEach } from 'vitest';
import { fromHex, toHex } from '../src/crypto/primitives.js';
import { strToBytes } from '../src/crypto/encoding.js';
import { getCipherSuiteForMode, OprfMode } from '../src/oprf/suite.js';
import { generateProof, serializeProof } from '../src/oprf/dleq.js';
import {
  OprfHttpClient, assertPinnedKeyMatches,
  OprfModeNotEnabledError, OprfPublicKeyMismatchError, OprfRateLimitedError,
  type OprfConfigResponseDto,
} from '../src/oprf/http.js';
import { loadVectors } from './rfc9497-vectors.js';

const VOPRF_KEY = fromHex(
  '02f4a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f');
const POPRF_KEY = fromHex(
  '0311223344556677889900aabbccddeeff11223344556677889900aabbccddeeff');

function advertising(mode: string, keyHex: string): OprfConfigResponseDto {
  return {
    cipherSuite: 'P256_SHA256',
    modes: [{ mode, publicKeyHex: keyHex, processIdentifier: 'proc', maxBatchSize: 64 }],
  };
}

describe('assertPinnedKeyMatches', () => {
  /** State one: no mode list — an older server, or one with no verifiable mode. */
  it('proceeds when the server advertises no modes', () => {
    expect(() => assertPinnedKeyMatches(
      { cipherSuite: 'P256_SHA256' }, 'VOPRF', VOPRF_KEY)).not.toThrow();
  });

  /** State two: listed and agreeing. */
  it('proceeds when the advertised key matches', () => {
    expect(() => assertPinnedKeyMatches(
      advertising('VOPRF', toHex(VOPRF_KEY)), 'VOPRF', VOPRF_KEY)).not.toThrow();
  });

  it('treats hex case as a spelling difference, not a disagreement', () => {
    expect(() => assertPinnedKeyMatches(
      advertising('VOPRF', toHex(VOPRF_KEY).toUpperCase()), 'VOPRF', VOPRF_KEY)).not.toThrow();
  });

  it('ignores surrounding whitespace on the advertised key', () => {
    expect(() => assertPinnedKeyMatches(
      advertising('VOPRF', `  ${toHex(VOPRF_KEY)}  `), 'VOPRF', VOPRF_KEY)).not.toThrow();
  });

  it('ignores mode-name case', () => {
    expect(() => assertPinnedKeyMatches(
      advertising('voprf', toHex(VOPRF_KEY)), 'VOPRF', VOPRF_KEY)).not.toThrow();
  });

  /** The case the whole mechanism exists for. */
  it('fails loudly on a different key, naming both likely causes', () => {
    expect(() => assertPinnedKeyMatches(
      advertising('VOPRF', toHex(POPRF_KEY)), 'VOPRF', VOPRF_KEY))
      .toThrow(OprfPublicKeyMismatchError);
    expect(() => assertPinnedKeyMatches(
      advertising('VOPRF', toHex(POPRF_KEY)), 'VOPRF', VOPRF_KEY))
      .toThrow(/rotated its key|Refusing to proceed/);
  });

  /** State three: a complete list that does not name the mode. */
  it('reports the mode as disabled when the list omits it', () => {
    expect(() => assertPinnedKeyMatches(
      advertising('VOPRF', toHex(VOPRF_KEY)), 'POPRF', POPRF_KEY))
      .toThrow(OprfModeNotEnabledError);
  });

  it('treats an empty mode list as every mode being off', () => {
    expect(() => assertPinnedKeyMatches(
      { cipherSuite: 'P256_SHA256', modes: [] }, 'VOPRF', VOPRF_KEY))
      .toThrow(OprfModeNotEnabledError);
  });

  it('reports a non-hex advertised key as a mismatch rather than crashing', () => {
    expect(() => assertPinnedKeyMatches(
      advertising('VOPRF', 'not-hex'), 'VOPRF', VOPRF_KEY))
      .toThrow(OprfPublicKeyMismatchError);
  });

  it('still checks mode availability when nothing is pinned', () => {
    expect(() => assertPinnedKeyMatches(
      advertising('VOPRF', toHex(VOPRF_KEY)), 'VOPRF', undefined as unknown as Uint8Array))
      .not.toThrow();
    expect(() => assertPinnedKeyMatches(
      advertising('VOPRF', toHex(VOPRF_KEY)), 'POPRF', undefined as unknown as Uint8Array))
      .toThrow(OprfModeNotEnabledError);
  });
});

// ── HTTP paths ───────────────────────────────────────────────────────────────

const suite = getCipherSuiteForMode('P256_SHA256', OprfMode.VOPRF);
const SK = suite.deserializeScalar(loadVectors('P256-SHA256', 'VOPRF').skSm);
const PK = suite.scalarMultiplyElement(suite.generator(), SK);

interface StubOptions {
  tamperProof?: boolean;
  status?: number;
  retryAfter?: string;
  modes?: OprfConfigResponseDto['modes'];
}

/**
 * A `fetch` that answers `/oprf/config` and `/oprf/verifiable` from an in-process
 * server built on the vectors' key.
 */
function stubFetch(options: StubOptions = {}): void {
  vi.stubGlobal('fetch', async (url: string, init?: RequestInit) => {
    if (String(url).endsWith('/oprf/config')) {
      return new Response(JSON.stringify({
        cipherSuite: 'P256_SHA256',
        modes: options.modes ?? [
          { mode: 'VOPRF', publicKeyHex: toHex(PK), processIdentifier: 'proc', maxBatchSize: 64 },
        ],
      }), { status: 200 });
    }
    if (options.status && options.status !== 200) {
      return new Response('', {
        status: options.status,
        headers: options.retryAfter ? { 'Retry-After': options.retryAfter } : undefined,
      });
    }
    const body = JSON.parse(String(init?.body)) as { blindedElements: string[] };
    const blinded = body.blindedElements.map(fromHex);
    const evaluated = blinded.map((e) => suite.scalarMultiplyElement(e, SK));
    const proof = serializeProof(suite, generateProof(suite, SK, PK, blinded, evaluated));
    if (options.tamperProof) proof[0] ^= 0x01;
    return new Response(JSON.stringify({
      evaluatedElements: evaluated.map(toHex),
      proof: toHex(proof),
      processIdentifier: 'proc',
    }), { status: 200 });
  });
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('OprfHttpClient verifiable paths', () => {
  it('evaluates a batch and verifies the proof', async () => {
    stubFetch();
    const client = await OprfHttpClient.create('https://example.test', {
      voprfServerPublicKey: PK,
    });

    const outputs = await client.evaluateVerifiable([strToBytes('a'), strToBytes('b')]);

    expect(outputs).toHaveLength(2);
    expect(toHex(outputs[0])).not.toEqual(toHex(outputs[1]));
  });

  /**
   * Without this, "TypeScript verified a Java-served proof" is unfalsifiable
   * from the outside: a verifier that returned true unconditionally would pass
   * the interop test too.
   */
  it('rejects a tampered proof rather than returning output', async () => {
    stubFetch({ tamperProof: true });
    const client = await OprfHttpClient.create('https://example.test', {
      voprfServerPublicKey: PK,
    });

    await expect(client.evaluateVerifiable([strToBytes('a')])).rejects.toThrow(/did not verify/);
  });

  it('cross-checks the pinned key at construction', async () => {
    stubFetch();

    await expect(OprfHttpClient.create('https://example.test', {
      voprfServerPublicKey: VOPRF_KEY,
    })).rejects.toThrow(OprfPublicKeyMismatchError);
  });

  it('refuses to evaluate without a pinned key, and says why', async () => {
    stubFetch();
    const client = await OprfHttpClient.create('https://example.test');

    await expect(client.evaluateVerifiable([strToBytes('a')]))
      .rejects.toThrow(/authenticated out of band/);
  });

  it('maps 404 to a mode-not-enabled error', async () => {
    stubFetch({ status: 404 });
    const client = await OprfHttpClient.create('https://example.test', {
      voprfServerPublicKey: PK,
    });

    await expect(client.evaluateVerifiable([strToBytes('a')]))
      .rejects.toThrow(OprfModeNotEnabledError);
  });

  it('maps 429 to a rate-limit error carrying Retry-After', async () => {
    stubFetch({ status: 429, retryAfter: '60' });
    const client = await OprfHttpClient.create('https://example.test', {
      voprfServerPublicKey: PK,
    });

    await expect(client.evaluateVerifiable([strToBytes('a')]))
      .rejects.toMatchObject({ retryAfterSeconds: 60 });
    await expect(client.evaluateVerifiable([strToBytes('a')]))
      .rejects.toBeInstanceOf(OprfRateLimitedError);
  });

  it('leaves retryAfterSeconds undefined when the header is absent', async () => {
    stubFetch({ status: 429 });
    const client = await OprfHttpClient.create('https://example.test', {
      voprfServerPublicKey: PK,
    });

    await expect(client.evaluateVerifiable([strToBytes('a')]))
      .rejects.toMatchObject({ retryAfterSeconds: undefined });
  });

  it('fails at construction when the server does not offer the mode', async () => {
    stubFetch({ modes: [] });

    await expect(OprfHttpClient.create('https://example.test', {
      voprfServerPublicKey: PK,
    })).rejects.toThrow(OprfModeNotEnabledError);
  });

  it('create(baseUrl) with no options still works, as before', async () => {
    stubFetch();
    const client = await OprfHttpClient.create('https://example.test');

    expect(client.cachedConfig?.cipherSuite).toEqual('P256_SHA256');
  });
});
