/**
 * RFC 9497 VOPRF (mode 0x01) and POPRF (mode 0x02) clients.
 *
 * Both take the server's public key at construction and never accept one from a
 * response. That is the whole property: a proof graded against a key the same
 * server supplied proves nothing, because a server able to choose both can
 * produce a verifying pair for any key it likes — and RFC 9497 §7.3 notes it can
 * do so per-client, partitioning users into individually identifiable buckets.
 * The key must arrive out of band, authenticated by something other than this
 * connection.
 */
import { toHex, fromHex, concat, i2osp } from '../crypto/primitives.js';
import { strToBytes } from '../crypto/encoding.js';
import { type CipherSuite, OprfMode, assertMode } from './suite.js';
import { deserializeProof, verifyProof } from './dleq.js';

// ── Wire model ───────────────────────────────────────────────────────────────

/** POST /oprf/verifiable request body. */
export interface VoprfRequestDto {
  blindedElements: string[];
  requestId: string;
}

/** POST /oprf/verifiable response body. */
export interface VoprfResponseDto {
  evaluatedElements: string[];
  proof: string;
  processIdentifier: string;
}

/** POST /oprf/partially-oblivious request body. */
export interface PoprfRequestDto {
  blindedElements: string[];
  /** Hex-encoded public input. Required; an empty string means "no public input". */
  info: string;
  requestId: string;
}

/** POST /oprf/partially-oblivious response body. */
export interface PoprfResponseDto {
  evaluatedElements: string[];
  proof: string;
  processIdentifier: string;
}

// ── Contexts ─────────────────────────────────────────────────────────────────

/** Client state between blinding a batch and finalizing the server's response. */
export interface VoprfClientContext {
  readonly requestId: string;
  readonly inputs: Uint8Array[];
  readonly blinds: bigint[];
  readonly blindedElements: Uint8Array[];
}

/** As {@link VoprfClientContext}, plus the public input and the key it tweaks to. */
export interface PoprfClientContext extends VoprfClientContext {
  readonly info: Uint8Array;
  /** `m*G + pkS`, derived by the client. The proof is graded against this, not `pkS`. */
  readonly tweakedKey: Uint8Array;
}

/** RFC 9497 §3.3.3: m = HashToScalar("Info" || I2OSP(len(info), 2) || info). */
function infoScalar(suite: CipherSuite, info: Uint8Array): bigint {
  return suite.hashToScalar(
    concat(strToBytes('Info'), i2osp(info.length, 2), info),
    suite.HASH_TO_SCALAR_DST,
  );
}

function blindBatchInto(
  suite: CipherSuite,
  inputs: Uint8Array[],
): { requestId: string; inputs: Uint8Array[]; blinds: bigint[]; blindedElements: Uint8Array[] } {
  if (!inputs || inputs.length === 0) {
    throw new Error('At least one input is required');
  }
  const blinds: bigint[] = [];
  const blindedElements: Uint8Array[] = [];
  const copied: Uint8Array[] = [];
  for (const input of inputs) {
    const { blind, blindedElement } = suite.blind(input);
    copied.push(Uint8Array.from(input));
    blinds.push(blind);
    blindedElements.push(blindedElement);
  }
  return { requestId: crypto.randomUUID(), inputs: copied, blinds, blindedElements };
}

/**
 * Decodes and validates the server's evaluated elements.
 *
 * Length first, so a short response is a clear error rather than an index out of
 * range inside the proof transcript.
 */
function decodeEvaluated(
  suite: CipherSuite,
  hexElements: string[],
  expected: number,
): Uint8Array[] {
  if (hexElements.length !== expected) {
    throw new Error(
      `Server returned ${hexElements.length} evaluated elements for ${expected} blinded elements`);
  }
  return hexElements.map((hex) => {
    const element = fromHex(hex);
    suite.validateElement(element);
    return element;
  });
}

// ── VOPRF ────────────────────────────────────────────────────────────────────

/** RFC 9497 §3.3.2 VOPRF client. */
export class VoprfClient {
  private readonly serverPublicKey: Uint8Array;

  /**
   * @param suite           a suite built for VOPRF mode — see `getCipherSuiteForMode`
   * @param serverPublicKey the server's public key, obtained and authenticated out of band
   */
  constructor(readonly suite: CipherSuite, serverPublicKey: Uint8Array) {
    assertMode(suite, OprfMode.VOPRF);
    // Validated once, here, rather than on each use. A public key that is the
    // identity, off-curve or non-canonically encoded would otherwise fail every
    // proof with no indication of why.
    suite.validateElement(serverPublicKey);
    this.serverPublicKey = Uint8Array.from(serverPublicKey);
  }

  /** Blinds a batch of inputs, all to be evaluated under one proof. */
  blindBatch(inputs: Uint8Array[]): VoprfClientContext {
    return blindBatchInto(this.suite, inputs);
  }

  /** Builds the wire request for a context. */
  request(ctx: VoprfClientContext): VoprfRequestDto {
    return {
      blindedElements: ctx.blindedElements.map(toHex),
      requestId: ctx.requestId,
    };
  }

  /**
   * Verifies the server's proof and, **only if it holds**, unblinds every element.
   *
   * The order matters and is not an implementation detail: unblinding before
   * verifying produces output indistinguishable from correct, which is precisely
   * what this mode exists to prevent.
   *
   * @throws Error if the proof does not verify or the response is malformed
   */
  finalizeBatch(ctx: VoprfClientContext, response: VoprfResponseDto): Uint8Array[] {
    const evaluated = decodeEvaluated(this.suite, response.evaluatedElements, ctx.inputs.length);
    const proof = deserializeProof(this.suite, fromHex(response.proof));

    if (!verifyProof(this.suite, this.serverPublicKey, ctx.blindedElements, evaluated, proof)) {
      throw new Error(
        `VOPRF proof did not verify for processor '${response.processIdentifier}'; the server did ` +
        `not evaluate with the key this client pinned`);
    }

    return evaluated.map((element, i) => this.suite.finalize(ctx.inputs[i], ctx.blinds[i], element));
  }
}

// ── POPRF ────────────────────────────────────────────────────────────────────

/** RFC 9497 §3.3.3 POPRF client. */
export class PoprfClient {
  private readonly serverPublicKey: Uint8Array;

  /**
   * @param suite           a suite built for POPRF mode
   * @param serverPublicKey the server's **untweaked** public key, obtained out of band
   */
  constructor(readonly suite: CipherSuite, serverPublicKey: Uint8Array) {
    assertMode(suite, OprfMode.POPRF);
    suite.validateElement(serverPublicKey);
    this.serverPublicKey = Uint8Array.from(serverPublicKey);
  }

  /**
   * Blinds a batch under a public input.
   *
   * `info` is required and an empty array is a valid value meaning "no public
   * input". Absent and empty are different public inputs producing different
   * outputs, so there is no default.
   */
  blindBatch(inputs: Uint8Array[], info: Uint8Array): PoprfClientContext {
    if (info === null || info === undefined) {
      throw new Error(
        'Public input is required; use an empty Uint8Array for no public input. An absent public ' +
        'input and an empty one are different public inputs producing different outputs.');
    }
    const base = blindBatchInto(this.suite, inputs);
    const m = infoScalar(this.suite, info);
    // One multi-scalar operation rather than add(m*G, pkS). The composed form
    // hands `add` an identity encoding when m is zero and reports it as a
    // malformed element, where §3.3.3 asks the client to detect the identity
    // result as such.
    const tweakedKey = this.suite.linearCombination(
      [m, 1n], [this.suite.generator(), this.serverPublicKey]);
    return { ...base, info: Uint8Array.from(info), tweakedKey };
  }

  /** Builds the wire request for a context. */
  request(ctx: PoprfClientContext): PoprfRequestDto {
    return {
      blindedElements: ctx.blindedElements.map(toHex),
      info: toHex(ctx.info),
      requestId: ctx.requestId,
    };
  }

  /**
   * Verifies the server's proof and, only if it holds, unblinds every element.
   *
   * Graded against the client's own tweaked key, with the element lists in POPRF
   * order — evaluated first, because `blindedElement = t * evaluatedElement`. A
   * port that keeps VOPRF's order round-trips against itself and fails every
   * vector. Grading against the tweaked key is what binds the response to the
   * public input the client actually asked for.
   */
  finalizeBatch(ctx: PoprfClientContext, response: PoprfResponseDto): Uint8Array[] {
    const evaluated = decodeEvaluated(this.suite, response.evaluatedElements, ctx.inputs.length);
    const proof = deserializeProof(this.suite, fromHex(response.proof));

    if (!verifyProof(this.suite, ctx.tweakedKey, evaluated, ctx.blindedElements, proof)) {
      throw new Error(
        `POPRF proof did not verify for processor '${response.processIdentifier}'; the server did ` +
        `not evaluate with the committed key under this public input`);
    }

    return evaluated.map((element, i) =>
      this.suite.finalizeWithInfo(ctx.inputs[i], ctx.info, ctx.blinds[i], element));
  }
}
