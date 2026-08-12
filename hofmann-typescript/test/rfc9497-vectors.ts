/**
 * Loader for the RFC 9497 Appendix A test vectors.
 *
 * Reads `hofmann-rfc/src/test/resources/rfc9497/vectors.json` — the same file the
 * Java tests use, deliberately not a transcription of it. Re-transcribing is how
 * a port ends up testing a subset and passing: the file already covers all four
 * suites across all three modes, with the RFC's two documented parsing traps
 * handled once, and a second copy would drift.
 *
 * Vitest runs under Node, so reading it off disk is fine; nothing here ships.
 */
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { fromHex } from '../src/crypto/primitives.js';

const HERE = dirname(fileURLToPath(import.meta.url));
const VECTORS_PATH = join(
  HERE, '..', '..', 'hofmann-rfc', 'src', 'test', 'resources', 'rfc9497', 'vectors.json');

/**
 * One Appendix A test vector, with the comma-separated batch fields split out.
 *
 * **Every scalar stays as bytes.** The RFC prints scalars in each suite's own
 * canonical encoding — big-endian for the NIST curves, little-endian for
 * ristretto255 — so a loader that decoded them itself would have to reimplement
 * the very convention the suite exists to own, and would silently produce
 * garbage on one of the four suites. Decode with `suite.deserializeScalar`.
 */
export interface Vector {
  readonly batchSize: number;
  readonly inputs: Uint8Array[];
  readonly blinds: Uint8Array[];
  readonly blindedElements: Uint8Array[];
  readonly evaluationElements: Uint8Array[];
  readonly outputs: Uint8Array[];
  /** Absent in base mode, present for VOPRF and POPRF. */
  readonly proof?: Uint8Array;
  readonly proofRandomScalar?: Uint8Array;
  /** POPRF only. */
  readonly info?: Uint8Array;
}

export interface ModeVectors {
  readonly skSm: Uint8Array;
  readonly pkSm?: Uint8Array;
  readonly seed: Uint8Array;
  readonly keyInfo: Uint8Array;
  readonly vectors: Vector[];
}

/** The RFC's spelling of each suite, which is also the contextString segment. */
export const RFC_SUITE_NAMES = [
  'P256-SHA256', 'P384-SHA384', 'P521-SHA512', 'ristretto255-SHA512',
] as const;
export type RfcSuiteName = typeof RFC_SUITE_NAMES[number];

/** The config-response spelling, which is what `getCipherSuite` accepts. */
export const CONFIG_SUITE_NAMES: Record<RfcSuiteName, string> = {
  'P256-SHA256': 'P256_SHA256',
  'P384-SHA384': 'P384_SHA384',
  'P521-SHA512': 'P521_SHA512',
  'ristretto255-SHA512': 'RISTRETTO255_SHA512',
};

// eslint-disable-next-line @typescript-eslint/no-explicit-any
const RAW: any = JSON.parse(readFileSync(VECTORS_PATH, 'utf8'));

function splitHex(value: string): Uint8Array[] {
  return value.split(',').map((part) => fromHex(part.trim()));
}

/**
 * Returns the vectors for one (suite, mode) pair.
 *
 * @param suite the RFC's suite spelling, e.g. "P256-SHA256"
 * @param mode  "OPRF", "VOPRF" or "POPRF"
 */
export function loadVectors(suite: RfcSuiteName, mode: 'OPRF' | 'VOPRF' | 'POPRF'): ModeVectors {
  const node = RAW[suite]?.[mode];
  if (!node) throw new Error(`No vectors for ${suite}/${mode}`);
  return {
    skSm: fromHex(node.keys.skSm),
    pkSm: node.keys.pkSm ? fromHex(node.keys.pkSm) : undefined,
    seed: fromHex(node.keys.Seed),
    keyInfo: fromHex(node.keys.KeyInfo),
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    vectors: node.vectors.map((v: any): Vector => ({
      batchSize: v.batchSize,
      inputs: splitHex(v.Input),
      blinds: splitHex(v.Blind),
      blindedElements: splitHex(v.BlindedElement),
      evaluationElements: splitHex(v.EvaluationElement),
      outputs: splitHex(v.Output),
      proof: v.Proof ? fromHex(v.Proof) : undefined,
      proofRandomScalar: v.ProofRandomScalar ? fromHex(v.ProofRandomScalar) : undefined,
      info: v.Info !== undefined ? fromHex(v.Info) : undefined,
    })),
  };
}

/** The secret key as a bigint, decoded in the suite's canonical scalar encoding. */
export function secretKeyScalar(
  suite: { deserializeScalar(b: Uint8Array): bigint },
  skSm: Uint8Array,
): bigint {
  return suite.deserializeScalar(skSm);
}
