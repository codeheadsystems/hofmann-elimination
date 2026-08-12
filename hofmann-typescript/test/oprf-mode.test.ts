/**
 * Mode threading through the cipher suites.
 *
 * The mode byte lives in the contextString and therefore in every
 * domain-separation tag derived from it. Two things must hold: the tags must be
 * exactly what RFC 9497 §3.1 specifies for all twelve (suite, mode) pairs, and
 * base mode must be untouched — OPAQUE imports these suites directly, and the
 * built `dist` feeds the cross-language harness.
 */
import { describe, it, expect } from 'vitest';
import { toHex } from '../src/crypto/primitives.js';
import { strToBytes } from '../src/crypto/encoding.js';
import {
  getCipherSuite, getCipherSuiteForMode, OprfMode, assertMode,
  P256_SHA256, P384_SHA384, P521_SHA512, RISTRETTO255_SHA512,
} from '../src/oprf/suite.js';
import { CONFIG_SUITE_NAMES, RFC_SUITE_NAMES, loadVectors } from './rfc9497-vectors.js';

const MODES = [
  { name: 'OPRF', byte: 0x00, value: OprfMode.OPRF },
  { name: 'VOPRF', byte: 0x01, value: OprfMode.VOPRF },
  { name: 'POPRF', byte: 0x02, value: OprfMode.POPRF },
] as const;

describe('contextString and DSTs for all twelve (suite, mode) pairs', () => {
  for (const rfcName of RFC_SUITE_NAMES) {
    for (const { name: modeName, byte, value } of MODES) {
      it(`${rfcName}/${modeName} builds "OPRFV1-\\x${byte.toString(16).padStart(2, '0')}-${rfcName}"`, () => {
        const suite = getCipherSuiteForMode(CONFIG_SUITE_NAMES[rfcName], value);
        const expected = new Uint8Array([
          ...strToBytes('OPRFV1-'), byte, ...strToBytes(`-${rfcName}`),
        ]);

        expect(toHex(suite.CONTEXT_STRING)).toEqual(toHex(expected));
        expect(suite.mode).toEqual(value);
      });

      it(`${rfcName}/${modeName} derives its three DSTs from that contextString`, () => {
        const suite = getCipherSuiteForMode(CONFIG_SUITE_NAMES[rfcName], value);
        const cs = suite.CONTEXT_STRING;

        expect(toHex(suite.HASH_TO_GROUP_DST))
          .toEqual(toHex(new Uint8Array([...strToBytes('HashToGroup-'), ...cs])));
        expect(toHex(suite.HASH_TO_SCALAR_DST))
          .toEqual(toHex(new Uint8Array([...strToBytes('HashToScalar-'), ...cs])));
        expect(toHex(suite.DERIVE_KEY_PAIR_DST))
          .toEqual(toHex(new Uint8Array([...strToBytes('DeriveKeyPair'), ...cs])));
      });
    }
  }
});

describe('base mode is unchanged', () => {
  const constants = [
    ['P256_SHA256', P256_SHA256],
    ['P384_SHA384', P384_SHA384],
    ['P521_SHA512', P521_SHA512],
    ['RISTRETTO255_SHA512', RISTRETTO255_SHA512],
  ] as const;

  /**
   * Reference identity, not just equality. OPAQUE imports `P256_SHA256`
   * directly; a second, equal-but-distinct base-mode instance would be a silent
   * behavioural change looking for somewhere to happen.
   */
  for (const [configName, constant] of constants) {
    it(`getCipherSuite("${configName}") returns the exported constant itself`, () => {
      expect(getCipherSuite(configName)).toBe(constant);
      expect(getCipherSuiteForMode(configName, OprfMode.OPRF)).toBe(constant);
    });
  }

  it('the exported constants are all in base mode', () => {
    for (const [, constant] of constants) {
      expect(constant.mode).toEqual(OprfMode.OPRF);
    }
  });

  it('a mode-specific suite is a different object from the base-mode one', () => {
    expect(getCipherSuiteForMode('P256_SHA256', OprfMode.VOPRF)).not.toBe(P256_SHA256);
    expect(getCipherSuiteForMode('P256_SHA256', OprfMode.VOPRF).CONTEXT_STRING)
      .not.toEqual(P256_SHA256.CONTEXT_STRING);
  });

  it('caches, so repeated lookups return the same instance', () => {
    expect(getCipherSuiteForMode('P384_SHA384', OprfMode.POPRF))
      .toBe(getCipherSuiteForMode('P384_SHA384', OprfMode.POPRF));
  });
});

describe('one key does not serve two modes', () => {
  /**
   * The mode byte is in the DeriveKeyPair tag, so the same seed gives a
   * different key per mode. The vectors record that directly — ristretto255's
   * base-mode `skSm` starts `5ebc` where its VOPRF one starts `e6f7` — and this
   * asserts the derivation rather than the constant.
   */
  for (const rfcName of RFC_SUITE_NAMES) {
    it(`${rfcName}: deriveKeyPair gives a different key in each mode`, () => {
      const base = loadVectors(rfcName, 'OPRF');
      const keys = MODES.map(({ name, value }) => {
        const suite = getCipherSuiteForMode(CONFIG_SUITE_NAMES[rfcName], value);
        void name;
        return suite.serializeScalar(suite.deriveKeyPair(base.seed, base.keyInfo));
      }).map(toHex);

      expect(new Set(keys).size).toEqual(3);
    });

    it(`${rfcName}: each mode's derived key matches that mode's vector skSm`, () => {
      for (const { name, value } of MODES) {
        const vectors = loadVectors(rfcName, name);
        const suite = getCipherSuiteForMode(CONFIG_SUITE_NAMES[rfcName], value);

        expect(toHex(suite.serializeScalar(suite.deriveKeyPair(vectors.seed, vectors.keyInfo))))
          .toEqual(toHex(vectors.skSm));
      }
    });
  }
});

describe('assertMode', () => {
  it('accepts a suite in one of the allowed modes', () => {
    expect(() => assertMode(P256_SHA256, OprfMode.OPRF)).not.toThrow();
    expect(() => assertMode(
      getCipherSuiteForMode('P256_SHA256', OprfMode.POPRF),
      OprfMode.VOPRF, OprfMode.POPRF)).not.toThrow();
  });

  it('names both the actual and the required modes when it refuses', () => {
    expect(() => assertMode(P256_SHA256, OprfMode.VOPRF, OprfMode.POPRF))
      .toThrow(/configured for OPRF.*requires one of \[VOPRF, POPRF\]/);
  });
});
