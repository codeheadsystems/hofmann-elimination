/**
 * RFC 9497 OPRF test vectors — P-256/SHA-256 (Appendix A.1.1).
 * Also covers: suite constants for P-384/P-521, getCipherSuite(), and
 * per-suite OPRF round-trip consistency checks.
 *
 * Source: CFRG draft-irtf-cfrg-voprf, Appendix A.1.1
 * Seed = 0xa3a3...a3 (32 bytes), Info = "test key"
 */
import { describe, it, expect } from 'vitest';
import {
  CONTEXT_STRING,
  HASH_TO_GROUP_DST,
  HASH_TO_SCALAR_DST,
  DERIVE_KEY_PAIR_DST,
  P256_SHA256,
  P384_SHA384,
  P521_SHA512,
  getCipherSuite,
  type CipherSuite,
} from '../src/oprf/suite.js';
import { blind, finalize, deriveKeyPair } from '../src/oprf/client.js';
import { toHex, fromHex } from '../src/crypto/primitives.js';
import { strToBytes } from '../src/crypto/encoding.js';

// ── DST constants ────────────────────────────────────────────────────────────

describe('OPRF P-256/SHA-256 DST constants', () => {
  it('contextString matches RFC 9497 §4.1', () => {
    // "OPRFV1-" || 0x00 || "-P256-SHA256"
    // Verified against Java OprfVectorsTest.testP256Constants()
    expect(toHex(CONTEXT_STRING)).toBe('4f50524656312d002d503235362d534841323536');
  });

  it('HashToGroup DST matches', () => {
    // "HashToGroup-" + contextString
    expect(toHex(HASH_TO_GROUP_DST)).toBe(
      '48617368546f47726f75702d4f50524656312d002d503235362d534841323536'
    );
  });

  it('HashToScalar DST matches', () => {
    // "HashToScalar-" + contextString
    expect(toHex(HASH_TO_SCALAR_DST)).toBe(
      '48617368546f5363616c61722d4f50524656312d002d503235362d534841323536'
    );
  });

  it('DeriveKeyPair DST matches (no dash separator)', () => {
    // "DeriveKeyPair" + contextString — no dash between "DeriveKeyPair" and contextString
    expect(toHex(DERIVE_KEY_PAIR_DST)).toBe(
      '4465726976654b6579506169724f50524656312d002d503235362d534841323536'
    );
  });
});

// ── DeriveKeyPair ────────────────────────────────────────────────────────────

describe('OPRF deriveKeyPair', () => {
  it('RFC 9497 A.1.1: seed=0xa3x32, info="test key" → expected skS', () => {
    const seed = new Uint8Array(32).fill(0xa3);
    const info = strToBytes('test key');
    const sk = deriveKeyPair(seed, info);
    expect(sk.toString(16)).toBe(
      '159749d750713afe245d2d39ccfaae8381c53ce92d098a9375ee70739c7ac0bf'
    );
  });
});

// ── Blind / Evaluate / Finalize ───────────────────────────────────────────────

describe('OPRF Test Vector 1 (RFC 9497 A.1.1)', () => {
  // Input = 0x00
  const input = new Uint8Array([0x00]);
  // Blind scalar from RFC 9497 A.1.1
  const blindScalar = BigInt(
    '0x3338fa65ec36e0290022b48eb562889d89dbfa691d1cde91517fa222ed7ad364'
  );
  // Server private key
  const SK_S = BigInt('0x159749d750713afe245d2d39ccfaae8381c53ce92d098a9375ee70739c7ac0bf');

  it('blindedElement matches RFC 9497 A.1.1', () => {
    const { blind: r, blindedElement } = blind(input, blindScalar);
    expect(toHex(blindedElement)).toBe(
      '03723a1e5c09b8b9c18d1dcbca29e8007e95f14f4732d9346d490ffc195110368d'
    );
  });

  it('evaluatedElement (server-side scalar multiply) matches', () => {
    const { p256 } = require('@noble/curves/p256');
    const { blindedElement } = blind(input, blindScalar);

    // Server evaluates: skS * blindedElement
    const Z = p256.ProjectivePoint.fromHex(blindedElement);
    const evaluated = Z.multiply(SK_S).toRawBytes(true);
    expect(toHex(evaluated)).toBe(
      '030de02ffec47a1fd53efcdd1c6faf5bdc270912b8749e783c7ca75bb412958832'
    );
  });

  it('finalize output matches RFC 9497 A.1.1', () => {
    const { p256 } = require('@noble/curves/p256');
    const { blind: r, blindedElement } = blind(input, blindScalar);

    // Server evaluation
    const Z = p256.ProjectivePoint.fromHex(blindedElement);
    const evaluatedElement = Z.multiply(SK_S).toRawBytes(true);

    const output = finalize(input, r, evaluatedElement);
    expect(toHex(output)).toBe(
      'a0b34de5fa4c5b6da07e72af73cc507cceeb48981b97b7285fc375345fe495dd'
    );
  });
});

describe('OPRF Test Vector 2 (RFC 9497 A.1.1)', () => {
  // Input = 17 bytes of 0x5a
  const input = new Uint8Array(17).fill(0x5a);
  const blindScalar = BigInt(
    '0xe6d0f1d89ad552e859d708177054aca4695ef33b5d89d4d3f9a2c376e08a1450'
  );
  const SK_S = BigInt('0x159749d750713afe245d2d39ccfaae8381c53ce92d098a9375ee70739c7ac0bf');

  it('finalize output matches RFC 9497 A.1.1', () => {
    const { p256 } = require('@noble/curves/p256');
    const { blind: r, blindedElement } = blind(input, blindScalar);
    const Z = p256.ProjectivePoint.fromHex(blindedElement);
    const evaluatedElement = Z.multiply(SK_S).toRawBytes(true);
    const output = finalize(input, r, evaluatedElement);
    expect(toHex(output)).toBe(
      'c748ca6dd327f0ce85f4ae3a8cd6d4d5390bbb804c9e12dcf94f853fece3dcce'
    );
  });
});

// ── Multi-suite: constants ────────────────────────────────────────────────────

describe('P-384/SHA-384 suite constants', () => {
  it('contextString = "OPRFV1-\\x00-P384-SHA384"', () => {
    // "OPRFV1-" + 0x00 + "-P384-SHA384"
    expect(toHex(P384_SHA384.CONTEXT_STRING)).toBe('4f50524656312d002d503338342d534841333834');
  });

  it('HashToGroup DST has correct prefix', () => {
    // "HashToGroup-" + contextString
    const dst = toHex(P384_SHA384.HASH_TO_GROUP_DST);
    expect(dst.startsWith('48617368546f47726f75702d')).toBe(true); // "HashToGroup-"
    expect(dst.endsWith('4f50524656312d002d503338342d534841333834')).toBe(true);
  });

  it('DeriveKeyPair DST has no dash separator', () => {
    // "DeriveKeyPair" + contextString (no dash)
    const dst = toHex(P384_SHA384.DERIVE_KEY_PAIR_DST);
    expect(dst.startsWith('4465726976654b657950616972')).toBe(true); // "DeriveKeyPair"
  });

  it('size constants: Nh=48, Npk=49, Nsk=48, Nn=32, Nm=48, L=72', () => {
    expect(P384_SHA384.Nh).toBe(48);
    expect(P384_SHA384.Npk).toBe(49);
    expect(P384_SHA384.Nsk).toBe(48);
    expect(P384_SHA384.Nn).toBe(32);
    expect(P384_SHA384.Nm).toBe(48);
    expect(P384_SHA384.L).toBe(72);
  });
});

describe('P-521/SHA-512 suite constants', () => {
  it('contextString = "OPRFV1-\\x00-P521-SHA512"', () => {
    expect(toHex(P521_SHA512.CONTEXT_STRING)).toBe('4f50524656312d002d503532312d534841353132');
  });

  it('HashToGroup DST has correct prefix', () => {
    const dst = toHex(P521_SHA512.HASH_TO_GROUP_DST);
    expect(dst.startsWith('48617368546f47726f75702d')).toBe(true);
    expect(dst.endsWith('4f50524656312d002d503532312d534841353132')).toBe(true);
  });

  it('size constants: Nh=64, Npk=67, Nsk=66, Nn=32, Nm=64, L=98', () => {
    expect(P521_SHA512.Nh).toBe(64);
    expect(P521_SHA512.Npk).toBe(67);
    expect(P521_SHA512.Nsk).toBe(66);
    expect(P521_SHA512.Nn).toBe(32);
    expect(P521_SHA512.Nm).toBe(64);
    expect(P521_SHA512.L).toBe(98);
  });
});

// ── getCipherSuite() ─────────────────────────────────────────────────────────

describe('getCipherSuite()', () => {
  it('resolves P256_SHA256', () => {
    expect(getCipherSuite('P256_SHA256')).toBe(P256_SHA256);
  });

  it('resolves P384_SHA384', () => {
    expect(getCipherSuite('P384_SHA384')).toBe(P384_SHA384);
  });

  it('resolves P521_SHA512', () => {
    expect(getCipherSuite('P521_SHA512')).toBe(P521_SHA512);
  });

  it('throws for unknown suite name', () => {
    expect(() => getCipherSuite('P256_SHA512')).toThrow('Unknown cipher suite');
    expect(() => getCipherSuite('')).toThrow('Unknown cipher suite');
  });
});

// ── Per-suite OPRF round-trip consistency ────────────────────────────────────

/**
 * For each suite: blind → server-evaluate (scalar multiply) → finalize.
 * Verifies output length, determinism, and that a different input yields a different output.
 * Does not require hardcoded RFC vectors — just checks protocol consistency.
 */
function oprfRoundTrip(suite: CipherSuite): void {
  const input  = strToBytes('test-password');
  const input2 = strToBytes('different-password');

  // Use a fixed blind scalar so blind step is deterministic
  const blindScalar = suite.deriveKeyPair(
    new Uint8Array(suite.Nsk).fill(0xa3),
    strToBytes('test-blind'),
    suite.DERIVE_KEY_PAIR_DST,
  );
  // Use a fixed server key
  const serverSk = suite.deriveKeyPair(
    new Uint8Array(suite.Nsk).fill(0x42),
    strToBytes('test-server-key'),
    suite.DERIVE_KEY_PAIR_DST,
  );

  const { blind: r, blindedElement } = suite.blind(input, blindScalar);
  expect(blindedElement.length).toBe(suite.Npk);

  // Server evaluates: serverSk * blindedElement
  const evaluatedElement = suite.dhMultiply(blindedElement, serverSk);
  expect(evaluatedElement.length).toBe(suite.Npk);

  const output = suite.finalize(input, r, evaluatedElement);
  expect(output.length).toBe(suite.Nh);

  // Deterministic: same inputs → same output
  const output2 = suite.finalize(input, r, evaluatedElement);
  expect(toHex(output)).toBe(toHex(output2));

  // Different input → different output
  const { blind: r3, blindedElement: be3 } = suite.blind(input2, blindScalar);
  const evaluated3 = suite.dhMultiply(be3, serverSk);
  const output3 = suite.finalize(input2, r3, evaluated3);
  expect(toHex(output3)).not.toBe(toHex(output));
}

describe('OPRF round-trip per suite', () => {
  it('P-256/SHA-256', () => oprfRoundTrip(P256_SHA256));
  it('P-384/SHA-384', () => oprfRoundTrip(P384_SHA384));
  it('P-521/SHA-512', () => oprfRoundTrip(P521_SHA512));
});
