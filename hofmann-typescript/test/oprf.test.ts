/**
 * RFC 9497 OPRF test vectors — P-256/SHA-256 (Appendix A.1.1).
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
