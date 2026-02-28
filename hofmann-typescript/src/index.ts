/**
 * hofmann-typescript — RFC 9497 (OPRF) and RFC 9807 (OPAQUE-3DH) browser client.
 *
 * Supports P-256/SHA-256, P-384/SHA-384, and P-521/SHA-512 cipher suites.
 * The cipher suite is negotiated automatically from the server's /opaque/config
 * or /oprf/config endpoint when using the HTTP client factories.
 */

// ── Crypto utilities ────────────────────────────────────────────────────────
export { i2osp, concat, xor, constantTimeEqual, fromHex, toHex } from './crypto/primitives.js';
export { base64Encode, base64Decode, strToBytes, bytesToStr } from './crypto/encoding.js';
export { hkdfExtract, hkdfExpand, hkdfExpandLabel } from './crypto/hkdf.js';

// ── OPRF cipher suites ───────────────────────────────────────────────────────
export type { CipherSuite } from './oprf/suite.js';
export {
  P256_SHA256,
  P384_SHA384,
  P521_SHA512,
  getCipherSuite,
  // Backward-compatible P-256 constant exports
  CONTEXT_STRING,
  HASH_TO_GROUP_DST,
  HASH_TO_SCALAR_DST,
  DERIVE_KEY_PAIR_DST,
  Nh, Npk, Nsk, Nn, Nm,
} from './oprf/suite.js';

// ── OPRF operations ──────────────────────────────────────────────────────────
export { randomScalar, blind, finalize, hashToScalar, deriveKeyPair } from './oprf/client.js';
export { OprfHttpClient } from './oprf/http.js';

// ── OPAQUE types ─────────────────────────────────────────────────────────────
export type {
  Envelope,
  ClientRegistrationState,
  RegistrationResponse,
  RegistrationRecord,
  ClientAuthState,
  KE1,
  KE2,
  AuthResult,
  RecoveredCredentials,
} from './opaque/types.js';

// ── OPAQUE crypto ─────────────────────────────────────────────────────────────
export {
  serializeEnvelope,
  deserializeEnvelope,
  deriveMaskingKey,
  storeEnvelope,
  recoverEnvelope,
} from './opaque/envelope.js';
export { buildPreamble, derive3DHKeys, verifyServerMac, computeClientMac } from './opaque/ake.js';
export { OpaqueClient, deriveRandomizedPwd, parseKE2 } from './opaque/client.js';
export { type KSF, identityKsf, argon2idKsf } from './opaque/ksf.js';
export { OpaqueHttpClient, type OpaqueHttpClientOptions, type OpaqueConfigResponseDto } from './opaque/http.js';
