/**
 * hofmann-typescript — RFC 9497 (OPRF) and RFC 9807 (OPAQUE-3DH) browser client.
 *
 * P-256/SHA-256 cipher suite only.
 */

// ── Crypto utilities ────────────────────────────────────────────────────────
export { i2osp, concat, xor, constantTimeEqual, fromHex, toHex } from './crypto/primitives.js';
export { base64Encode, base64Decode, strToBytes, bytesToStr } from './crypto/encoding.js';
export { hkdfExtract, hkdfExpand, hkdfExpandLabel } from './crypto/hkdf.js';

// ── OPRF ────────────────────────────────────────────────────────────────────
export {
  CONTEXT_STRING,
  HASH_TO_GROUP_DST,
  HASH_TO_SCALAR_DST,
  DERIVE_KEY_PAIR_DST,
  Nh, Npk, Nsk, Nn, Nm,
} from './oprf/suite.js';
export { randomScalar, blind, finalize, hashToScalar, deriveKeyPair } from './oprf/client.js';
export { OprfHttpClient } from './oprf/http.js';

// ── OPAQUE ───────────────────────────────────────────────────────────────────
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
export { OpaqueHttpClient, type OpaqueHttpClientOptions } from './opaque/http.js';
