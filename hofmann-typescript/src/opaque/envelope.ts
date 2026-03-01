/**
 * OPAQUE credential envelope: store and recovery (RFC 9807 §2.1.2).
 *
 * Envelope = { nonce (Nn=32 bytes), authTag (Nh bytes) }
 *
 * Key derivation (all from randomizedPwd via HKDF-Expand):
 *   maskingKey = Expand(randomizedPwd, "MaskingKey", Nh)
 *   authKey    = Expand(randomizedPwd, nonce || "AuthKey",    Nh)
 *   exportKey  = Expand(randomizedPwd, nonce || "ExportKey",  Nh)
 *   seed       = Expand(randomizedPwd, nonce || "PrivateKey", Nseed=32)  [RFC 9807 §4.1.2]
 *   (sk, pk)   = DeriveKeyPair(seed, "OPAQUE-DeriveDiffieHellmanKeyPair")
 *
 * authTag = HMAC(authKey, nonce || cleartext)
 * where cleartext = serverPk || I2OSP(len(serverId),2) || serverId
 *                 || I2OSP(len(clientId),2) || clientId
 * (null identities default to the respective public keys)
 *
 * All functions accept a CipherSuite so sizes are correct for P-256, P-384, P-521.
 */
import { concat, i2osp, constantTimeEqual } from '../crypto/primitives.js';
import { strToBytes } from '../crypto/encoding.js';
import { type CipherSuite, P256_SHA256 } from '../oprf/suite.js';
import type { Envelope } from './types.js';

const DERIVE_CLIENT_KEY_PAIR_INFO = strToBytes('OPAQUE-DeriveDiffieHellmanKeyPair');

/**
 * Serialize an envelope to bytes: nonce (Nn) || authTag (Nh).
 */
export function serializeEnvelope(env: Envelope): Uint8Array {
  return concat(env.nonce, env.authTag);
}

/**
 * Deserialize an envelope from bytes.
 * Expected length: Nn + Nh bytes (Nn=32 always; Nh is suite-specific).
 */
export function deserializeEnvelope(
  bytes: Uint8Array,
  suite: CipherSuite = P256_SHA256,
): Envelope {
  const expectedLen = suite.Nn + suite.Nh;
  if (bytes.length !== expectedLen) {
    throw new Error(`deserializeEnvelope: expected ${expectedLen} bytes (Nn=${suite.Nn}+Nh=${suite.Nh}), got ${bytes.length}`);
  }
  return {
    nonce:   bytes.slice(0, suite.Nn),
    authTag: bytes.slice(suite.Nn),
  };
}

/**
 * Derive the masking key from randomizedPwd (deterministic).
 * Output length = Nh bytes.
 */
export function deriveMaskingKey(
  randomizedPwd: Uint8Array,
  suite: CipherSuite = P256_SHA256,
): Uint8Array {
  return suite.hkdfExpand(randomizedPwd, strToBytes('MaskingKey'), suite.Nh);
}

/**
 * Store credentials into an envelope (registration step, RFC 9807 §3.3.1.1).
 *
 * @param randomizedPwd   Nh-byte output from OPRF + HKDF-Extract
 * @param serverPublicKey Npk-byte compressed server public key
 * @param serverIdentity  Server identity bytes. null → use serverPublicKey.
 * @param clientIdentity  Client identity bytes. null → use derived clientPublicKey.
 * @param nonce           Nn-byte nonce (random; provided for deterministic testing)
 * @param suite           Cipher suite (defaults to P-256/SHA-256).
 */
export function storeEnvelope(
  randomizedPwd: Uint8Array,
  serverPublicKey: Uint8Array,
  serverIdentity: Uint8Array | null,
  clientIdentity: Uint8Array | null,
  nonce: Uint8Array,
  suite: CipherSuite = P256_SHA256,
): { envelope: Envelope; clientPublicKey: Uint8Array; maskingKey: Uint8Array; exportKey: Uint8Array } {
  const { Nh, Nn } = suite;
  const maskingKey = suite.hkdfExpand(randomizedPwd, strToBytes('MaskingKey'), Nh);
  const authKey    = suite.hkdfExpand(randomizedPwd, concat(nonce, strToBytes('AuthKey')),    Nh);
  const exportKey  = suite.hkdfExpand(randomizedPwd, concat(nonce, strToBytes('ExportKey')),  Nh);
  // RFC 9807 §4.1.2: Nseed = 32 (= Nn), suite-independent constant
  const seed       = suite.hkdfExpand(randomizedPwd, concat(nonce, strToBytes('PrivateKey')), Nn);

  const sk = suite.deriveKeyPair(seed, DERIVE_CLIENT_KEY_PAIR_INFO, suite.DERIVE_KEY_PAIR_DST);
  const clientPublicKey = suite.getPublicKey(sk); // Npk bytes compressed

  // Resolve null identities: default to the respective public keys (CleartextCredentials.create)
  const servId   = serverIdentity ?? serverPublicKey;
  const clientId = clientIdentity ?? clientPublicKey;

  const cleartext = buildCleartext(serverPublicKey, servId, clientId);
  const authTag = suite.hmac(authKey, concat(nonce, cleartext));

  return { envelope: { nonce, authTag }, clientPublicKey, maskingKey, exportKey };
}

/**
 * Recover credentials from an envelope (authentication step, RFC 9807 §3.3.1.2).
 *
 * @param randomizedPwd   Nh-byte output from OPRF + HKDF-Extract
 * @param envelope        The envelope to recover
 * @param serverPublicKey Npk-byte compressed server public key (from credential response)
 * @param serverIdentity  Server identity bytes. null → use serverPublicKey.
 * @param clientIdentity  Client identity bytes. null → use derived clientPublicKey.
 * @param suite           Cipher suite (defaults to P-256/SHA-256).
 * @throws Error if the auth tag does not verify (constant-time check).
 */
export function recoverEnvelope(
  randomizedPwd: Uint8Array,
  envelope: Envelope,
  serverPublicKey: Uint8Array,
  serverIdentity: Uint8Array | null,
  clientIdentity: Uint8Array | null,
  suite: CipherSuite = P256_SHA256,
): { clientSecretKey: bigint; clientPublicKey: Uint8Array; exportKey: Uint8Array } {
  const { Nh, Nn } = suite;
  const { nonce, authTag } = envelope;

  const authKey   = suite.hkdfExpand(randomizedPwd, concat(nonce, strToBytes('AuthKey')),    Nh);
  const exportKey = suite.hkdfExpand(randomizedPwd, concat(nonce, strToBytes('ExportKey')),  Nh);
  // RFC 9807 §4.1.2: Nseed = 32 (= Nn), suite-independent constant
  const seed      = suite.hkdfExpand(randomizedPwd, concat(nonce, strToBytes('PrivateKey')), Nn);

  const sk = suite.deriveKeyPair(seed, DERIVE_CLIENT_KEY_PAIR_INFO, suite.DERIVE_KEY_PAIR_DST);
  const clientPublicKey = suite.getPublicKey(sk);

  // Resolve null identities
  const servId   = serverIdentity ?? serverPublicKey;
  const clientId = clientIdentity ?? clientPublicKey;

  // Verify auth tag (constant-time)
  const cleartext    = buildCleartext(serverPublicKey, servId, clientId);
  const expectedTag  = suite.hmac(authKey, concat(nonce, cleartext));
  if (!constantTimeEqual(expectedTag, authTag)) {
    throw new Error('recoverEnvelope: auth tag verification failed');
  }

  return { clientSecretKey: sk, clientPublicKey, exportKey };
}

/**
 * Build the HMAC cleartext (CleartextCredentials.serialize in Java):
 * serverPk || I2OSP(len(serverId), 2) || serverId
 *          || I2OSP(len(clientId), 2) || clientId
 */
function buildCleartext(
  serverPublicKey: Uint8Array,
  serverIdentity: Uint8Array,
  clientIdentity: Uint8Array,
): Uint8Array {
  return concat(
    serverPublicKey,
    i2osp(serverIdentity.length, 2),
    serverIdentity,
    i2osp(clientIdentity.length, 2),
    clientIdentity,
  );
}
