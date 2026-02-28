/**
 * OPAQUE credential envelope: store and recovery (RFC 9807 §2.1.2).
 *
 * Envelope = { nonce (32 bytes), authTag (32 bytes) }
 *
 * Key derivation (all from randomizedPwd via HKDF-Expand):
 *   maskingKey = Expand(randomizedPwd, "MaskingKey", 32)
 *   authKey    = Expand(randomizedPwd, nonce || "AuthKey",   32)
 *   exportKey  = Expand(randomizedPwd, nonce || "ExportKey", 32)
 *   seed       = Expand(randomizedPwd, nonce || "PrivateKey", 32)
 *   (sk, pk)   = DeriveKeyPair(seed, "OPAQUE-DeriveDiffieHellmanKeyPair")
 *
 * authTag = HMAC(authKey, nonce || cleartext)
 * where cleartext = serverPk || I2OSP(len(serverId),2) || serverId
 *                 || I2OSP(len(clientId),2) || clientId
 * (null identities default to the respective public keys)
 */
import { hmac } from '@noble/hashes/hmac';
import { sha256 } from '@noble/hashes/sha256';
import { p256 } from '@noble/curves/p256';
import { hkdfExpand } from '../crypto/hkdf.js';
import { concat, i2osp, constantTimeEqual, fromHex } from '../crypto/primitives.js';
import { strToBytes } from '../crypto/encoding.js';
import { deriveKeyPair } from '../oprf/client.js';
import { DERIVE_KEY_PAIR_DST } from '../oprf/suite.js';
import type { Envelope } from './types.js';

const DERIVE_CLIENT_KEY_PAIR_INFO = strToBytes('OPAQUE-DeriveDiffieHellmanKeyPair');

/**
 * Serialize an envelope to bytes: nonce (32) || authTag (32).
 */
export function serializeEnvelope(env: Envelope): Uint8Array {
  return concat(env.nonce, env.authTag);
}

/**
 * Deserialize an envelope from bytes (64 bytes total).
 */
export function deserializeEnvelope(bytes: Uint8Array): Envelope {
  if (bytes.length !== 64) {
    throw new Error(`deserializeEnvelope: expected 64 bytes, got ${bytes.length}`);
  }
  return {
    nonce: bytes.slice(0, 32),
    authTag: bytes.slice(32, 64),
  };
}

/**
 * Derive the masking key from randomizedPwd (deterministic).
 */
export function deriveMaskingKey(randomizedPwd: Uint8Array): Uint8Array {
  return hkdfExpand(randomizedPwd, strToBytes('MaskingKey'), 32);
}

/**
 * Store credentials into an envelope (registration step, RFC 9807 §3.3.1.1).
 *
 * @param randomizedPwd   32-byte output from OPRF + HKDF-Extract
 * @param serverPublicKey 33-byte compressed server public key
 * @param serverIdentity  Server identity bytes. null → use serverPublicKey.
 * @param clientIdentity  Client identity bytes. null → use derived clientPublicKey.
 * @param nonce           32-byte nonce (random; provided for deterministic testing)
 * @returns               envelope, derived client public key, masking key, and export key
 */
export function storeEnvelope(
  randomizedPwd: Uint8Array,
  serverPublicKey: Uint8Array,
  serverIdentity: Uint8Array | null,
  clientIdentity: Uint8Array | null,
  nonce: Uint8Array
): { envelope: Envelope; clientPublicKey: Uint8Array; maskingKey: Uint8Array; exportKey: Uint8Array } {
  const maskingKey = hkdfExpand(randomizedPwd, strToBytes('MaskingKey'), 32);
  const authKey = hkdfExpand(randomizedPwd, concat(nonce, strToBytes('AuthKey')), 32);
  const exportKey = hkdfExpand(randomizedPwd, concat(nonce, strToBytes('ExportKey')), 32);
  const seed = hkdfExpand(randomizedPwd, concat(nonce, strToBytes('PrivateKey')), 32);

  const sk = deriveKeyPair(seed, DERIVE_CLIENT_KEY_PAIR_INFO, DERIVE_KEY_PAIR_DST);
  const clientPublicKey = p256.getPublicKey(bigintToBytes32(sk), true); // 33-byte compressed

  // Resolve null identities: default to the respective public keys (CleartextCredentials.create)
  const servId = serverIdentity ?? serverPublicKey;
  const clientId = clientIdentity ?? clientPublicKey;

  const cleartext = buildCleartext(serverPublicKey, servId, clientId);
  const authTag = hmac(sha256, authKey, concat(nonce, cleartext));

  return { envelope: { nonce, authTag }, clientPublicKey, maskingKey, exportKey };
}

/**
 * Recover credentials from an envelope (authentication step, RFC 9807 §3.3.1.2).
 *
 * @param randomizedPwd   32-byte output from OPRF + HKDF-Extract
 * @param envelope        The envelope to recover
 * @param serverPublicKey 33-byte compressed server public key (from credential response)
 * @param serverIdentity  Server identity bytes. null → use serverPublicKey.
 * @param clientIdentity  Client identity bytes. null → use derived clientPublicKey.
 * @throws Error if the auth tag does not verify (constant-time check).
 */
export function recoverEnvelope(
  randomizedPwd: Uint8Array,
  envelope: Envelope,
  serverPublicKey: Uint8Array,
  serverIdentity: Uint8Array | null,
  clientIdentity: Uint8Array | null
): { clientSecretKey: bigint; clientPublicKey: Uint8Array; exportKey: Uint8Array } {
  const { nonce, authTag } = envelope;
  const authKey = hkdfExpand(randomizedPwd, concat(nonce, strToBytes('AuthKey')), 32);
  const exportKey = hkdfExpand(randomizedPwd, concat(nonce, strToBytes('ExportKey')), 32);
  const seed = hkdfExpand(randomizedPwd, concat(nonce, strToBytes('PrivateKey')), 32);

  const sk = deriveKeyPair(seed, DERIVE_CLIENT_KEY_PAIR_INFO, DERIVE_KEY_PAIR_DST);
  const clientPublicKey = p256.getPublicKey(bigintToBytes32(sk), true);

  // Resolve null identities
  const servId = serverIdentity ?? serverPublicKey;
  const clientId = clientIdentity ?? clientPublicKey;

  // Verify auth tag (constant-time)
  const cleartext = buildCleartext(serverPublicKey, servId, clientId);
  const expectedTag = hmac(sha256, authKey, concat(nonce, cleartext));
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
  clientIdentity: Uint8Array
): Uint8Array {
  return concat(
    serverPublicKey,
    i2osp(serverIdentity.length, 2),
    serverIdentity,
    i2osp(clientIdentity.length, 2),
    clientIdentity
  );
}

/** Convert bigint to 32-byte big-endian Uint8Array. */
function bigintToBytes32(n: bigint): Uint8Array {
  const hex = n.toString(16).padStart(64, '0');
  return fromHex(hex);
}
