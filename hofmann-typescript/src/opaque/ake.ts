/**
 * OPAQUE-3DH AKE (Authenticated Key Exchange) operations (RFC 9807 §3.3).
 *
 * DH points always use 33-byte compressed SEC1 encoding (.toRawBytes(true)).
 * Client MAC formula: HMAC(Km3, SHA256(preamble || serverMac))  — NOT concat of hashes.
 */
import { p256 } from '@noble/curves/p256';
import { sha256 } from '@noble/hashes/sha256';
import { hmac } from '@noble/hashes/hmac';
import { hkdfExtract, hkdfExpandLabel } from '../crypto/hkdf.js';
import { concat, i2osp, constantTimeEqual } from '../crypto/primitives.js';
import { strToBytes } from '../crypto/encoding.js';

/**
 * Build the OPAQUE-3DH preamble (RFC 9807 §3.3).
 *
 * preamble = "OPAQUEv1-"
 *          || I2OSP(len(context), 2) || context
 *          || I2OSP(len(clientId), 2) || clientId
 *          || ke1Bytes
 *          || I2OSP(len(serverId), 2) || serverId
 *          || credResponseBytes
 *          || serverNonce
 *          || serverAkePk
 */
export function buildPreamble(
  context: Uint8Array,
  clientId: Uint8Array,
  ke1Bytes: Uint8Array,
  serverId: Uint8Array,
  credResponseBytes: Uint8Array,
  serverNonce: Uint8Array,
  serverAkePk: Uint8Array
): Uint8Array {
  return concat(
    strToBytes('OPAQUEv1-'),
    i2osp(context.length, 2),
    context,
    i2osp(clientId.length, 2),
    clientId,
    ke1Bytes,
    i2osp(serverId.length, 2),
    serverId,
    credResponseBytes,
    serverNonce,
    serverAkePk
  );
}

/**
 * Derive 3DH shared keys (RFC 9807 §3.3.1).
 *
 * dh1 = serverAkePk * clientAkeSk   (ephemeral–ephemeral)
 * dh2 = serverPk   * clientAkeSk   (ephemeral–static)
 * dh3 = serverAkePk * clientSk     (static–ephemeral)
 * ikm = dh1 || dh2 || dh3          (each 33-byte compressed)
 *
 * prk             = HKDF-Extract([], ikm)
 * preambleHash    = SHA-256(preamble)
 * handshakeSecret = HKDF-Expand-Label(prk, "HandshakeSecret", preambleHash, 32)
 * sessionKey      = HKDF-Expand-Label(prk, "SessionKey",      preambleHash, 32)
 * km2             = HKDF-Expand-Label(handshakeSecret, "ServerMAC", [], 32)
 * km3             = HKDF-Expand-Label(handshakeSecret, "ClientMAC", [], 32)
 */
export function derive3DHKeys(
  clientAkeSk: bigint,
  clientSk: bigint,
  serverAkePk: Uint8Array,
  serverPk: Uint8Array,
  preamble: Uint8Array
): { km2: Uint8Array; km3: Uint8Array; sessionKey: Uint8Array } {
  const serverAkePkPoint = p256.ProjectivePoint.fromHex(serverAkePk);
  const serverPkPoint = p256.ProjectivePoint.fromHex(serverPk);

  // All DH results are 33-byte compressed points
  const dh1 = serverAkePkPoint.multiply(clientAkeSk).toRawBytes(true);
  const dh2 = serverPkPoint.multiply(clientAkeSk).toRawBytes(true);
  const dh3 = serverAkePkPoint.multiply(clientSk).toRawBytes(true);

  const ikm = concat(dh1, dh2, dh3);
  // HKDF-Extract with empty salt (undefined → RFC-correct zero-filled key)
  const prk = hkdfExtract(undefined, ikm);

  const preambleHash = sha256(preamble);
  const handshakeSecret = hkdfExpandLabel(prk, 'HandshakeSecret', preambleHash, 32);
  const sessionKey = hkdfExpandLabel(prk, 'SessionKey', preambleHash, 32);
  const km2 = hkdfExpandLabel(handshakeSecret, 'ServerMAC', new Uint8Array(0), 32);
  const km3 = hkdfExpandLabel(handshakeSecret, 'ClientMAC', new Uint8Array(0), 32);

  return { km2, km3, sessionKey };
}

/**
 * Verify the server MAC (constant-time).
 *
 * server_mac = HMAC(km2, SHA256(preamble))
 */
export function verifyServerMac(
  km2: Uint8Array,
  preamble: Uint8Array,
  serverMac: Uint8Array
): boolean {
  const expected = hmac(sha256, km2, sha256(preamble));
  return constantTimeEqual(expected, serverMac);
}

/**
 * Compute the client MAC.
 *
 * client_mac = HMAC(km3, SHA256(preamble || serverMac))
 *
 * Note: hash the concatenation, NOT concat the hashes.
 */
export function computeClientMac(
  km3: Uint8Array,
  preamble: Uint8Array,
  serverMac: Uint8Array
): Uint8Array {
  const hashInput = sha256(concat(preamble, serverMac));
  return hmac(sha256, km3, hashInput);
}
