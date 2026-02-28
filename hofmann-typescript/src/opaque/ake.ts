/**
 * OPAQUE-3DH AKE (Authenticated Key Exchange) operations (RFC 9807 §3.3).
 *
 * DH points always use compressed SEC1 encoding (.toRawBytes(true)).
 * Client MAC formula: HMAC(Km3, Hash(preamble || serverMac)) — NOT concat of hashes.
 *
 * All functions accept a CipherSuite so they work with P-256, P-384, and P-521.
 */
import { concat, i2osp, constantTimeEqual } from '../crypto/primitives.js';
import { strToBytes } from '../crypto/encoding.js';
import { type CipherSuite, P256_SHA256 } from '../oprf/suite.js';

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
  serverAkePk: Uint8Array,
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
    serverAkePk,
  );
}

/**
 * Derive 3DH shared keys (RFC 9807 §3.3.1).
 *
 * dh1 = serverAkePk * clientAkeSk   (ephemeral–ephemeral)
 * dh2 = serverPk   * clientAkeSk   (ephemeral–static)
 * dh3 = serverAkePk * clientSk     (static–ephemeral)
 * ikm = dh1 || dh2 || dh3          (each Npk bytes compressed)
 *
 * prk             = HKDF-Extract([], ikm)
 * preambleHash    = Hash(preamble)
 * handshakeSecret = HKDF-Expand-Label(prk, "HandshakeSecret", preambleHash, Nh)
 * sessionKey      = HKDF-Expand-Label(prk, "SessionKey",      preambleHash, Nh)
 * km2             = HKDF-Expand-Label(handshakeSecret, "ServerMAC", [], Nh)
 * km3             = HKDF-Expand-Label(handshakeSecret, "ClientMAC", [], Nh)
 */
export function derive3DHKeys(
  clientAkeSk: bigint,
  clientSk: bigint,
  serverAkePk: Uint8Array,
  serverPk: Uint8Array,
  preamble: Uint8Array,
  suite: CipherSuite = P256_SHA256,
): { km2: Uint8Array; km3: Uint8Array; sessionKey: Uint8Array } {
  // All DH results are Npk-byte compressed points
  const dh1 = suite.dhMultiply(serverAkePk, clientAkeSk);
  const dh2 = suite.dhMultiply(serverPk,    clientAkeSk);
  const dh3 = suite.dhMultiply(serverAkePk, clientSk);

  const ikm = concat(dh1, dh2, dh3);
  const prk = suite.hkdfExtract(undefined, ikm);

  const preambleHash = suite.hash(preamble);
  const handshakeSecret = suite.hkdfExpandLabel(prk, 'HandshakeSecret', preambleHash, suite.Nh);
  const sessionKey      = suite.hkdfExpandLabel(prk, 'SessionKey',      preambleHash, suite.Nh);
  const km2 = suite.hkdfExpandLabel(handshakeSecret, 'ServerMAC', new Uint8Array(0), suite.Nh);
  const km3 = suite.hkdfExpandLabel(handshakeSecret, 'ClientMAC', new Uint8Array(0), suite.Nh);

  return { km2, km3, sessionKey };
}

/**
 * Verify the server MAC (constant-time).
 *
 * server_mac = HMAC(km2, Hash(preamble))
 */
export function verifyServerMac(
  km2: Uint8Array,
  preamble: Uint8Array,
  serverMac: Uint8Array,
  suite: CipherSuite = P256_SHA256,
): boolean {
  const expected = suite.hmac(km2, suite.hash(preamble));
  return constantTimeEqual(expected, serverMac);
}

/**
 * Compute the client MAC.
 *
 * client_mac = HMAC(km3, Hash(preamble || serverMac))
 *
 * Note: hash the concatenation, NOT concat the hashes.
 */
export function computeClientMac(
  km3: Uint8Array,
  preamble: Uint8Array,
  serverMac: Uint8Array,
  suite: CipherSuite = P256_SHA256,
): Uint8Array {
  const hashInput = suite.hash(concat(preamble, serverMac));
  return suite.hmac(km3, hashInput);
}
