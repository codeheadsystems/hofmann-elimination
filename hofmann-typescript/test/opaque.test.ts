/**
 * RFC 9807 OPAQUE-3DH test vectors — P-256/SHA-256.
 *
 * Source: CFRG OPAQUE reference vectors (Vector 1 = no identities, Vector 2 = with identities).
 * These match the Java OpaqueVectorsTest exactly.
 */
import { describe, it, expect } from 'vitest';
import { p256 } from '@noble/curves/p256';
import { sha256 } from '@noble/hashes/sha256';
import { hmac } from '@noble/hashes/hmac';

import { OpaqueClient, deriveRandomizedPwd } from '../src/opaque/client.js';
import { storeEnvelope, serializeEnvelope } from '../src/opaque/envelope.js';
import { buildPreamble, derive3DHKeys } from '../src/opaque/ake.js';
import { toHex, fromHex, concat } from '../src/crypto/primitives.js';
import { strToBytes } from '../src/crypto/encoding.js';
import { hkdfExpand, hkdfExtract, hkdfExpandLabel } from '../src/crypto/hkdf.js';
import { finalize, deriveKeyPair } from '../src/oprf/client.js';
import { DERIVE_KEY_PAIR_DST } from '../src/oprf/suite.js';
import { identityKsf } from '../src/opaque/ksf.js';
import type { KE2, RegistrationRecord, RegistrationResponse } from '../src/opaque/types.js';

// ── Shared test inputs ─────────────────────────────────────────────────────

// CFRG test context from OpaqueConfig.forTesting() = "OPAQUE-POC"
const CONTEXT     = strToBytes('OPAQUE-POC');
const PASSWORD    = fromHex('436f7272656374486f72736542617474657279537461706c65');
const CRED_ID     = fromHex('31323334');
const OPRF_SEED   = fromHex('62f60b286d20ce4fd1d64809b0021dad6ed5d52a2c8cf27ae6582543a0a8dce2');
const SERVER_SK   = fromHex('c36139381df63bfc91c850db0b9cfbec7a62e86d80040a41aa7725bf0e79d5e5');
const SERVER_PK   = fromHex('035f40ff9cf88aa1f5cd4fe5fd3da9ea65a4923a5594f84fd9f2092d6067784874');

const BLIND_REG  = BigInt('0x411bf1a62d119afe30df682b91a0a33d777972d4f2daa4b34ca527d597078153');
const ENV_NONCE  = fromHex('a921f2a014513bd8a90e477a629794e89fec12d12206dde662ebdcf65670e51f');

const BLIND_LOGIN         = BigInt('0xc497fddf6056d241e6cf9fb7ac37c384f49b357a221eb0a802c989b9942256c1');
const CLIENT_NONCE        = fromHex('ab3d33bde0e93eda72392346a7a73051110674bbf6b1b7ffab8be4f91fdaeeb1');
const CLIENT_AKE_SEED     = fromHex('633b875d74d1556d2a2789309972b06db21dfcc4f5ad51d7e74d783b7cfab8dc');
const MASKING_NONCE       = fromHex('38fe59af0df2c79f57b8780278f5ae47355fe1f817119041951c80f612fdfc6d');
const SERVER_NONCE        = fromHex('71cd9960ecef2fe0d0f7494986fa3d8b2bb01963537e60efb13981e138e3d4a1');
const SERVER_AKE_SEED     = fromHex('05a4f54206eef1ba2f615bc0aa285cb22f26d1153b5b40a1e85ff80da12f982f');

// Expected outputs (Vector 1 — no identities)
const EXPECTED_REG_REQUEST   = fromHex('029e949a29cfa0bf7c1287333d2fb3dc586c41aa652f5070d26a5315a1b50229f8');
const EXPECTED_RAND_PWD      = fromHex('06be0a1a51d56557a3adad57ba29c5510565dcd8b5078fa319151b9382258fb0');
const EXPECTED_REG_UPLOAD    = fromHex(
  '03b218507d978c3db570ca994aaf36695a731ddb2db272c817f79746fc37ae521' +
  '47f0ed53532d3ae8e505ecc70d42d2b814b6b0e48156def71ea029148b2803aaf' +
  'a921f2a014513bd8a90e477a629794e89fec12d12206dde662ebdcf65670e51f' +
  'ad30bbcfc1f8eda0211553ab9aaf26345ad59a128e80188f035fe4924fad67b8'
);
const EXPECTED_KE3           = fromHex('e97cab4433aa39d598e76f13e768bba61c682947bdcf9936035e8a3a3ebfb66e');
const EXPECTED_SESSION_KEY   = fromHex('484ad345715ccce138ca49e4ea362c6183f0949aaaa1125dc3bc3f80876e7cd1');
const EXPECTED_EXPORT_KEY    = fromHex('c3c9a1b0e33ac84dd83d0b7e8af6794e17e7a3caadff289fbd9dc769a853c64b');

// Vector 2 identities
const CLIENT_ID = fromHex('616c696365'); // "alice"
const SERVER_ID = fromHex('626f62');     // "bob"
const EXPECTED_REG_UPLOAD_V2 = fromHex(
  '03b218507d978c3db570ca994aaf36695a731ddb2db272c817f79746fc37ae521' +
  '47f0ed53532d3ae8e505ecc70d42d2b814b6b0e48156def71ea029148b2803aaf' +
  'a921f2a014513bd8a90e477a629794e89fec12d12206dde662ebdcf65670e51f' +
  '4d7773a36a208a866301dbb2858e40dc5638017527cf91aef32d3848eebe0971'
);

// ── Server simulation helpers ───────────────────────────────────────────────

/**
 * Server OPRF key derivation: deriveOprfKey(oprfSeed, credId).
 *
 * Java: seed = hkdfExpand(oprfSeed, credId || "OprfKey", Nsk)
 *       key  = deriveKeyPair(seed, "OPAQUE-DeriveKeyPair")
 */
function serverDeriveOprfKey(credId: Uint8Array): bigint {
  const info = concat(credId, strToBytes('OprfKey'));
  const seed = hkdfExpand(OPRF_SEED, info, 32);
  return deriveKeyPair(seed, strToBytes('OPAQUE-DeriveKeyPair'), DERIVE_KEY_PAIR_DST);
}

/** Server evaluates the OPRF: oprfKey * blindedElement. */
function serverEvaluate(blindedElement: Uint8Array, credId: Uint8Array): Uint8Array {
  const oprfKey = serverDeriveOprfKey(credId);
  return p256.ProjectivePoint.fromHex(blindedElement).multiply(oprfKey).toRawBytes(true);
}

/** Build a RegistrationResponse from the server. */
function serverRegistrationResponse(blindedElement: Uint8Array): RegistrationResponse {
  return {
    evaluatedElement: serverEvaluate(blindedElement, CRED_ID),
    serverPublicKey: SERVER_PK,
  };
}

/** Build the masked credential response for KE2. */
function serverBuildMaskedResponse(record: RegistrationRecord): Uint8Array {
  const padInfo = concat(MASKING_NONCE, strToBytes('CredentialResponsePad'));
  const pad = hkdfExpand(record.maskingKey, padInfo, 97); // Npk(33) + 64
  const plaintext = concat(SERVER_PK, record.envelope.nonce, record.envelope.authTag);
  const result = new Uint8Array(97);
  for (let i = 0; i < 97; i++) result[i] = pad[i] ^ plaintext[i];
  return result;
}

/** Convert bytes to bigint (big-endian). */
function bytesToBigint(bytes: Uint8Array): bigint {
  let result = 0n;
  for (const b of bytes) result = (result << 8n) | BigInt(b);
  return result;
}

/**
 * Build the server's KE2 response deterministically.
 *
 * Uses MASKING_NONCE, SERVER_NONCE, SERVER_AKE_SEED from the test constants.
 * clientPublicKey from the record determines the client identity (null→clientPk).
 */
function serverBuildKE2(
  record: RegistrationRecord,
  clientAkePk: Uint8Array,
  blindedElement: Uint8Array,
  ke1Bytes: Uint8Array
): KE2 {
  const evaluatedElement = serverEvaluate(blindedElement, CRED_ID);
  const maskedResponse   = serverBuildMaskedResponse(record);

  // Server AKE key pair — derived via DeriveAkeKeyPair(seed) = deriveKeyPair(seed, "OPAQUE-DeriveDiffieHellmanKeyPair")
  const DERIVE_AKE_INFO = strToBytes('OPAQUE-DeriveDiffieHellmanKeyPair');
  const serverAkeSk = deriveKeyPair(SERVER_AKE_SEED, DERIVE_AKE_INFO, DERIVE_KEY_PAIR_DST);
  const serverAkePkBytes = serverAkeSk.toString(16).padStart(64, '0');
  const serverAkePk = p256.getPublicKey(fromHex(serverAkePkBytes), true);
  const serverSkScalar = bytesToBigint(SERVER_SK);

  // Resolve identities (null → public keys)
  const cId = record.clientPublicKey;  // client identity defaults to clientPublicKey
  const sId = SERVER_PK;              // server identity defaults to serverPublicKey

  // Build preamble
  const credResponseBytes = concat(evaluatedElement, MASKING_NONCE, maskedResponse);
  const preamble = buildPreamble(
    CONTEXT, // "OPAQUE-POC" matches OpaqueConfig.forTesting()
    cId,
    ke1Bytes,
    sId,
    credResponseBytes,
    SERVER_NONCE,
    serverAkePk
  );

  // 3DH: server side
  // dh1 = clientAkePk * serverAkeSk
  // dh2 = clientAkePk * serverSk
  // dh3 = clientLongTermPk * serverAkeSk
  const clientAkePkPt = p256.ProjectivePoint.fromHex(clientAkePk);
  const clientLtPkPt  = p256.ProjectivePoint.fromHex(record.clientPublicKey);
  const dh1 = clientAkePkPt.multiply(serverAkeSk).toRawBytes(true);
  const dh2 = clientAkePkPt.multiply(serverSkScalar).toRawBytes(true);
  const dh3 = clientLtPkPt.multiply(serverAkeSk).toRawBytes(true);
  const ikm  = concat(dh1, dh2, dh3);

  const prk             = hkdfExtract(undefined, ikm);
  const preambleHash    = sha256(preamble);
  const handshakeSecret = hkdfExpandLabel(prk, 'HandshakeSecret', preambleHash, 32);
  const km2             = hkdfExpandLabel(handshakeSecret, 'ServerMAC', new Uint8Array(0), 32);
  const serverMac       = hmac(sha256, km2, preambleHash);

  return {
    evaluatedElement,
    maskingNonce:    MASKING_NONCE,
    maskedResponse,
    serverNonce:     SERVER_NONCE,
    serverAkePublicKey: serverAkePk,
    serverMac,
  };
}

// suppress unused import warning — storeEnvelope and derive3DHKeys are used by helpers above
void (storeEnvelope as unknown);
void (derive3DHKeys as unknown);

// ── Registration tests ─────────────────────────────────────────────────────

describe('OPAQUE Vector 1: Registration (no explicit identities)', () => {
  const client = new OpaqueClient();

  it('blindedElement matches expected registration request', () => {
    const state = client.createRegistrationRequestDeterministic(PASSWORD, BLIND_REG);
    expect(toHex(state.blindedElement)).toBe(toHex(EXPECTED_REG_REQUEST));
  });

  it('randomizedPwd matches expected intermediate value', async () => {
    const state    = client.createRegistrationRequestDeterministic(PASSWORD, BLIND_REG);
    const response = serverRegistrationResponse(state.blindedElement);
    const oprfOutput    = finalize(PASSWORD, BLIND_REG, response.evaluatedElement);
    const randomizedPwd = await deriveRandomizedPwd(oprfOutput, identityKsf);
    expect(toHex(randomizedPwd)).toBe(toHex(EXPECTED_RAND_PWD));
  });

  it('registration record (clientPk || maskingKey || nonce || authTag) matches', async () => {
    const state    = client.createRegistrationRequestDeterministic(PASSWORD, BLIND_REG);
    const response = serverRegistrationResponse(state.blindedElement);
    const record   = await client.finalizeRegistration(state, response, null, null, ENV_NONCE);
    const actual   = concat(record.clientPublicKey, record.maskingKey, serializeEnvelope(record.envelope));
    expect(toHex(actual)).toBe(toHex(EXPECTED_REG_UPLOAD));
  });
});

describe('OPAQUE Vector 2: Registration (with explicit identities alice/bob)', () => {
  const client = new OpaqueClient();

  it('registration record matches (different authTag due to identity binding)', async () => {
    const state    = client.createRegistrationRequestDeterministic(PASSWORD, BLIND_REG);
    const response = serverRegistrationResponse(state.blindedElement);
    const record   = await client.finalizeRegistration(state, response, SERVER_ID, CLIENT_ID, ENV_NONCE);
    const actual   = concat(record.clientPublicKey, record.maskingKey, serializeEnvelope(record.envelope));
    expect(toHex(actual)).toBe(toHex(EXPECTED_REG_UPLOAD_V2));
  });
});

// ── AKE tests ──────────────────────────────────────────────────────────────

// Intermediate values from RFC 9807 CFRG test vectors
const EXPECTED_KE1 = fromHex(
  '037342f0bcb3ecea754c1e67576c86aa90c1de3875f390ad599a26686cdfee6e07' +
  'ab3d33bde0e93eda72392346a7a73051110674bbf6b1b7ffab8be4f91fdaeeb1' +
  '022ed3f32f318f81bab80da321fecab3cd9b6eea11a95666dfa6beeaab321280b6'
);
const EXPECTED_SERVER_AKE_PK = fromHex('03c1701353219b53acf337bf6456a83cefed8f563f1040b65afbf3b65d3bc9a19b');
const EXPECTED_SERVER_MAC    = fromHex('50a73b145bc87a157e8c58c0342e2047ee22ae37b63db17e0a82a30fcc4ecf7b');

describe('OPAQUE AKE intermediate verification', () => {
  const client = new OpaqueClient();

  it('KE1 wire bytes match RFC 9807 vector', () => {
    const { state } = client.generateKE1Deterministic(PASSWORD, BLIND_LOGIN, CLIENT_NONCE, CLIENT_AKE_SEED);
    expect(toHex(state.ke1Bytes)).toBe(toHex(EXPECTED_KE1));
  });

  it('server AKE key pair derivation matches', () => {
    const DERIVE_AKE_INFO = strToBytes('OPAQUE-DeriveDiffieHellmanKeyPair');
    const serverAkeSk = deriveKeyPair(SERVER_AKE_SEED, DERIVE_AKE_INFO, DERIVE_KEY_PAIR_DST);
    const serverAkePk = p256.getPublicKey(fromHex(serverAkeSk.toString(16).padStart(64, '0')), true);
    expect(toHex(serverAkePk)).toBe(toHex(EXPECTED_SERVER_AKE_PK));
  });

  it('server MAC in KE2 matches', async () => {
    const regState = client.createRegistrationRequestDeterministic(PASSWORD, BLIND_REG);
    const regResp  = serverRegistrationResponse(regState.blindedElement);
    const record   = await client.finalizeRegistration(regState, regResp, null, null, ENV_NONCE);
    const { state } = client.generateKE1Deterministic(PASSWORD, BLIND_LOGIN, CLIENT_NONCE, CLIENT_AKE_SEED);
    const ke2 = serverBuildKE2(record, state.clientAkePublicKey, state.blindedElement, state.ke1Bytes);
    expect(toHex(ke2.serverAkePublicKey)).toBe(toHex(EXPECTED_SERVER_AKE_PK));
    expect(toHex(ke2.serverMac)).toBe(toHex(EXPECTED_SERVER_MAC));
  });
});

describe('OPAQUE Vector 1: Full AKE (no explicit identities)', () => {
  const client = new OpaqueClient();

  it('clientMac (KE3), sessionKey, and exportKey all match RFC vectors', async () => {
    // Registration
    const regState  = client.createRegistrationRequestDeterministic(PASSWORD, BLIND_REG);
    const regResp   = serverRegistrationResponse(regState.blindedElement);
    const record    = await client.finalizeRegistration(regState, regResp, null, null, ENV_NONCE);

    // KE1
    const { state } = client.generateKE1Deterministic(PASSWORD, BLIND_LOGIN, CLIENT_NONCE, CLIENT_AKE_SEED);

    // Build server KE2
    const ke2 = serverBuildKE2(record, state.clientAkePublicKey, state.blindedElement, state.ke1Bytes);

    // KE3 — pass context = "OPAQUE-POC" matching Java's OpaqueConfig.forTesting()
    const authResult = await client.generateKE3(state, ke2, null, null, CONTEXT);

    expect(toHex(authResult.clientMac)).toBe(toHex(EXPECTED_KE3));
    expect(toHex(authResult.sessionKey)).toBe(toHex(EXPECTED_SESSION_KEY));
    expect(toHex(authResult.exportKey)).toBe(toHex(EXPECTED_EXPORT_KEY));
  });
});
