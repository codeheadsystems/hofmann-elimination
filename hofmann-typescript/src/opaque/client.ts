/**
 * OPAQUE-3DH client (RFC 9807).
 * P-256/SHA-256 cipher suite. KSF is pluggable (default: identity, no stretching).
 */
import { p256 } from '@noble/curves/p256';
import { hkdfExtract, hkdfExpand } from '../crypto/hkdf.js';
import { concat, xor, fromHex } from '../crypto/primitives.js';
import { strToBytes } from '../crypto/encoding.js';
import { blind, finalize, deriveKeyPair } from '../oprf/client.js';
import { Npk, Nn, DERIVE_KEY_PAIR_DST } from '../oprf/suite.js';
import { storeEnvelope, recoverEnvelope, deriveMaskingKey, deserializeEnvelope } from './envelope.js';
import { buildPreamble, derive3DHKeys, verifyServerMac, computeClientMac } from './ake.js';
import { type KSF, identityKsf } from './ksf.js';
import type {
  ClientRegistrationState,
  RegistrationResponse,
  RegistrationRecord,
  ClientAuthState,
  KE2,
  AuthResult,
} from './types.js';

/**
 * Public OPAQUE client.
 */
export class OpaqueClient {
  /**
   * Step 1a: Create a registration request (random blind).
   */
  createRegistrationRequest(password: Uint8Array): ClientRegistrationState {
    const { blind: r, blindedElement } = blind(password);
    return { password, blind: r, blindedElement };
  }

  /**
   * Step 1a (deterministic): Create a registration request with a fixed blind scalar.
   * Use for testing with RFC test vectors.
   */
  createRegistrationRequestDeterministic(
    password: Uint8Array,
    fixedBlind: bigint
  ): ClientRegistrationState {
    const { blind: r, blindedElement } = blind(password, fixedBlind);
    return { password, blind: r, blindedElement };
  }

  /**
   * Step 1c: Finalize registration.
   * Returns the RegistrationRecord to upload to the server.
   *
   * @param state           State from createRegistrationRequest
   * @param response        RegistrationResponse from server
   * @param serverIdentity  Server identity (null → use serverPublicKey)
   * @param clientIdentity  Client identity (null → use derived clientPublicKey)
   * @param envelopeNonce   32-byte nonce for testing; random if omitted
   * @param ksf             Key stretching function (default: identity)
   */
  async finalizeRegistration(
    state: ClientRegistrationState,
    response: RegistrationResponse,
    serverIdentity?: Uint8Array | null,
    clientIdentity?: Uint8Array | null,
    envelopeNonce?: Uint8Array,
    ksf?: KSF
  ): Promise<RegistrationRecord> {
    const nonce = envelopeNonce ?? crypto.getRandomValues(new Uint8Array(Nn));
    const oprfOutput = finalize(state.password, state.blind, response.evaluatedElement);
    const randomizedPwd = await deriveRandomizedPwd(oprfOutput, ksf ?? identityKsf);

    const { envelope, clientPublicKey, maskingKey } = storeEnvelope(
      randomizedPwd,
      response.serverPublicKey,
      serverIdentity ?? null,
      clientIdentity ?? null,
      nonce
    );

    return { clientPublicKey, maskingKey, envelope };
  }

  /**
   * Step 2a: Generate KE1 (start authentication, random nonces).
   * Uses 32 random bytes as the AKE seed for DeriveAkeKeyPair.
   */
  generateKE1(password: Uint8Array): { state: ClientAuthState; ke1Bytes: Uint8Array } {
    const clientNonce   = crypto.getRandomValues(new Uint8Array(Nn));
    const clientAkeSeed = crypto.getRandomValues(new Uint8Array(Nn));
    return this._generateKE1Inner(password, undefined, clientNonce, clientAkeSeed);
  }

  /**
   * Step 2a (deterministic): Generate KE1 with fixed blind + AKE inputs.
   * Use for testing with RFC test vectors.
   */
  generateKE1Deterministic(
    password: Uint8Array,
    fixedBlind: bigint,
    clientNonce: Uint8Array,
    clientAkeSeed: Uint8Array
  ): { state: ClientAuthState; ke1Bytes: Uint8Array } {
    return this._generateKE1Inner(password, fixedBlind, clientNonce, clientAkeSeed);
  }

  private _generateKE1Inner(
    password: Uint8Array,
    fixedBlind: bigint | undefined,
    clientNonce: Uint8Array,
    clientAkeSeed: Uint8Array
  ): { state: ClientAuthState; ke1Bytes: Uint8Array } {
    const { blind: r, blindedElement } = blind(password, fixedBlind);
    // AKE key derived via deriveKeyPair(seed, "OPAQUE-DeriveDiffieHellmanKeyPair")
    // matching Java OpaqueCipherSuite.deriveAkeKeyPair(seed)
    const DERIVE_AKE_INFO = strToBytes('OPAQUE-DeriveDiffieHellmanKeyPair');
    const clientAkeSk = deriveKeyPair(clientAkeSeed, DERIVE_AKE_INFO, DERIVE_KEY_PAIR_DST);
    const clientAkePk = p256.getPublicKey(fromHex(clientAkeSk.toString(16).padStart(64, '0')), true);

    // KE1 = blindedElement (33) || clientNonce (32) || clientAkePk (33) = 98 bytes
    const ke1Bytes = concat(blindedElement, clientNonce, clientAkePk);

    const state: ClientAuthState = {
      password,
      blind: r,
      blindedElement,
      clientAkeSecretKey: clientAkeSk,
      clientAkePublicKey: clientAkePk,
      clientNonce,
      ke1Bytes,
    };
    return { state, ke1Bytes };
  }

  /**
   * Step 2c: Process KE2 and produce KE3 + session key.
   *
   * @param state          State from generateKE1
   * @param ke2            Parsed KE2 message from server
   * @param clientIdentity Client identity (null → use derived clientPublicKey)
   * @param serverIdentity Server identity (null → use serverPublicKey from credential response)
   * @param context        Application context (empty if none)
   * @param ksf            Key stretching function (default: identity)
   */
  async generateKE3(
    state: ClientAuthState,
    ke2: KE2,
    clientIdentity?: Uint8Array | null,
    serverIdentity?: Uint8Array | null,
    context?: Uint8Array,
    ksf?: KSF
  ): Promise<AuthResult> {
    const ctx = context ?? new Uint8Array(0);

    // 1. Finalize OPRF
    const oprfOutput = finalize(state.password, state.blind, ke2.evaluatedElement);
    const randomizedPwd = await deriveRandomizedPwd(oprfOutput, ksf ?? identityKsf);

    // 2. Unmask credential response
    const maskingKey = deriveMaskingKey(randomizedPwd);
    const pad = deriveMaskingPad(maskingKey, ke2.maskingNonce);
    const unmasked = xor(ke2.maskedResponse, pad);

    // unmasked = serverPublicKey (Npk=33) || envelope (64 = nonce 32 + authTag 32)
    const serverPublicKey = unmasked.slice(0, Npk);
    const envelope = deserializeEnvelope(unmasked.slice(Npk));

    // 3. Recover credentials from envelope (null identities default to public keys inside)
    const { clientSecretKey, clientPublicKey, exportKey } = recoverEnvelope(
      randomizedPwd,
      envelope,
      serverPublicKey,
      serverIdentity ?? null,
      clientIdentity ?? null
    );

    // Resolve identities for preamble (same defaulting as CleartextCredentials)
    const finalClientId = clientIdentity ?? clientPublicKey;
    const finalServerId = serverIdentity ?? serverPublicKey;

    // 4. Build preamble
    // credResponseBytes = evaluatedElement (33) || maskingNonce (32) || maskedResponse (97)
    const credResponseBytes = concat(ke2.evaluatedElement, ke2.maskingNonce, ke2.maskedResponse);
    const preamble = buildPreamble(
      ctx,
      finalClientId,
      state.ke1Bytes,
      finalServerId,
      credResponseBytes,
      ke2.serverNonce,
      ke2.serverAkePublicKey
    );

    // 5. Derive 3DH keys
    const { km2, km3, sessionKey } = derive3DHKeys(
      state.clientAkeSecretKey,
      clientSecretKey,
      ke2.serverAkePublicKey,
      serverPublicKey,
      preamble
    );

    // 6. Verify server MAC
    if (!verifyServerMac(km2, preamble, ke2.serverMac)) {
      throw new Error('generateKE3: server MAC verification failed');
    }

    // 7. Compute client MAC (= KE3 message sent to server)
    const clientMac = computeClientMac(km3, preamble, ke2.serverMac);

    return { clientMac, sessionKey, exportKey };
  }
}

// ── Module-level helpers ────────────────────────────────────────────────────

/**
 * Derive randomizedPwd from OPRF output using the given KSF.
 *
 * randomizedPwd = HKDF-Extract("", oprfOutput || stretchedOprfOutput)
 *
 * With identity KSF: stretchedOprfOutput = oprfOutput (no key stretching).
 * With Argon2id KSF: stretchedOprfOutput = Argon2id(oprfOutput, salt=zeros(32), ...).
 * Empty salt → noble uses HashLen zeros per RFC 5869.
 */
export async function deriveRandomizedPwd(oprfOutput: Uint8Array, ksf: KSF = identityKsf): Promise<Uint8Array> {
  const stretchedOprfOutput = await ksf(oprfOutput);
  return hkdfExtract(undefined, concat(oprfOutput, stretchedOprfOutput));
}

/**
 * Derive the masking pad for XOR-unmasking the credential response.
 *
 * pad = HKDF-Expand(maskingKey, maskingNonce || "CredentialResponsePad", Npk + 64)
 *
 * Npk = 33, envelope = 64 bytes (nonce 32 + authTag 32) → pad length = 97.
 */
function deriveMaskingPad(maskingKey: Uint8Array, maskingNonce: Uint8Array): Uint8Array {
  const info = concat(maskingNonce, strToBytes('CredentialResponsePad'));
  return hkdfExpand(maskingKey, info, Npk + 64); // 33 + 64 = 97
}

/**
 * Parse a 259-byte KE2 wire format into its component fields.
 *
 * KE2 wire layout:
 *   evaluatedElement  (33) = OPRF evaluated element
 *   maskingNonce      (32) = nonce for credential response masking
 *   maskedResponse    (97) = serverPk(33) || nonce(32) || authTag(32), XOR-masked
 *   serverNonce       (32) = server AKE ephemeral nonce
 *   serverAkePublicKey(33) = server ephemeral AKE public key
 *   serverMac         (32) = server authentication MAC
 * Total: 33 + 32 + 97 + 32 + 33 + 32 = 259 bytes
 */
export function parseKE2(bytes: Uint8Array): KE2 {
  if (bytes.length !== 259) {
    throw new Error(`parseKE2: expected 259 bytes, got ${bytes.length}`);
  }
  let o = 0;
  const evaluatedElement = bytes.slice(o, o + 33); o += 33;
  const maskingNonce = bytes.slice(o, o + 32); o += 32;
  const maskedResponse = bytes.slice(o, o + 97); o += 97;
  const serverNonce = bytes.slice(o, o + 32); o += 32;
  const serverAkePublicKey = bytes.slice(o, o + 33); o += 33;
  const serverMac = bytes.slice(o, o + 32);

  return { evaluatedElement, maskingNonce, maskedResponse, serverNonce, serverAkePublicKey, serverMac };
}
