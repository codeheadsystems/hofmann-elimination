/**
 * OPAQUE-3DH client (RFC 9807).
 * Supports P-256/SHA-256, P-384/SHA-384, and P-521/SHA-512 cipher suites.
 * KSF is pluggable (default: identity, no stretching).
 */
import { concat, xor } from '../crypto/primitives.js';
import { strToBytes } from '../crypto/encoding.js';
import { type CipherSuite, P256_SHA256 } from '../oprf/suite.js';
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
 * Public OPAQUE client. Construct with a CipherSuite to use P-384 or P-521;
 * defaults to P-256/SHA-256 for backward compatibility.
 */
export class OpaqueClient {
  constructor(private readonly suite: CipherSuite = P256_SHA256) {}

  /**
   * Step 1a: Create a registration request (random blind).
   */
  createRegistrationRequest(password: Uint8Array): ClientRegistrationState {
    const { blind: r, blindedElement } = this.suite.blind(password);
    return { password, blind: r, blindedElement };
  }

  /**
   * Step 1a (deterministic): Create a registration request with a fixed blind scalar.
   * Use for testing with RFC test vectors.
   */
  createRegistrationRequestDeterministic(
    password: Uint8Array,
    fixedBlind: bigint,
  ): ClientRegistrationState {
    const { blind: r, blindedElement } = this.suite.blind(password, fixedBlind);
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
   * @param envelopeNonce   Nn-byte nonce for testing; random if omitted
   * @param ksf             Key stretching function (default: identity)
   */
  async finalizeRegistration(
    state: ClientRegistrationState,
    response: RegistrationResponse,
    serverIdentity?: Uint8Array | null,
    clientIdentity?: Uint8Array | null,
    envelopeNonce?: Uint8Array,
    ksf?: KSF,
  ): Promise<RegistrationRecord> {
    const nonce = envelopeNonce ?? crypto.getRandomValues(new Uint8Array(this.suite.Nn));
    const oprfOutput = this.suite.finalize(state.password, state.blind, response.evaluatedElement);
    const randomizedPwd = await deriveRandomizedPwd(oprfOutput, ksf ?? identityKsf, this.suite);

    const { envelope, clientPublicKey, maskingKey } = storeEnvelope(
      randomizedPwd,
      response.serverPublicKey,
      serverIdentity ?? null,
      clientIdentity ?? null,
      nonce,
      this.suite,
    );

    return { clientPublicKey, maskingKey, envelope };
  }

  /**
   * Step 2a: Generate KE1 (start authentication, random nonces).
   */
  generateKE1(password: Uint8Array): { state: ClientAuthState; ke1Bytes: Uint8Array } {
    const clientNonce   = crypto.getRandomValues(new Uint8Array(this.suite.Nn));
    const clientAkeSeed = crypto.getRandomValues(new Uint8Array(this.suite.Nn));
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
    clientAkeSeed: Uint8Array,
  ): { state: ClientAuthState; ke1Bytes: Uint8Array } {
    return this._generateKE1Inner(password, fixedBlind, clientNonce, clientAkeSeed);
  }

  private _generateKE1Inner(
    password: Uint8Array,
    fixedBlind: bigint | undefined,
    clientNonce: Uint8Array,
    clientAkeSeed: Uint8Array,
  ): { state: ClientAuthState; ke1Bytes: Uint8Array } {
    const { blind: r, blindedElement } = this.suite.blind(password, fixedBlind);

    // AKE key derived via deriveKeyPair(seed, "OPAQUE-DeriveDiffieHellmanKeyPair")
    const DERIVE_AKE_INFO = strToBytes('OPAQUE-DeriveDiffieHellmanKeyPair');
    const clientAkeSk = this.suite.deriveKeyPair(
      clientAkeSeed, DERIVE_AKE_INFO, this.suite.DERIVE_KEY_PAIR_DST,
    );
    const clientAkePk = this.suite.getPublicKey(clientAkeSk);

    // KE1 = blindedElement (Npk) || clientNonce (Nn) || clientAkePk (Npk)
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
    ksf?: KSF,
  ): Promise<AuthResult> {
    const ctx = context ?? new Uint8Array(0);
    const { suite } = this;

    // 1. Finalize OPRF
    const oprfOutput = suite.finalize(state.password, state.blind, ke2.evaluatedElement);
    const randomizedPwd = await deriveRandomizedPwd(oprfOutput, ksf ?? identityKsf, suite);

    // 2. Unmask credential response
    const maskingKey = deriveMaskingKey(randomizedPwd, suite);
    const pad = deriveMaskingPad(maskingKey, ke2.maskingNonce, suite);
    const unmasked = xor(ke2.maskedResponse, pad);

    // unmasked = serverPublicKey (Npk) || envelopeBytes (Nn + Nh)
    const serverPublicKey = unmasked.slice(0, suite.Npk);
    const envelope = deserializeEnvelope(unmasked.slice(suite.Npk), suite);

    // 3. Recover credentials from envelope
    const { clientSecretKey, clientPublicKey, exportKey } = recoverEnvelope(
      randomizedPwd,
      envelope,
      serverPublicKey,
      serverIdentity ?? null,
      clientIdentity ?? null,
      suite,
    );

    // Resolve identities for preamble (same defaulting as CleartextCredentials)
    const finalClientId = clientIdentity ?? clientPublicKey;
    const finalServerId = serverIdentity ?? serverPublicKey;

    // 4. Build preamble
    // credResponseBytes = evaluatedElement (Npk) || maskingNonce (Nn) || maskedResponse (Npk+Nn+Nh)
    const credResponseBytes = concat(ke2.evaluatedElement, ke2.maskingNonce, ke2.maskedResponse);
    const preamble = buildPreamble(
      ctx,
      finalClientId,
      state.ke1Bytes,
      finalServerId,
      credResponseBytes,
      ke2.serverNonce,
      ke2.serverAkePublicKey,
    );

    // 5. Derive 3DH keys
    const { km2, km3, sessionKey } = derive3DHKeys(
      state.clientAkeSecretKey,
      clientSecretKey,
      ke2.serverAkePublicKey,
      serverPublicKey,
      preamble,
      suite,
    );

    // 6. Verify server MAC
    if (!verifyServerMac(km2, preamble, ke2.serverMac, suite)) {
      throw new Error('generateKE3: server MAC verification failed');
    }

    // 7. Compute client MAC (= KE3 message sent to server)
    const clientMac = computeClientMac(km3, preamble, ke2.serverMac, suite);

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
 * With Argon2id KSF: stretchedOprfOutput = Argon2id(oprfOutput, ...).
 *
 * Uses the suite's hash for HKDF-Extract when provided.
 */
export async function deriveRandomizedPwd(
  oprfOutput: Uint8Array,
  ksf: KSF = identityKsf,
  suite: CipherSuite = P256_SHA256,
): Promise<Uint8Array> {
  const stretchedOprfOutput = await ksf(oprfOutput);
  return suite.hkdfExtract(undefined, concat(oprfOutput, stretchedOprfOutput));
}

/**
 * Derive the masking pad for XOR-unmasking the credential response.
 *
 * pad = HKDF-Expand(maskingKey, maskingNonce || "CredentialResponsePad", Npk + Nn + Nh)
 */
function deriveMaskingPad(
  maskingKey: Uint8Array,
  maskingNonce: Uint8Array,
  suite: CipherSuite,
): Uint8Array {
  const info = concat(maskingNonce, strToBytes('CredentialResponsePad'));
  const padLen = suite.Npk + suite.Nn + suite.Nh;
  return suite.hkdfExpand(maskingKey, info, padLen);
}

/**
 * Parse a KE2 wire message into its component fields.
 *
 * KE2 wire layout (sizes depend on cipher suite):
 *   evaluatedElement   (Npk)        OPRF evaluated element
 *   maskingNonce       (Nn=32)      nonce for credential response masking
 *   maskedResponse     (Npk+Nn+Nh)  serverPk || envNonce || authTag, XOR-masked
 *   serverNonce        (Nn=32)      server AKE ephemeral nonce
 *   serverAkePublicKey (Npk)        server ephemeral AKE public key
 *   serverMac          (Nh)         server authentication MAC
 *
 * P-256: 33+32+97+32+33+32 = 259 bytes
 * P-384: 49+32+129+32+49+48 = 339 bytes
 * P-521: 67+32+163+32+67+64 = 425 bytes
 */
export function parseKE2(bytes: Uint8Array, suite: CipherSuite = P256_SHA256): KE2 {
  const { Npk, Nn, Nh } = suite;
  const maskedResponseLen = Npk + Nn + Nh;
  const expectedLen = Npk + Nn + maskedResponseLen + Nn + Npk + Nh;

  if (bytes.length !== expectedLen) {
    throw new Error(`parseKE2: expected ${expectedLen} bytes for ${suite.name}, got ${bytes.length}`);
  }

  let o = 0;
  const evaluatedElement   = bytes.slice(o, o + Npk);  o += Npk;
  const maskingNonce       = bytes.slice(o, o + Nn);   o += Nn;
  const maskedResponse     = bytes.slice(o, o + maskedResponseLen); o += maskedResponseLen;
  const serverNonce        = bytes.slice(o, o + Nn);   o += Nn;
  const serverAkePublicKey = bytes.slice(o, o + Npk);  o += Npk;
  const serverMac          = bytes.slice(o, o + Nh);

  return { evaluatedElement, maskingNonce, maskedResponse, serverNonce, serverAkePublicKey, serverMac };
}
