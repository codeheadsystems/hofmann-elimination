/**
 * HTTP client for OPAQUE protocol REST endpoints.
 * All /opaque/* endpoints use base64 encoding.
 *
 * The cipher suite is read from GET /opaque/config so the client
 * automatically uses the same suite the server was configured with.
 */
import { OpaqueClient } from './client.js';
import { base64Encode, base64Decode, strToBytes } from '../crypto/encoding.js';
import { type KSF, identityKsf, argon2idKsf } from './ksf.js';
import { type CipherSuite, P256_SHA256, getCipherSuite } from '../oprf/suite.js';
import type { KE2 } from './types.js';

/**
 * Thrown when the server responds with HTTP 401, indicating authentication failure.
 */
export class OpaqueAuthenticationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'OpaqueAuthenticationError';
  }
}

export interface OpaqueHttpClientOptions {
  /** OPAQUE protocol context — must match the server's configured context exactly. */
  context?: string;
  /**
   * Key stretching function — must match the server's KSF configuration.
   *
   * Omitting this means NO PASSWORD STRETCHING: the identity KSF returns the OPRF output
   * unchanged, leaving the stored record open to an offline dictionary attack. Prefer the
   * static `create()` factory, which negotiates the KSF and enforces a minimum.
   */
  ksf?: KSF;
  /** Cipher suite to use. Resolved automatically from server config when using create(). */
  suite?: CipherSuite;
}

// ── Wire DTOs ──────────────────────────────────────────────────────────────

interface RegistrationStartRequestDto {
  credentialIdentifier: string;  // base64-encoded credential identifier
  blindedElement: string;        // base64
}

interface RegistrationStartResponseDto {
  evaluatedElement: string;  // base64
  serverPublicKey: string;   // base64
}

interface RegistrationFinishRequestDto {
  credentialIdentifier: string;  // base64-encoded credential identifier
  clientPublicKey: string;       // base64
  maskingKey: string;            // base64
  envelopeNonce: string;         // base64
  authTag: string;               // base64
}

interface AuthStartRequestDto {
  credentialIdentifier: string;  // base64-encoded credential identifier
  blindedElement: string;        // base64
  clientNonce: string;           // base64
  clientAkePublicKey: string;    // base64
}

interface AuthStartResponseDto {
  sessionToken: string;       // server-side AKE state token (echo back in finish)
  evaluatedElement: string;   // base64
  maskingNonce: string;       // base64
  maskedResponse: string;     // base64
  serverNonce: string;        // base64
  serverAkePublicKey: string; // base64
  serverMac: string;          // base64
}

interface AuthFinishRequestDto {
  sessionToken: string;  // from AuthStartResponseDto
  clientMac: string;     // base64
}

interface AuthFinishResponseDto {
  sessionKey: string;  // base64 — the shared session key
  token: string;       // JWT bearer token
  keyRotationRequired?: boolean;  // true when credential needs re-registration under new server keys
}

interface RegistrationDeleteRequestDto {
  credentialIdentifier: string;  // base64-encoded credential identifier
}

// ── Recovery DTOs ────────────────────────────────────────────────────────────

export interface RecoveryStartRequest {
  credentialIdentifier: string;  // base64-encoded credential identifier
}

export interface RecoveryVerifyRequest {
  credentialIdentifier: string;  // base64-encoded credential identifier
  challengeResponse: string;
}

export interface RecoveryVerifyResponse {
  recoveryToken: string;
}

export interface OpaqueConfigResponseDto {
  cipherSuite: string;
  context: string;
  argon2MemoryKib: number;
  argon2Iterations: number;
  argon2Parallelism: number;
}

// ── Client ─────────────────────────────────────────────────────────────────

/**
 * Minimum Argon2id memory cost, in KiB, accepted from a server-supplied config.
 *
 * 19456 KiB (19 MiB) is the OWASP Password Storage Cheat Sheet minimum for Argon2id at
 * t=2, p=1. The server's own default is 65536 KiB. Matches MIN_ARGON2_MEMORY_KIB in the
 * Java client.
 */
export const MIN_ARGON2_MEMORY_KIB = 19456;

/** Minimum Argon2id iteration count accepted from a server-supplied config. */
export const MIN_ARGON2_ITERATIONS = 2;

/**
 * Upper bound on server-requested Argon2id memory, 4 GiB. Not a security floor — it stops a
 * server from inducing a client-side denial of service through an absurd allocation.
 */
export const MAX_ARGON2_MEMORY_KIB = 4194304;

/**
 * Upper bound on server-requested Argon2id iterations. Argon2id cost is linear in iterations
 * and unbounded, so an absurd value hangs the client on its first registration just as surely
 * as an absurd memory request. OWASP's published parameter sets top out at 4; 10 is generous.
 * Like {@link MAX_ARGON2_MEMORY_KIB} this is DoS hardening, not a security floor.
 */
export const MAX_ARGON2_ITERATIONS = 10;

/** Upper bound on server-requested Argon2id parallelism. DoS hardening, not a security floor. */
export const MAX_ARGON2_PARALLELISM = 16;

/** Argon2id parameters that have been type-checked and range-checked. */
export interface ValidatedKsfParams {
  readonly argon2MemoryKib: number;
  readonly argon2Iterations: number;
  readonly argon2Parallelism: number;
}

/**
 * Rejects server-supplied key-stretching parameters weak enough to make an offline
 * dictionary attack cheap.
 *
 * In OPAQUE the KSF runs entirely on the client, so these parameters decide how expensive
 * it is to attack the record the server stores. Taking them from the server unchecked lets
 * a malicious, breached, or MITM'd server turn its own users' password hashing off:
 * `argon2MemoryKib: 0` selects the identity KSF, which returns the OPRF output unchanged.
 * Registration then stores a record derived from an unstretched password, and since the
 * server keeps serving the same config, authentication still succeeds and nothing looks
 * wrong. The server gates this behind an `allowIdentityKsf` flag and refuses to start
 * without it; this is the client-side counterpart.
 */
export function assertKsfMeetsMinimum(cfg: OpaqueConfigResponseDto): ValidatedKsfParams {
  const memoryKib = cfg.argon2MemoryKib;
  const iterations = cfg.argon2Iterations;
  const parallelism = cfg.argon2Parallelism;

  // Type-check BEFORE comparing magnitudes. `await r.json() as OpaqueConfigResponseDto` is a
  // compile-time assertion with no runtime force, so these fields are whatever the server sent.
  // A missing field, a string, or an object yields NaN in any numeric comparison — and every
  // comparison with NaN is false, so a magnitude-only guard passes and control falls through to
  // the identity KSF. Omitting a single JSON key would otherwise restore the whole
  // vulnerability this function exists to prevent. Java is immune to the same payload only
  // because Jackson refuses to bind a non-integer to `int`.
  if (!Number.isInteger(memoryKib)
    || !Number.isInteger(iterations)
    || !Number.isInteger(parallelism)) {
    throw new Error(
      'Server config has non-integer Argon2id parameters: '
      + `memory=${JSON.stringify(memoryKib)}, iterations=${JSON.stringify(iterations)}, `
      + `parallelism=${JSON.stringify(parallelism)}. Refusing, because a non-numeric value `
      + 'silently defeats the key-stretching floor.',
    );
  }
  if (memoryKib === 0) {
    throw new Error(
      'Server offers the identity KSF (argon2MemoryKib=0), which performs no password '
      + 'stretching and leaves the stored record open to an offline dictionary attack. '
      + 'Refusing. Pass { allowWeakServerKsf: true } to opt in locally.',
    );
  }
  if (memoryKib < MIN_ARGON2_MEMORY_KIB || iterations < MIN_ARGON2_ITERATIONS) {
    throw new Error(
      `Server offers Argon2id parameters below the client's minimum: `
      + `memory=${memoryKib} KiB (minimum ${MIN_ARGON2_MEMORY_KIB}), `
      + `iterations=${iterations} (minimum ${MIN_ARGON2_ITERATIONS}). `
      + 'Refusing, because these determine offline attack cost against the stored record. '
      + 'Pass { allowWeakServerKsf: true } to opt in locally.',
    );
  }
  if (memoryKib > MAX_ARGON2_MEMORY_KIB) {
    throw new Error(
      `Server asks for ${memoryKib} KiB of Argon2id memory, above the client's ceiling of `
      + `${MAX_ARGON2_MEMORY_KIB} KiB. Refusing, to avoid a server-induced client DoS.`,
    );
  }
  if (iterations > MAX_ARGON2_ITERATIONS) {
    throw new Error(
      `Server asks for ${iterations} Argon2id iterations, above the client's ceiling of `
      + `${MAX_ARGON2_ITERATIONS}. Refusing, to avoid a server-induced client DoS — Argon2id `
      + 'cost is linear in iterations and otherwise unbounded.',
    );
  }
  if (parallelism < 1 || parallelism > MAX_ARGON2_PARALLELISM) {
    throw new Error(
      `Server offers argon2Parallelism=${parallelism}; must be between 1 and `
      + `${MAX_ARGON2_PARALLELISM}.`,
    );
  }
  return { argon2MemoryKib: memoryKib, argon2Iterations: iterations, argon2Parallelism: parallelism };
}

/**
 * HTTP wrapper for the OPAQUE registration and authentication flow.
 *
 * Use the static `create()` factory to automatically resolve the cipher suite
 * and KSF from the server's /opaque/config endpoint.
 */
export class OpaqueHttpClient {
  private readonly opaque: OpaqueClient;
  private readonly ctx: Uint8Array;
  private readonly ksf: KSF;
  configResponse: OpaqueConfigResponseDto | null = null;

  constructor(private readonly baseUrl: string, options?: OpaqueHttpClientOptions) {
    const suite = options?.suite ?? P256_SHA256;
    this.opaque = new OpaqueClient(suite);
    this.ctx = options?.context ? strToBytes(options.context) : new Uint8Array(0);
    // No silent default to identityKsf: constructing this class without a KSF meant no password
    // stretching at all, which reads like a reasonable default and is not one. create() is the
    // supported entry point and negotiates it; a caller constructing directly must say what they
    // want, including saying explicitly that they want none.
    if (options?.ksf === undefined) {
      throw new Error(
        'OpaqueHttpClient requires an explicit ksf. Use OpaqueHttpClient.create(), which '
        + 'negotiates it from the server and enforces a minimum, or pass { ksf: identityKsf } '
        + 'to opt in to no password stretching.',
      );
    }
    this.ksf = options.ksf;
  }

  /**
   * Fetches the OPAQUE configuration from the server.
   */
  async getConfig(): Promise<OpaqueConfigResponseDto> {
    const r = await fetch(`${this.baseUrl}/opaque/config`);
    if (!r.ok) {
      throw new Error(`getConfig failed: ${r.status} ${r.statusText}`);
    }
    return r.json();
  }

  /**
   * Factory that fetches server config, resolves cipher suite + KSF, and returns
   * a fully configured client. This is the recommended way to create a client.
   *
   * The cipherSuite field in the server response must be one of:
   *   "P256_SHA256", "P384_SHA384", "P521_SHA512"
   */
  static async create(
    baseUrl: string,
    options?: { allowWeakServerKsf?: boolean; expectedContext?: string },
  ): Promise<OpaqueHttpClient> {
    const r = await fetch(`${baseUrl}/opaque/config`);
    if (!r.ok) {
      throw new Error(`Failed to fetch OPAQUE config: ${r.status} ${r.statusText}`);
    }
    const cfg = await r.json() as OpaqueConfigResponseDto;
    // The context is the binding that stops a transcript from one deployment being replayed
    // against another, and the docs specify it is shared out-of-band — yet it arrives on the same
    // channel an attacker in the middle controls. Pin it to verify rather than adopt.
    if (options?.expectedContext !== undefined && options.expectedContext !== cfg.context) {
      throw new Error(
        `Server context "${cfg.context}" does not match the expected "${options.expectedContext}". `
        + 'The context must be shared out-of-band, not taken from the server.',
      );
    }
    const suite = getCipherSuite(cfg.cipherSuite);
    let ksf: KSF;
    if (options?.allowWeakServerKsf) {
      // Opt-in path. Still require an integer before choosing Argon2id, so an unexpected value
      // lands on the branch the caller explicitly accepted rather than on an accident.
      ksf = Number.isInteger(cfg.argon2MemoryKib) && cfg.argon2MemoryKib > 0
        ? argon2idKsf(cfg.argon2MemoryKib, cfg.argon2Iterations, cfg.argon2Parallelism, suite.Nh)
        : identityKsf;
    } else {
      // On the strict path there is deliberately no branch to identityKsf at all: the guard
      // guarantees memory >= MIN_ARGON2_MEMORY_KIB, so Argon2id is the only reachable outcome.
      // A ternary here would be one coercion bug away from silently selecting no stretching.
      const p = assertKsfMeetsMinimum(cfg);
      ksf = argon2idKsf(p.argon2MemoryKib, p.argon2Iterations, p.argon2Parallelism, suite.Nh);
    }
    const client = new OpaqueHttpClient(baseUrl, { context: cfg.context, ksf, suite });
    client.configResponse = cfg;
    return client;
  }

  /**
   * Full registration flow: create request → server response → finalize → upload.
   *
   * @param credentialId    Unique credential identifier (e.g. username or user ID)
   * @param password        The user's password
   * @param serverIdentity  Optional explicit server identity
   * @param clientIdentity  Optional explicit client identity
   * @param recoveryToken   Optional recovery token (from recoveryVerify) to authorize re-registration
   */
  async register(
    credentialId: string,
    password: string,
    serverIdentity?: string,
    clientIdentity?: string,
    recoveryToken?: string,
  ): Promise<void> {
    const passwordBytes = strToBytes(password);
    const credentialIdBytes = strToBytes(credentialId);
    const authHeaders: Record<string, string> = recoveryToken
      ? { 'Authorization': `Bearer ${recoveryToken}` }
      : {};

    // Step 1: Create registration request
    const regState = this.opaque.createRegistrationRequest(passwordBytes);

    // Step 2: Send to server and get response
    const reqDto: RegistrationStartRequestDto = {
      credentialIdentifier: base64Encode(credentialIdBytes),
      blindedElement: base64Encode(regState.blindedElement),
    };
    const regResp = await this._post<RegistrationStartResponseDto>(
      `/opaque/registration/start`,
      reqDto,
      authHeaders,
    );

    // Step 3: Finalize registration
    const response = {
      evaluatedElement: base64Decode(regResp.evaluatedElement),
      serverPublicKey:  base64Decode(regResp.serverPublicKey),
    };
    const record = await this.opaque.finalizeRegistration(
      regState,
      response,
      serverIdentity ? strToBytes(serverIdentity) : null,
      clientIdentity ? strToBytes(clientIdentity) : null,
      undefined,
      this.ksf,
    );

    // Step 4: Upload registration record
    const uploadDto: RegistrationFinishRequestDto = {
      credentialIdentifier: base64Encode(credentialIdBytes),
      clientPublicKey: base64Encode(record.clientPublicKey),
      maskingKey:      base64Encode(record.maskingKey),
      envelopeNonce:   base64Encode(record.envelope.nonce),
      authTag:         base64Encode(record.envelope.authTag),
    };
    await this._post<void>(`/opaque/registration/finish`, uploadDto, authHeaders);
  }

  /**
   * Full authentication flow: KE1 → KE2 → KE3.
   *
   * If the server indicates that key rotation is required (the credential was registered
   * under an older server key version), this method automatically re-registers the
   * credential via the change-password flow using the same password.
   *
   * @param credentialId    Credential identifier
   * @param password        The user's password
   * @param serverIdentity  Optional explicit server identity
   * @param clientIdentity  Optional explicit client identity
   * @returns               JWT bearer token from server
   */
  async authenticate(
    credentialId: string,
    password: string,
    serverIdentity?: string,
    clientIdentity?: string,
  ): Promise<string> {
    const passwordBytes = strToBytes(password);
    const credentialIdBytes = strToBytes(credentialId);

    // Step 1: Generate KE1
    const { state } = this.opaque.generateKE1(passwordBytes);

    const authReqDto: AuthStartRequestDto = {
      credentialIdentifier: base64Encode(credentialIdBytes),
      blindedElement:       base64Encode(state.blindedElement),
      clientNonce:          base64Encode(state.clientNonce),
      clientAkePublicKey:   base64Encode(state.clientAkePublicKey),
    };

    // Step 2: Send KE1 and get KE2 (server returns individual base64 fields)
    const authRespDto = await this._post<AuthStartResponseDto>(
      `/opaque/auth/start`,
      authReqDto,
    );

    // Assemble KE2 from individual base64 fields
    const ke2: KE2 = {
      evaluatedElement:   base64Decode(authRespDto.evaluatedElement),
      maskingNonce:       base64Decode(authRespDto.maskingNonce),
      maskedResponse:     base64Decode(authRespDto.maskedResponse),
      serverNonce:        base64Decode(authRespDto.serverNonce),
      serverAkePublicKey: base64Decode(authRespDto.serverAkePublicKey),
      serverMac:          base64Decode(authRespDto.serverMac),
    };

    // Step 3: Process KE2 and generate KE3
    const authResult = await this.opaque.generateKE3(
      state,
      ke2,
      clientIdentity ? strToBytes(clientIdentity) : null,
      serverIdentity ? strToBytes(serverIdentity) : null,
      this.ctx,
      this.ksf,
    );

    // Step 4: Send KE3 (clientMac), echoing back sessionToken for server AKE state lookup
    const finalizeDto: AuthFinishRequestDto = {
      sessionToken: authRespDto.sessionToken,
      clientMac:    base64Encode(authResult.clientMac),
    };
    const finalizeResp = await this._post<AuthFinishResponseDto>(
      `/opaque/auth/finish`,
      finalizeDto,
    );

    // Step 5: If key rotation required, silently re-register with the same password
    if (finalizeResp.keyRotationRequired) {
      await this.changePassword(credentialId, password, finalizeResp.token, serverIdentity, clientIdentity);
    }

    return finalizeResp.token;
  }

  /**
   * Change password for an existing registration (authenticated).
   *
   * Follows the same registration flow but POSTs to /opaque/password/start
   * and /opaque/password/finish with a JWT bearer token.
   *
   * @param credentialId    Credential identifier
   * @param newPassword     The new password
   * @param token           JWT bearer token (from a previous authenticate() call)
   * @param serverIdentity  Optional explicit server identity
   * @param clientIdentity  Optional explicit client identity
   */
  async changePassword(
    credentialId: string,
    newPassword: string,
    token: string,
    serverIdentity?: string,
    clientIdentity?: string,
  ): Promise<void> {
    const passwordBytes = strToBytes(newPassword);
    const credentialIdBytes = strToBytes(credentialId);
    const authHeaders: Record<string, string> = { 'Authorization': `Bearer ${token}` };

    // Step 1: Create registration request
    const regState = this.opaque.createRegistrationRequest(passwordBytes);

    // Step 2: Send to server and get response
    const reqDto: RegistrationStartRequestDto = {
      credentialIdentifier: base64Encode(credentialIdBytes),
      blindedElement: base64Encode(regState.blindedElement),
    };
    const regResp = await this._post<RegistrationStartResponseDto>(
      `/opaque/password/start`,
      reqDto,
      authHeaders,
    );

    // Step 3: Finalize registration
    const response = {
      evaluatedElement: base64Decode(regResp.evaluatedElement),
      serverPublicKey:  base64Decode(regResp.serverPublicKey),
    };
    const record = await this.opaque.finalizeRegistration(
      regState,
      response,
      serverIdentity ? strToBytes(serverIdentity) : null,
      clientIdentity ? strToBytes(clientIdentity) : null,
      undefined,
      this.ksf,
    );

    // Step 4: Upload new registration record
    const uploadDto: RegistrationFinishRequestDto = {
      credentialIdentifier: base64Encode(credentialIdBytes),
      clientPublicKey: base64Encode(record.clientPublicKey),
      maskingKey:      base64Encode(record.maskingKey),
      envelopeNonce:   base64Encode(record.envelope.nonce),
      authTag:         base64Encode(record.envelope.authTag),
    };
    await this._post<void>(`/opaque/password/finish`, uploadDto, authHeaders);
  }

  /**
   * Delete a registration by credential ID.
   *
   * @param credentialId  Credential identifier to delete
   * @param token         JWT bearer token (from a previous authenticate() call)
   */
  async deleteRegistration(credentialId: string, token: string): Promise<void> {
    const url = `${this.baseUrl}/opaque/registration`;
    const body: RegistrationDeleteRequestDto = {
      credentialIdentifier: base64Encode(strToBytes(credentialId)),
    };
    const response = await fetch(url, {
      method: 'DELETE',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${token}`,
      },
      body: JSON.stringify(body),
    });
    if (!response.ok) {
      if (response.status === 401) {
        throw new OpaqueAuthenticationError(`Delete failed: authentication required`);
      }
      throw new Error(`Delete failed: ${response.status} ${response.statusText}`);
    }
  }

  /**
   * Initiates account recovery by sending an out-of-band challenge to the user.
   *
   * The server always returns 202 Accepted regardless of whether the credential
   * exists, to prevent user enumeration.
   *
   * @param credentialId  Credential identifier to recover
   */
  async recoveryStart(credentialId: string): Promise<void> {
    const dto: RecoveryStartRequest = {
      credentialIdentifier: base64Encode(strToBytes(credentialId)),
    };
    await this._post<void>(`/opaque/recovery/start`, dto);
  }

  /**
   * Verifies the user's response to a recovery challenge.
   *
   * @param credentialId       Credential identifier being recovered
   * @param challengeResponse  The user's response to the challenge (e.g. email code, OTP)
   * @returns                  A single-use recovery token to authorize re-registration
   */
  async recoveryVerify(
    credentialId: string,
    challengeResponse: string,
  ): Promise<string> {
    const dto: RecoveryVerifyRequest = {
      credentialIdentifier: base64Encode(strToBytes(credentialId)),
      challengeResponse,
    };
    const resp = await this._post<RecoveryVerifyResponse>(`/opaque/recovery/verify`, dto);
    return resp.recoveryToken;
  }

  /**
   * Convenience method for the full recovery flow:
   * recoveryStart → (user provides challenge response) → recoveryVerify → register with recovery token.
   *
   * @param credentialId       Credential identifier to recover
   * @param challengeResponse  The user's response to the out-of-band challenge
   * @param newPassword        The new password to register
   * @param serverIdentity     Optional explicit server identity
   * @param clientIdentity     Optional explicit client identity
   */
  async recoverAndReRegister(
    credentialId: string,
    challengeResponse: string,
    newPassword: string,
    serverIdentity?: string,
    clientIdentity?: string,
  ): Promise<void> {
    const recoveryToken = await this.recoveryVerify(credentialId, challengeResponse);
    await this.register(credentialId, newPassword, serverIdentity, clientIdentity, recoveryToken);
  }

  private async _post<T>(path: string, body: unknown, extraHeaders?: Record<string, string>): Promise<T> {
    const response = await fetch(`${this.baseUrl}${path}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...extraHeaders },
      body: JSON.stringify(body),
    });
    if (!response.ok) {
      if (response.status === 401) {
        throw new OpaqueAuthenticationError(`Authentication failed [${path}]`);
      }
      const text = await response.text().catch(() => '');
      throw new Error(`OPAQUE server error [${path}]: ${response.status} ${response.statusText}${text ? ` — ${text}` : ''}`);
    }
    const text = await response.text();
    if (!text) return undefined as T;
    return JSON.parse(text) as T;
  }
}
