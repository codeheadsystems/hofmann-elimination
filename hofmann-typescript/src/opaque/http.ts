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

export interface OpaqueHttpClientOptions {
  /** OPAQUE protocol context — must match the server's configured context exactly. */
  context?: string;
  /** Key stretching function — must match the server's KSF configuration. Default: identity. */
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
}

interface RegistrationDeleteRequestDto {
  credentialIdentifier: string;  // base64-encoded credential identifier
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
    this.ksf = options?.ksf ?? identityKsf;
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
  static async create(baseUrl: string): Promise<OpaqueHttpClient> {
    const r = await fetch(`${baseUrl}/opaque/config`);
    if (!r.ok) {
      throw new Error(`Failed to fetch OPAQUE config: ${r.status} ${r.statusText}`);
    }
    const cfg = await r.json() as OpaqueConfigResponseDto;
    const suite = getCipherSuite(cfg.cipherSuite);
    const ksf = cfg.argon2MemoryKib > 0
      ? argon2idKsf(cfg.argon2MemoryKib, cfg.argon2Iterations, cfg.argon2Parallelism)
      : identityKsf;
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
   */
  async register(
    credentialId: string,
    password: string,
    serverIdentity?: string,
    clientIdentity?: string,
  ): Promise<void> {
    const passwordBytes = strToBytes(password);
    const credentialIdBytes = strToBytes(credentialId);

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
    await this._post<void>(`/opaque/registration/finish`, uploadDto);
  }

  /**
   * Full authentication flow: KE1 → KE2 → KE3.
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

    return finalizeResp.token;
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
      throw new Error(`Delete failed: ${response.status} ${response.statusText}`);
    }
  }

  private async _post<T>(path: string, body: unknown): Promise<T> {
    const response = await fetch(`${this.baseUrl}${path}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    if (!response.ok) {
      const text = await response.text().catch(() => '');
      throw new Error(`OPAQUE server error [${path}]: ${response.status} ${response.statusText}${text ? ` — ${text}` : ''}`);
    }
    const text = await response.text();
    if (!text) return undefined as T;
    return JSON.parse(text) as T;
  }
}
