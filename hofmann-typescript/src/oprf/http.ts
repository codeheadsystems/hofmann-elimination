/**
 * HTTP client for the OPRF server endpoints.
 *
 * Covers base mode (`POST /oprf`), VOPRF (`POST /oprf/verifiable`) and POPRF
 * (`POST /oprf/partially-oblivious`), and reads the cipher suite from
 * `GET /oprf/config` so the client uses the suite the server was configured with.
 *
 * The verifiable modes additionally require the server's public key, which this
 * client will **not** fetch. See `assertPinnedKeyMatches`.
 */
import { toHex, fromHex } from '../crypto/primitives.js';
import {
  type CipherSuite, P256_SHA256, getCipherSuite, getCipherSuiteForMode, OprfMode,
} from './suite.js';
import {
  VoprfClient, PoprfClient,
  type VoprfResponseDto, type PoprfResponseDto,
} from './verifiable.js';

export interface OprfRequest {
  ecPoint: string;    // hex-encoded compressed point (server API uses hex)
  requestId: string;  // unique request identifier required by server
}

export interface OprfResponse {
  ecPoint: string;             // hex-encoded evaluated element
  processIdentifier?: string;  // the server's keying-context label
}

/** One verifiable mode a server advertises on `GET /oprf/config`. */
export interface OprfModeInfoDto {
  mode: string;               // "VOPRF" | "POPRF"
  publicKeyHex: string;
  processIdentifier: string;
  maxBatchSize: number;
}

/**
 * `GET /oprf/config`.
 *
 * `modes` is absent — not empty — when the server has no verifiable mode
 * enabled, which is also what an older server sends.
 */
export interface OprfConfigResponseDto {
  cipherSuite: string;
  modes?: OprfModeInfoDto[];
}

// ── Errors ───────────────────────────────────────────────────────────────────

/** The server has no key configured for the requested mode (HTTP 404). */
export class OprfModeNotEnabledError extends Error {}

/** The server advertises a different public key than the one pinned. */
export class OprfPublicKeyMismatchError extends Error {}

/** The server rate-limited this client (HTTP 429). */
export class OprfRateLimitedError extends Error {
  constructor(message: string, readonly retryAfterSeconds?: number) {
    super(message);
  }
}

// ── Pinned-key cross-check ───────────────────────────────────────────────────

/**
 * Cross-checks a pinned public key against what the server advertises.
 *
 * **This is a diagnostic, not a security control, and must not become one.** The
 * config response is unauthenticated, so a hostile server can put anything in
 * it. What it cannot do is cause an *acceptance* — the only outcomes are
 * "proceed with the key already pinned" and "throw". Proof verification against
 * the pinned key remains the sole mechanism that makes a verifiable mode
 * verifiable. What this buys is that a rotated key or a mistyped pin surfaces
 * once, saying what disagreed, rather than as an unexplained run of proof
 * failures.
 *
 * Deliberately a standalone function: it is testable without `fetch`, and it can
 * be read side by side against the Java `OprfClientConfig.assertMatches` that
 * implements the same rule.
 *
 * The mode list is read as three states. Absent means the server predates the
 * field or has no verifiable mode, so no cross-check is possible and the
 * endpoint's 404 remains the capability probe. Present and naming the mode is
 * authoritative. Present and not naming it means the mode is off.
 */
export function assertPinnedKeyMatches(
  config: OprfConfigResponseDto,
  mode: 'VOPRF' | 'POPRF',
  pinned: Uint8Array,
): void {
  if (!config || config.modes === undefined || config.modes === null) {
    return;
  }
  const advertised = config.modes.find((m) => m.mode?.toUpperCase() === mode);
  if (!advertised) {
    throw new OprfModeNotEnabledError(
      `Server advertises its enabled modes and ${mode} is not among them`);
  }
  if (!pinned) return;
  let served: Uint8Array;
  try {
    served = fromHex(advertised.publicKeyHex.trim());
  } catch {
    throw new OprfPublicKeyMismatchError(
      `Server advertised a ${mode} public key that is not valid hex`);
  }
  // Compared as bytes: hex case and any leading-zero spelling difference would
  // otherwise read as a mismatch and refuse a perfectly good server.
  if (served.length !== pinned.length || !served.every((b, i) => b === pinned[i])) {
    throw new OprfPublicKeyMismatchError(
      `Server advertises a different ${mode} public key than the one pinned for this client. ` +
      `Either the server rotated its key and the pinned copies were not updated, or this is not ` +
      `the server that was pinned. Refusing to proceed.`);
  }
}

// ── Client ───────────────────────────────────────────────────────────────────

/** Optional configuration for {@link OprfHttpClient.create}. */
export interface OprfHttpClientOptions {
  /** Overrides the suite that would otherwise come from `GET /oprf/config`. */
  suite?: CipherSuite;
  /**
   * The server's VOPRF public key, obtained and authenticated out of band.
   * Required to call `evaluateVerifiable`; it is never fetched.
   */
  voprfServerPublicKey?: Uint8Array;
  /** The server's untweaked POPRF public key, obtained out of band. */
  poprfServerPublicKey?: Uint8Array;
}

/**
 * Thin HTTP wrapper for the OPRF protocol.
 * The cipher suite is resolved from the server's /oprf/config on construction.
 */
export class OprfHttpClient {
  cachedConfig: OprfConfigResponseDto | null = null;

  private voprfServerPublicKey?: Uint8Array;
  private poprfServerPublicKey?: Uint8Array;

  constructor(
    private readonly baseUrl: string,
    private readonly suite: CipherSuite = P256_SHA256,
  ) {}

  /**
   * Factory that fetches server config, resolves the cipher suite, and returns
   * a fully configured client.
   *
   * When a pinned key is supplied it is cross-checked against the config here,
   * so a mismatch fails at construction rather than at the first evaluation.
   */
  static async create(
    baseUrl: string,
    options: OprfHttpClientOptions = {},
  ): Promise<OprfHttpClient> {
    const r = await fetch(`${baseUrl}/oprf/config`);
    if (!r.ok) {
      throw new Error(`getConfig failed: ${r.status} ${r.statusText}`);
    }
    const cfg = await r.json() as OprfConfigResponseDto;
    const suite = options.suite ?? getCipherSuite(cfg.cipherSuite);
    const client = new OprfHttpClient(baseUrl, suite);
    client.cachedConfig = cfg;
    if (options.voprfServerPublicKey) {
      assertPinnedKeyMatches(cfg, 'VOPRF', options.voprfServerPublicKey);
      client.voprfServerPublicKey = options.voprfServerPublicKey;
    }
    if (options.poprfServerPublicKey) {
      assertPinnedKeyMatches(cfg, 'POPRF', options.poprfServerPublicKey);
      client.poprfServerPublicKey = options.poprfServerPublicKey;
    }
    return client;
  }

  /**
   * Fetches the OPRF configuration from the server.
   */
  async getConfig(): Promise<OprfConfigResponseDto> {
    const r = await fetch(`${this.baseUrl}/oprf/config`);
    if (!r.ok) {
      throw new Error(`getConfig failed: ${r.status} ${r.statusText}`);
    }
    return r.json();
  }

  /**
   * Evaluate the OPRF for the given input.
   * Returns the Nh-byte OPRF output (finalized).
   */
  async evaluate(input: Uint8Array): Promise<Uint8Array> {
    const { blind: r, blindedElement } = this.suite.blind(input);

    const body: OprfRequest = {
      ecPoint: toHex(blindedElement),
      requestId: crypto.randomUUID(),
    };
    const response = await fetch(`${this.baseUrl}/oprf`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });

    if (!response.ok) {
      throw new Error(`OPRF server error: ${response.status} ${response.statusText}`);
    }

    const json: OprfResponse = await response.json();
    const evaluatedElement = fromHex(json.ecPoint);
    return this.suite.finalize(input, r, evaluatedElement);
  }

  /**
   * Evaluates a batch under the server's VOPRF key and verifies the DLEQ proof.
   *
   * Batched because one proof covers the whole batch: sending elements one at a
   * time would cost a proof each and prove strictly less.
   *
   * @throws Error if the proof does not verify — no output is returned in that case
   */
  async evaluateVerifiable(inputs: Uint8Array[]): Promise<Uint8Array[]> {
    const client = new VoprfClient(this.modeSuite(OprfMode.VOPRF), this.requirePinned('VOPRF'));
    const ctx = client.blindBatch(inputs);
    const json = await this.postVerifiable<VoprfResponseDto>(
      '/oprf/verifiable', client.request(ctx), 'VOPRF');
    return client.finalizeBatch(ctx, json);
  }

  /** Single-input convenience over {@link evaluateVerifiable}. */
  async evaluateVerifiableOne(input: Uint8Array): Promise<Uint8Array> {
    return (await this.evaluateVerifiable([input]))[0];
  }

  /**
   * Evaluates a batch under a key tweaked by `info`, and verifies the proof.
   *
   * `info` is required and an empty array is a valid value meaning "no public
   * input" — absent and empty are different public inputs producing different
   * outputs, so there is no default.
   */
  async evaluatePartiallyOblivious(
    inputs: Uint8Array[],
    info: Uint8Array,
  ): Promise<Uint8Array[]> {
    const client = new PoprfClient(this.modeSuite(OprfMode.POPRF), this.requirePinned('POPRF'));
    const ctx = client.blindBatch(inputs, info);
    const json = await this.postVerifiable<PoprfResponseDto>(
      '/oprf/partially-oblivious', client.request(ctx), 'POPRF');
    return client.finalizeBatch(ctx, json);
  }

  /** Single-input convenience over {@link evaluatePartiallyOblivious}. */
  async evaluatePartiallyObliviousOne(
    input: Uint8Array,
    info: Uint8Array,
  ): Promise<Uint8Array> {
    return (await this.evaluatePartiallyOblivious([input], info))[0];
  }

  /**
   * The suite for a verifiable mode. The base-mode suite this client holds
   * computes a different function under a different set of domain-separation
   * tags, so it cannot be reused.
   */
  private modeSuite(mode: OprfMode): CipherSuite {
    return getCipherSuiteForMode(configSuiteName(this.suite.name), mode);
  }

  private requirePinned(mode: 'VOPRF' | 'POPRF'): Uint8Array {
    const key = mode === 'VOPRF' ? this.voprfServerPublicKey : this.poprfServerPublicKey;
    if (!key) {
      throw new Error(
        `No pinned ${mode} server public key. The verifiable modes require a public key ` +
        `authenticated out of band; it cannot be fetched from the server, because a proof graded ` +
        `against a key the same server supplied proves nothing. Pass it to ` +
        `OprfHttpClient.create(url, { ${mode.toLowerCase()}ServerPublicKey }).`);
    }
    return key;
  }

  private async postVerifiable<T>(
    path: string,
    body: unknown,
    mode: 'VOPRF' | 'POPRF',
  ): Promise<T> {
    const response = await fetch(`${this.baseUrl}${path}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    if (response.status === 404) {
      throw new OprfModeNotEnabledError(`${mode} is not enabled on this server (404)`);
    }
    if (response.status === 429) {
      const header = response.headers.get('Retry-After');
      const seconds = header && /^\d+$/.test(header.trim())
        ? Number(header.trim()) : undefined;
      throw new OprfRateLimitedError(`${mode} request was rate limited (429)`, seconds);
    }
    if (!response.ok) {
      throw new Error(`${mode} server error: ${response.status} ${response.statusText}`);
    }
    return response.json() as Promise<T>;
  }
}

/** Maps the RFC's suite spelling back to the one `getCipherSuiteForMode` accepts. */
function configSuiteName(rfcName: string): string {
  switch (rfcName) {
    case 'P256-SHA256': return 'P256_SHA256';
    case 'P384-SHA384': return 'P384_SHA384';
    case 'P521-SHA512': return 'P521_SHA512';
    case 'ristretto255-SHA512': return 'RISTRETTO255_SHA512';
    default: throw new Error(`Unknown cipher suite: "${rfcName}"`);
  }
}
