/**
 * HTTP client for the OPRF server endpoint.
 * Handles the POST /oprf REST call.
 * Reads the cipher suite from GET /oprf/config so the client uses the same
 * suite the server was configured with.
 */
import { toHex, fromHex } from '../crypto/primitives.js';
import { type CipherSuite, P256_SHA256, getCipherSuite } from './suite.js';

export interface OprfRequest {
  ecPoint: string;    // hex-encoded compressed point (server API uses hex)
  requestId: string;  // unique request identifier required by server
}

export interface OprfResponse {
  ecPoint: string;  // hex-encoded evaluated element
}

/**
 * Thin HTTP wrapper for the OPRF protocol.
 * The cipher suite is resolved from the server's /oprf/config on construction.
 */
export class OprfHttpClient {
  cachedConfig: { cipherSuite: string } | null = null;

  constructor(
    private readonly baseUrl: string,
    private readonly suite: CipherSuite = P256_SHA256,
  ) {}

  /**
   * Factory that fetches server config, resolves the cipher suite, and returns
   * a fully configured client.
   */
  static async create(baseUrl: string): Promise<OprfHttpClient> {
    const r = await fetch(`${baseUrl}/oprf/config`);
    if (!r.ok) {
      throw new Error(`getConfig failed: ${r.status} ${r.statusText}`);
    }
    const cfg = await r.json() as { cipherSuite: string };
    const suite = getCipherSuite(cfg.cipherSuite);
    const client = new OprfHttpClient(baseUrl, suite);
    client.cachedConfig = cfg;
    return client;
  }

  /**
   * Fetches the OPRF configuration from the server.
   */
  async getConfig(): Promise<{ cipherSuite: string }> {
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
}
