/**
 * HTTP client for the OPRF server endpoint.
 * Handles the POST /oprf REST call.
 */
import { blind, finalize } from './client.js';
import { toHex, fromHex } from '../crypto/primitives.js';

export interface OprfRequest {
  ecPoint: string;    // hex-encoded 33-byte compressed point (server API uses hex)
  requestId: string;  // unique request identifier required by server
}

export interface OprfResponse {
  ecPoint: string;  // hex-encoded 33-byte evaluated element
}

/**
 * Thin HTTP wrapper for the OPRF protocol.
 */
export class OprfHttpClient {
  constructor(private readonly baseUrl: string) {}

  /**
   * Evaluate the OPRF for the given input.
   * Returns the 32-byte OPRF output (finalized).
   */
  async evaluate(input: Uint8Array): Promise<Uint8Array> {
    const { blind: r, blindedElement } = blind(input);

    const body: OprfRequest = { ecPoint: toHex(blindedElement), requestId: crypto.randomUUID() };
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
    return finalize(input, r, evaluatedElement);
  }
}
