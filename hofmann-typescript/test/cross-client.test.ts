/**
 * Cross-client integration tests — validates Java and TypeScript clients
 * produce consistent results when talking to the same server.
 *
 * These tests are driven by the Java integration test suite which:
 * 1. Starts a Spring Boot server with a specific cipher suite
 * 2. Performs operations (hash / register) on the Java side
 * 3. Invokes this test file with TEST_SERVER_URL and TEST_OUTPUT_DIR set
 * 4. Reads back result files to verify consistency
 *
 * Environment variables:
 *   TEST_SERVER_URL  — base URL of the running server (e.g. http://localhost:8080)
 *   TEST_OUTPUT_DIR  — shared directory for exchanging result files with Java
 *
 * Skipped automatically when TEST_SERVER_URL is not set.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { OprfHttpClient } from '../src/oprf/http.js';
import { OpaqueHttpClient } from '../src/opaque/http.js';
import { strToBytes } from '../src/crypto/encoding.js';
import { toHex } from '../src/crypto/primitives.js';
import * as fs from 'node:fs';
import * as path from 'node:path';

const SERVER_URL = process.env['TEST_SERVER_URL'];
const OUTPUT_DIR = process.env['TEST_OUTPUT_DIR'];
const skip = !SERVER_URL || !OUTPUT_DIR;

function readFile(name: string): string | null {
  if (!OUTPUT_DIR) return null;
  const filePath = path.join(OUTPUT_DIR, name);
  try {
    return fs.readFileSync(filePath, 'utf-8').trim();
  } catch {
    return null;
  }
}

function writeFile(name: string, content: string): void {
  if (!OUTPUT_DIR) return;
  fs.writeFileSync(path.join(OUTPUT_DIR, name), content, 'utf-8');
}

// ── Cross-client OPRF ──────────────────────────────────────────────────────

describe.skipIf(skip)('cross-client OPRF', () => {
  const CROSS_CLIENT_INPUT = 'cross-client-oprf-test-input';
  let client: OprfHttpClient;

  beforeAll(async () => {
    client = await OprfHttpClient.create(SERVER_URL!);
  });

  it('produces the same OPRF hash as the Java client', async () => {
    const result = await client.evaluate(strToBytes(CROSS_CLIENT_INPUT));
    const hashHex = toHex(result);

    // Write result for the Java test to read and compare
    writeFile('oprf-ts.txt', hashHex);

    // If the Java result is already available, compare directly
    const javaHash = readFile('oprf-java.txt');
    if (javaHash) {
      expect(hashHex).toBe(javaHash);
    }
  });
});

// ── Cross-client OPAQUE ────────────────────────────────────────────────────

describe.skipIf(skip)('cross-client OPAQUE', () => {
  let client: OpaqueHttpClient;

  beforeAll(async () => {
    client = await OpaqueHttpClient.create(SERVER_URL!);
  });

  it('authenticates with a credential registered by Java', async () => {
    const credId = readFile('opaque-java-registered-cred.txt');
    const password = readFile('opaque-java-registered-pwd.txt');

    if (!credId || !password) {
      // No Java-registered credential available — write skip marker
      writeFile('opaque-ts-auth-result.txt', 'skipped');
      return;
    }

    try {
      const token = await client.authenticate(credId, password);
      expect(token).toBeTruthy();
      writeFile('opaque-ts-auth-result.txt', 'success');
    } catch (e) {
      writeFile('opaque-ts-auth-result.txt', `failed: ${e}`);
      throw e;
    }
  }, 60_000);

  it('registers a credential for Java to authenticate with', async () => {
    const credId = readFile('opaque-ts-register-cred.txt');
    const password = readFile('opaque-ts-register-pwd.txt');

    if (!credId || !password) {
      // No registration request from Java — write skip marker
      writeFile('opaque-ts-reg-result.txt', 'skipped');
      return;
    }

    try {
      await client.register(credId, password);
      writeFile('opaque-ts-reg-result.txt', 'success');
    } catch (e) {
      writeFile('opaque-ts-reg-result.txt', `failed: ${e}`);
      throw e;
    }
  }, 60_000);
});
