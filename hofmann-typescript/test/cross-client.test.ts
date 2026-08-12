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
import { toHex, fromHex } from '../src/crypto/primitives.js';
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

// ── Cross-client VOPRF ─────────────────────────────────────────────────────

/**
 * The server public key is read from a file the Java side wrote, having derived
 * it from the configured master key — not fetched from the server. That is the
 * point of the exercise: a proof graded against a key the same server supplied
 * would verify no matter which key the server actually used, so fetching it
 * would make this test unable to fail.
 *
 * `OprfHttpClient.create` still cross-checks the pinned key against what
 * `/oprf/config` advertises, so a disagreement between the two implementations'
 * key derivation fails here rather than as an unexplained proof failure.
 */
describe.skipIf(skip)('cross-client VOPRF', () => {
  const INPUT_A = 'cross-client-voprf-alpha';
  const INPUT_B = 'cross-client-voprf-beta';

  it('verifies a Java-served DLEQ proof and matches the Java outputs', async () => {
    const pinned = readFile('voprf-pks.txt');
    expect(pinned, 'voprf-pks.txt written by the Java side').not.toBeNull();

    const client = await OprfHttpClient.create(SERVER_URL!, {
      voprfServerPublicKey: fromHex(pinned!),
    });

    // A two-element batch, because one proof covers the batch and a single
    // element would not exercise the composite index at all.
    const outputs = await client.evaluateVerifiable([
      strToBytes(INPUT_A), strToBytes(INPUT_B),
    ]);
    const hex = outputs.map(toHex).join('\n');

    writeFile('voprf-ts.txt', hex);

    const javaOutputs = readFile('voprf-java.txt');
    if (javaOutputs) {
      expect(hex).toBe(javaOutputs);
    }
  });
});

// ── Cross-client POPRF ─────────────────────────────────────────────────────

describe.skipIf(skip)('cross-client POPRF', () => {
  const INPUT_A = 'cross-client-poprf-alpha';
  const INPUT_B = 'cross-client-poprf-beta';

  it('verifies a Java-served proof under a public input and matches the outputs', async () => {
    const pinned = readFile('poprf-pks.txt');
    const infoHex = readFile('poprf-info.txt');
    expect(pinned, 'poprf-pks.txt written by the Java side').not.toBeNull();
    expect(infoHex, 'poprf-info.txt written by the Java side').not.toBeNull();

    const client = await OprfHttpClient.create(SERVER_URL!, {
      poprfServerPublicKey: fromHex(pinned!),
    });

    const outputs = await client.evaluatePartiallyOblivious(
      [strToBytes(INPUT_A), strToBytes(INPUT_B)],
      fromHex(infoHex!),
    );
    const hex = outputs.map(toHex).join('\n');

    writeFile('poprf-ts.txt', hex);

    const javaOutputs = readFile('poprf-java.txt');
    if (javaOutputs) {
      expect(hex).toBe(javaOutputs);
    }
  });
});

// ── Cross-client OPAQUE ────────────────────────────────────────────────────

describe.skipIf(skip)('cross-client OPAQUE', () => {
  let client: OpaqueHttpClient;

  beforeAll(async () => {
    // The integration server runs real Argon2id but tuned down to 1024 KiB / 1 iteration for
    // test speed (see hofmann-integration-tests/src/test/resources/application.yml), which is
    // below the client's floor of 19456 KiB / 2. Opt in explicitly, as a developer running
    // against a deliberately weakened dev server must.
    client = await OpaqueHttpClient.create(SERVER_URL!, { allowWeakServerKsf: true });
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

  it('recovers a credential registered by Java and re-registers with a new password', async () => {
    const credId = readFile('opaque-recovery-cred.txt');
    const newPassword = readFile('opaque-recovery-new-pwd.txt');

    if (!credId || !newPassword) {
      writeFile('opaque-ts-recovery-result.txt', 'skipped');
      return;
    }

    try {
      // Recovery flow: start → verify (code "123456") → re-register
      await client.recoveryStart(credId);
      const recoveryToken = await client.recoveryVerify(credId, '123456');
      expect(recoveryToken).toBeTruthy();
      await client.register(credId, newPassword, undefined, undefined, recoveryToken);
      writeFile('opaque-ts-recovery-result.txt', 'success');
    } catch (e) {
      writeFile('opaque-ts-recovery-result.txt', `failed: ${e}`);
      throw e;
    }
  }, 60_000);

  it('authenticates and auto-migrates after key rotation', async () => {
    const credId = readFile('opaque-rotation-cred.txt');
    const password = readFile('opaque-rotation-pwd.txt');

    if (!credId || !password) {
      writeFile('opaque-ts-rotation-result.txt', 'skipped');
      return;
    }

    try {
      // authenticate() auto-calls changePassword when keyRotationRequired=true
      const token = await client.authenticate(credId, password);
      expect(token).toBeTruthy();
      writeFile('opaque-ts-rotation-result.txt', 'success');
    } catch (e) {
      writeFile('opaque-ts-rotation-result.txt', `failed: ${e}`);
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
