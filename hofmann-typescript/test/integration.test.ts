/**
 * Integration tests — require a live hofmann-server instance.
 *
 * Run with:
 *   TEST_SERVER_URL=http://localhost:8080 npm test -- integration
 *
 * Tests are skipped automatically when TEST_SERVER_URL is not set.
 *
 * The clients use OpaqueHttpClient.create() / OprfHttpClient.create() so that
 * the cipher suite and Argon2id parameters are read from the server rather than
 * being hardcoded here.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { OpaqueHttpClient } from '../src/opaque/http.js';
import { OprfHttpClient } from '../src/oprf/http.js';
import { strToBytes } from '../src/crypto/encoding.js';

const SERVER_URL = process.env['TEST_SERVER_URL'];
const skip = !SERVER_URL;

describe.skipIf(skip)('OprfHttpClient integration', () => {
  let client: OprfHttpClient;

  beforeAll(async () => {
    // create() fetches /oprf/config to resolve cipher suite automatically
    client = await OprfHttpClient.create(SERVER_URL!);
  });

  it('resolves cipher suite from server config', () => {
    expect(client.cachedConfig).not.toBeNull();
    expect(client.cachedConfig!.cipherSuite).toMatch(/^P(256|384|521)_SHA(256|384|512)$/);
  });

  it('evaluates OPRF against live server (output length matches Nh)', async () => {
    const result = await client.evaluate(strToBytes('test-input'));
    // Nh depends on the suite the server is configured with
    expect([32, 48, 64]).toContain(result.length);
  });
});

describe.skipIf(skip)('OpaqueHttpClient integration', () => {
  const credentialId = `ts-test-${Date.now()}`;
  const password = 'correct-horse-battery-staple';
  let client: OpaqueHttpClient;
  let authToken: string;

  beforeAll(async () => {
    // create() fetches /opaque/config and configures cipher suite + Argon2id automatically
    client = await OpaqueHttpClient.create(SERVER_URL!);
  });

  it('resolves cipher suite and Argon2id config from server', () => {
    expect(client.configResponse).not.toBeNull();
    const cfg = client.configResponse!;
    expect(cfg.cipherSuite).toMatch(/^P(256|384|521)_SHA(256|384|512)$/);
    // argon2MemoryKib ≥ 0 (0 means identity KSF / no stretching)
    expect(cfg.argon2MemoryKib).toBeGreaterThanOrEqual(0);
    expect(typeof cfg.argon2Iterations).toBe('number');
    expect(typeof cfg.argon2Parallelism).toBe('number');
  });

  it('completes full registration flow', async () => {
    await expect(client.register(credentialId, password)).resolves.toBeUndefined();
  }, 30_000); // Argon2id can take several seconds

  it('authenticates with correct password', async () => {
    authToken = await client.authenticate(credentialId, password);
    expect(authToken).toBeTruthy();
    expect(typeof authToken).toBe('string');
  }, 30_000);

  it('rejects authentication with wrong password', async () => {
    await expect(
      client.authenticate(credentialId, 'wrong-password')
    ).rejects.toThrow();
  }, 30_000);

  it('deletes the registration', async () => {
    await expect(client.deleteRegistration(credentialId, authToken)).resolves.toBeUndefined();
  });
});
