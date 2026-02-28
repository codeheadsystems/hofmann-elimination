/**
 * Integration tests — require a live hofmann-server instance.
 *
 * Run with:
 *   TEST_SERVER_URL=http://localhost:8080 npm test -- integration
 *
 * Tests are skipped automatically when TEST_SERVER_URL is not set.
 *
 * The default options match hofmann-testserver/config/config.yml:
 *   context     = "hofmann-testserver"
 *   argon2id    memory=65536 KiB, iterations=3, parallelism=1
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { OpaqueHttpClient } from '../src/opaque/http.js';
import { OprfHttpClient } from '../src/oprf/http.js';
import { argon2idKsf } from '../src/opaque/ksf.js';
import { strToBytes } from '../src/crypto/encoding.js';

const SERVER_URL = process.env['TEST_SERVER_URL'];
const skip = !SERVER_URL;

// KSF matching hofmann-testserver config.yml defaults
const TESTSERVER_KSF = argon2idKsf(65536, 3, 1);

describe.skipIf(skip)('OprfHttpClient integration', () => {
  it('evaluates OPRF against live server', async () => {
    const client = new OprfHttpClient(SERVER_URL!);
    const result = await client.evaluate(strToBytes('test-input'));
    expect(result).toHaveLength(32);
  });
});

describe.skipIf(skip)('OpaqueHttpClient integration', () => {
  const credentialId = `ts-test-${Date.now()}`;
  const password = 'correct-horse-battery-staple';
  let client: OpaqueHttpClient;
  let authToken: string;

  beforeAll(() => {
    client = new OpaqueHttpClient(SERVER_URL!, {
      context: 'hofmann-testserver',
      ksf: TESTSERVER_KSF,
    });
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
