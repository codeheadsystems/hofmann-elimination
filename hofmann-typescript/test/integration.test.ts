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
import { OpaqueHttpClient, OpaqueAuthenticationError } from '../src/opaque/http.js';
import { OprfHttpClient } from '../src/oprf/http.js';
import { strToBytes } from '../src/crypto/encoding.js';

const SERVER_URL = process.env['TEST_SERVER_URL'];
const skip = !SERVER_URL;
// Recovery tests require the server to have a RecoveryChallenger configured
const skipRecovery = skip || !process.env['TEST_RECOVERY_ENABLED'];

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

// ── Recovery integration tests ────────────────────────────────────────────────
// These require TEST_RECOVERY_ENABLED=true and a server with a RecoveryChallenger
// that accepts "123456" as the challenge response for any credential.

describe.skipIf(skipRecovery)('OpaqueHttpClient recovery integration', () => {
  const credentialId = `ts-recovery-${Date.now()}`;
  const oldPassword = 'old-password';
  const newPassword = 'new-password';
  let client: OpaqueHttpClient;

  beforeAll(async () => {
    client = await OpaqueHttpClient.create(SERVER_URL!);
  });

  it('registers with old password', async () => {
    await expect(client.register(credentialId, oldPassword)).resolves.toBeUndefined();
  }, 30_000);

  it('authenticates with old password', async () => {
    const token = await client.authenticate(credentialId, oldPassword);
    expect(token).toBeTruthy();
  }, 30_000);

  it('recoveryStart succeeds (always 202)', async () => {
    await expect(client.recoveryStart(credentialId)).resolves.toBeUndefined();
  });

  it('recoveryVerify returns a recovery token', async () => {
    // Assumes test challenger accepts "123456"
    const token = await client.recoveryVerify(credentialId, '123456');
    expect(token).toBeTruthy();
    expect(typeof token).toBe('string');
  });

  it('re-registers with new password using recovery token', async () => {
    // Need a fresh recovery flow since token was consumed by the previous test's verify
    await client.recoveryStart(credentialId);
    const recoveryToken = await client.recoveryVerify(credentialId, '123456');
    await expect(
      client.register(credentialId, newPassword, undefined, undefined, recoveryToken),
    ).resolves.toBeUndefined();
  }, 30_000);

  it('authenticates with new password after recovery', async () => {
    const token = await client.authenticate(credentialId, newPassword);
    expect(token).toBeTruthy();
  }, 30_000);

  it('old password fails after recovery', async () => {
    await expect(
      client.authenticate(credentialId, oldPassword),
    ).rejects.toThrow();
  }, 30_000);

  it('recoverAndReRegister convenience method works', async () => {
    // Re-register back to old password using the convenience method
    await client.recoveryStart(credentialId);
    await expect(
      client.recoverAndReRegister(credentialId, '123456', oldPassword),
    ).resolves.toBeUndefined();
    // Verify old password works again
    const token = await client.authenticate(credentialId, oldPassword);
    expect(token).toBeTruthy();
  }, 60_000);
});
