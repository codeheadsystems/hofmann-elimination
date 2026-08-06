import { describe, it, expect } from 'vitest';
import {
  assertKsfMeetsMinimum,
  MIN_ARGON2_MEMORY_KIB,
  MIN_ARGON2_ITERATIONS,
  MAX_ARGON2_MEMORY_KIB,
  MAX_ARGON2_ITERATIONS,
  MAX_ARGON2_PARALLELISM,
} from '../src/index.js';

/**
 * In OPAQUE the key-stretching function runs entirely on the client, so the Argon2id
 * parameters decide how expensive an offline dictionary attack is against the record the
 * server stores. Taking them from the server unchecked lets a malicious, breached, or MITM'd
 * server switch its own users' password hashing off — and because it keeps serving the same
 * config afterwards, authentication continues to work and nothing looks wrong.
 *
 * Mirrors OpaqueClientConfigKsfFloorTest on the Java side; the floors must stay in step or a
 * browser client and a Java client will disagree about what is safe.
 */
const serverOffering = (argon2MemoryKib: number, argon2Iterations: number) => ({
  cipherSuite: 'P256_SHA256',
  context: 'ctx',
  argon2MemoryKib,
  argon2Iterations,
  argon2Parallelism: 1,
});

describe('server-supplied KSF floor', () => {
  it('refuses the identity KSF', () => {
    expect(() => assertKsfMeetsMinimum(serverOffering(0, 0)))
      .toThrow(/identity KSF/);
  });

  it('names the consequence so the error is actionable', () => {
    expect(() => assertKsfMeetsMinimum(serverOffering(0, 0)))
      .toThrow(/offline dictionary attack/);
  });

  it.each([
    [8, 1],       // the quiet variant of the same attack
    [1024, 3],    // plausible-looking but far below the floor
    [19455, 2],   // one KiB under
    [65536, 1],   // strong memory, too few iterations
  ])('refuses memory=%i KiB, iterations=%i', (memory, iterations) => {
    expect(() => assertKsfMeetsMinimum(serverOffering(memory, iterations)))
      .toThrow(/below the client's minimum/);
  });

  it.each([
    [19456, 2],   // exactly at the floor
    [65536, 3],   // the server's own default
    [131072, 4],
  ])('accepts memory=%i KiB, iterations=%i', (memory, iterations) => {
    expect(() => assertKsfMeetsMinimum(serverOffering(memory, iterations))).not.toThrow();
  });

  it('uses the same floor as the Java client', () => {
    expect(MIN_ARGON2_MEMORY_KIB).toBe(19456);
    expect(MIN_ARGON2_ITERATIONS).toBe(2);
  });
});

/**
 * `await r.json() as OpaqueConfigResponseDto` is a compile-time assertion with no runtime
 * force, so these fields are whatever the server sent. Any non-numeric value yields NaN in a
 * comparison, and every comparison with NaN is false — so a magnitude-only guard passes and
 * the client falls through to the identity KSF. Omitting one JSON key was enough to restore
 * the entire vulnerability.
 */
describe('type confusion in the server config', () => {
  const withMemory = (argon2MemoryKib: unknown) => ({
    cipherSuite: 'P256_SHA256',
    context: 'ctx',
    argon2Iterations: 3,
    argon2Parallelism: 1,
    ...(argon2MemoryKib === undefined ? {} : { argon2MemoryKib }),
  } as never);

  it.each([
    ['omitted entirely', undefined],
    ['a non-numeric string', 'high'],
    ['an object', {}],
    ['an array', []],
    ['null', null],
    ['a numeric string', '65536'],
    ['a float', 65536.5],
    ['NaN', Number.NaN],
    ['Infinity', Number.POSITIVE_INFINITY],
  ])('refuses argon2MemoryKib that is %s', (_label, value) => {
    expect(() => assertKsfMeetsMinimum(withMemory(value))).toThrow();
  });

  it('refuses a non-integer iteration count', () => {
    expect(() => assertKsfMeetsMinimum({
      cipherSuite: 'P256_SHA256', context: 'ctx',
      argon2MemoryKib: 65536, argon2Iterations: 'many', argon2Parallelism: 1,
    } as never)).toThrow(/non-integer/);
  });

  it('returns the validated parameters so callers need not re-read the raw config', () => {
    const p = assertKsfMeetsMinimum(serverOffering(65536, 3));
    expect(p).toEqual({
      argon2MemoryKib: 65536, argon2Iterations: 3, argon2Parallelism: 1,
    });
  });
});

describe('resource bounds', () => {
  it('refuses an absurd memory request that would DoS the client', () => {
    expect(() => assertKsfMeetsMinimum(serverOffering(MAX_ARGON2_MEMORY_KIB + 1, 3)))
      .toThrow(/ceiling/);
  });

  it('accepts memory exactly at the ceiling', () => {
    expect(() => assertKsfMeetsMinimum(serverOffering(MAX_ARGON2_MEMORY_KIB, 3))).not.toThrow();
  });

  it('refuses an absurd iteration count that would hang the client', () => {
    // Argon2id cost is linear in iterations, so an unbounded value is the same DoS the memory
    // ceiling exists to prevent: Integer.MAX_VALUE iterations extrapolates to well over a year.
    expect(() => assertKsfMeetsMinimum(serverOffering(65536, MAX_ARGON2_ITERATIONS + 1)))
      .toThrow(/ceiling/);
    expect(() => assertKsfMeetsMinimum(serverOffering(65536, 2147483647))).toThrow(/ceiling/);
  });

  it('accepts iterations exactly at the ceiling', () => {
    expect(() => assertKsfMeetsMinimum(serverOffering(65536, MAX_ARGON2_ITERATIONS)))
      .not.toThrow();
  });

  it('refuses parallelism above the ceiling', () => {
    expect(() => assertKsfMeetsMinimum({
      cipherSuite: 'P256_SHA256', context: 'ctx',
      argon2MemoryKib: 65536, argon2Iterations: 3,
      argon2Parallelism: MAX_ARGON2_PARALLELISM + 1,
    })).toThrow(/between 1 and/);
  });

  it('refuses parallelism below 1', () => {
    expect(() => assertKsfMeetsMinimum({
      cipherSuite: 'P256_SHA256', context: 'ctx',
      argon2MemoryKib: 65536, argon2Iterations: 3, argon2Parallelism: 0,
    })).toThrow(/between 1 and/);
  });
});
