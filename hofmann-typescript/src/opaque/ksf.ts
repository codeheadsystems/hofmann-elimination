/**
 * Key Stretching Function (KSF) interface and implementations for OPAQUE.
 *
 * The KSF stretches the raw OPRF output before it is fed into HKDF-Extract
 * to produce randomized_pwd. The server and client must use identical KSF
 * parameters, otherwise the derived keys will not match.
 */

/**
 * A KSF receives the raw OPRF output and returns the stretched output.
 * Output length depends on the cipher suite's Nh (32 for P-256, 48 for P-384, 64 for P-521).
 */
export type KSF = (input: Uint8Array) => Promise<Uint8Array>;

/**
 * Identity KSF — no stretching. Returned output equals the input.
 * Used for RFC 9807 test vectors (no Argon2id overhead).
 */
export const identityKsf: KSF = (input) => Promise.resolve(input);

/**
 * Argon2id KSF. Parameters must exactly match the server configuration.
 *
 * Server defaults (hofmann-testserver config.yml):
 *   memoryKib   = 65536  (64 MiB)
 *   iterations  = 3
 *   parallelism = 1
 *
 * @param memoryKib   Memory cost in KiB
 * @param iterations  Time cost (number of passes)
 * @param parallelism Degree of parallelism
 * @param hashLength  Output length in bytes (must match the cipher suite's Nh: 32/48/64).
 *                    Defaults to 32 for backward compatibility with P-256/SHA-256.
 */
export function argon2idKsf(memoryKib: number, iterations: number, parallelism: number, hashLength = 32): KSF {
  return async (input: Uint8Array): Promise<Uint8Array> => {
    const { argon2id } = await import('hash-wasm');
    return argon2id({
      password: input,
      salt: new Uint8Array(32),  // 32-byte zero salt per OPAQUE convention
      iterations,
      parallelism,
      memorySize: memoryKib,
      hashLength,
      outputType: 'binary',
    });
  };
}
