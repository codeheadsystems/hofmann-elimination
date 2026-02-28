/**
 * Key Stretching Function (KSF) interface and implementations for OPAQUE.
 *
 * The KSF stretches the raw OPRF output before it is fed into HKDF-Extract
 * to produce randomized_pwd. The server and client must use identical KSF
 * parameters, otherwise the derived keys will not match.
 */

/**
 * A KSF receives the raw OPRF output and returns the stretched output.
 * Both input and output are 32-byte arrays for P-256/SHA-256.
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
 */
export function argon2idKsf(memoryKib: number, iterations: number, parallelism: number): KSF {
  return async (input: Uint8Array): Promise<Uint8Array> => {
    const { argon2id } = await import('hash-wasm');
    return argon2id({
      password: input,
      salt: new Uint8Array(32),  // 32-byte zero salt per OPAQUE convention
      iterations,
      parallelism,
      memorySize: memoryKib,
      hashLength: 32,
      outputType: 'binary',
    });
  };
}
