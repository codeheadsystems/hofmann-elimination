package com.codeheadsystems.the.opaque.config;

import java.nio.charset.StandardCharsets;
import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.params.Argon2Parameters;

/**
 * Configuration for the OPAQUE-3DH protocol.
 * Holds Argon2id parameters, application context, and protocol constants.
 */
public record OpaqueConfig(
    int argon2Memory,
    int argon2Iterations,
    int argon2Parallelism,
    byte[] context,
    KeyStretchingFunction ksf
) {

  // Protocol constants (§ 4)
  public static final int Nn = 32;   // nonce length
  public static final int Nm = 32;   // MAC length
  public static final int Nh = 32;   // hash output length
  public static final int Nx = 32;   // HKDF output length
  public static final int Npk = 33;  // compressed SEC1 P-256 point
  public static final int Nsk = 32;  // P-256 scalar
  public static final int Noe = 33;  // compressed OPRF element
  public static final int Nok = 32;  // OPRF key length

  /**
   * Envelope size = nonce + auth_tag
   */
  public static final int ENVELOPE_SIZE = Nn + Nm;

  /**
   * Masked response size = server_public_key + envelope
   */
  public static final int MASKED_RESPONSE_SIZE = Npk + ENVELOPE_SIZE;

  /**
   * Default configuration for production use with Argon2id.
   * Context is the string "OPAQUE-3DH".
   */
  public static final OpaqueConfig DEFAULT = new OpaqueConfig(
      65536, 3, 1,
      "OPAQUE-3DH".getBytes(StandardCharsets.UTF_8),
      new Argon2idKsf()
  );

  /**
   * Creates a test configuration with Identity KSF and the CFRG test context.
   * Uses Identity KSF to match CFRG reference test vectors.
   */
  public static OpaqueConfig forTesting() {
    return new OpaqueConfig(
        0, 0, 0,
        new byte[]{0x4f, 0x50, 0x41, 0x51, 0x55, 0x45, 0x2d, 0x50, 0x4f, 0x43}, // "OPAQUE-POC"
        new IdentityKsf()
    );
  }

  /**
   * Creates a configuration with Argon2id KSF and given context.
   */
  public static OpaqueConfig withArgon2id(byte[] context, int memory, int iterations, int parallelism) {
    return new OpaqueConfig(memory, iterations, parallelism, context, new Argon2idKsf());
  }

  /**
   * Key Stretching Function interface.
   */
  public interface KeyStretchingFunction {
    byte[] stretch(byte[] input, OpaqueConfig config);
  }

  /**
   * Identity KSF: returns input unchanged. Used for CFRG test vectors.
   */
  public static class IdentityKsf implements KeyStretchingFunction {
    @Override
    public byte[] stretch(byte[] input, OpaqueConfig config) {
      return input;
    }
  }

  /**
   * Argon2id KSF. Uses the config's Argon2id parameters.
   * The salt is a 32-byte all-zero array per OPAQUE convention.
   */
  public static class Argon2idKsf implements KeyStretchingFunction {
    @Override
    public byte[] stretch(byte[] input, OpaqueConfig config) {
      // Defer to OpaqueCrypto to avoid circular import — compute inline here
      Argon2BytesGenerator gen = new Argon2BytesGenerator();
      Argon2Parameters params =
          new Argon2Parameters.Builder(
              Argon2Parameters.ARGON2_id)
              .withSalt(new byte[Nn]) // 32-byte zero salt
              .withMemoryAsKB(config.argon2Memory())
              .withIterations(config.argon2Iterations())
              .withParallelism(config.argon2Parallelism())
              .build();
      gen.init(params);
      byte[] output = new byte[Nh];
      gen.generateBytes(input, output, 0, output.length);
      return output;
    }
  }
}
