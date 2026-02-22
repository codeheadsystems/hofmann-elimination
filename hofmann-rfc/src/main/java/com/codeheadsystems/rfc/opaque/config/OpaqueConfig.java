package com.codeheadsystems.rfc.opaque.config;

import com.codeheadsystems.rfc.common.RandomProvider;
import java.nio.charset.StandardCharsets;
import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.params.Argon2Parameters;

/**
 * Configuration for the OPAQUE-3DH protocol.
 * Holds the cipher suite, Argon2id parameters, application context, and protocol constants.
 */
public record OpaqueConfig(
    OpaqueCipherSuite cipherSuite,
    int argon2Memory,
    int argon2Iterations,
    int argon2Parallelism,
    byte[] context,
    KeyStretchingFunction ksf,
    RandomProvider randomProvider
) {

  // Nonce length — suite-independent (always 32)
  public static final int Nn = 32;
  /**
   * Default configuration for production use with Argon2id, P256-SHA256 suite.
   * Context is the string "OPAQUE-3DH".
   */
  public static final OpaqueConfig DEFAULT = new OpaqueConfig(
      OpaqueCipherSuite.P256_SHA256,
      65536, 3, 1,
      "OPAQUE-3DH".getBytes(StandardCharsets.UTF_8),
      new Argon2idKsf(),
      new RandomProvider()
  );

  /**
   * Creates a test configuration with Identity KSF, P256-SHA256 suite, and the CFRG test context.
   */
  public static OpaqueConfig forTesting() {
    return new OpaqueConfig(
        OpaqueCipherSuite.P256_SHA256,
        0, 0, 0,
        new byte[]{0x4f, 0x50, 0x41, 0x51, 0x55, 0x45, 0x2d, 0x50, 0x4f, 0x43}, // "OPAQUE-POC"
        new IdentityKsf(),
        new RandomProvider()
    );
  }

  /**
   * Creates a test configuration for a given cipher suite with Identity KSF.
   */
  public static OpaqueConfig forTesting(OpaqueCipherSuite suite) {
    return new OpaqueConfig(
        suite,
        0, 0, 0,
        new byte[]{0x4f, 0x50, 0x41, 0x51, 0x55, 0x45, 0x2d, 0x50, 0x4f, 0x43},
        new IdentityKsf(),
        new RandomProvider()
    );
  }

  /**
   * Creates a configuration with Argon2id KSF, P256-SHA256 suite, and given context.
   */
  public static OpaqueConfig withArgon2id(byte[] context, int memory, int iterations, int parallelism) {
    return new OpaqueConfig(OpaqueCipherSuite.P256_SHA256, memory, iterations, parallelism, context, new Argon2idKsf(), new RandomProvider());
  }

  /**
   * Creates a configuration with Argon2id KSF, specified suite, and given context.
   */
  public static OpaqueConfig withArgon2id(OpaqueCipherSuite suite, byte[] context,
                                          int memory, int iterations, int parallelism) {
    return new OpaqueConfig(suite, memory, iterations, parallelism, context, new Argon2idKsf(), new RandomProvider());
  }

  /**
   * Returns a new config identical to this one but using the given {@link RandomProvider}.
   */
  public OpaqueConfig withRandomConfig(RandomProvider randomProvider) {
    return new OpaqueConfig(cipherSuite, argon2Memory, argon2Iterations, argon2Parallelism, context, ksf, randomProvider);
  }

  // Suite-dependent size accessors delegating to the cipher suite
  public int Nm() {
    return cipherSuite.Nm();
  }

  public int Nh() {
    return cipherSuite.Nh();
  }

  public int Nx() {
    return cipherSuite.Nx();
  }

  public int Npk() {
    return cipherSuite.Npk();
  }

  public int Nsk() {
    return cipherSuite.Nsk();
  }

  public int Noe() {
    return cipherSuite.Noe();
  }

  public int Nok() {
    return cipherSuite.Nok();
  }

  /**
   * Envelope size = Nn + Nm.
   */
  public int envelopeSize() {
    return cipherSuite.envelopeSize();
  }

  /**
   * Masked response size = Npk + envelopeSize.
   */
  public int maskedResponseSize() {
    return cipherSuite.maskedResponseSize();
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
      Argon2BytesGenerator gen = new Argon2BytesGenerator();
      Argon2Parameters params =
          new Argon2Parameters.Builder(
              Argon2Parameters.ARGON2_id)
              .withSalt(new byte[Nn]) // 32-byte zero salt (nonce-length, suite-independent)
              .withMemoryAsKB(config.argon2Memory())
              .withIterations(config.argon2Iterations())
              .withParallelism(config.argon2Parallelism())
              .build();
      gen.init(params);
      byte[] output = new byte[config.Nh()];
      gen.generateBytes(input, output, 0, output.length);
      return output;
    }
  }
}
