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

  /**
   * The constant Nn.
   */
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
   *
   * @return the opaque config
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
   *
   * @param suite the suite
   * @return the opaque config
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
   *
   * @param context     the context
   * @param memory      the memory
   * @param iterations  the iterations
   * @param parallelism the parallelism
   * @return the opaque config
   */
  public static OpaqueConfig withArgon2id(byte[] context, int memory, int iterations, int parallelism) {
    return new OpaqueConfig(OpaqueCipherSuite.P256_SHA256, memory, iterations, parallelism, context, new Argon2idKsf(), new RandomProvider());
  }

  /**
   * Creates a configuration with Argon2id KSF, specified suite, and given context.
   *
   * @param suite       the suite
   * @param context     the context
   * @param memory      the memory
   * @param iterations  the iterations
   * @param parallelism the parallelism
   * @return the opaque config
   */
  public static OpaqueConfig withArgon2id(OpaqueCipherSuite suite, byte[] context,
                                          int memory, int iterations, int parallelism) {
    return new OpaqueConfig(suite, memory, iterations, parallelism, context, new Argon2idKsf(), new RandomProvider());
  }

  /**
   * Returns a new config identical to this one but using the given {@link RandomProvider}.
   *
   * @param randomProvider the random provider
   * @return the opaque config
   */
  public OpaqueConfig withRandomConfig(RandomProvider randomProvider) {
    return new OpaqueConfig(cipherSuite, argon2Memory, argon2Iterations, argon2Parallelism, context, ksf, randomProvider);
  }

  /**
   * Nm int.
   *
   * @return the int
   */
// Suite-dependent size accessors delegating to the cipher suite
  public int Nm() {
    return cipherSuite.Nm();
  }

  /**
   * Nh int.
   *
   * @return the int
   */
  public int Nh() {
    return cipherSuite.Nh();
  }

  /**
   * Nx int.
   *
   * @return the int
   */
  public int Nx() {
    return cipherSuite.Nx();
  }

  /**
   * Npk int.
   *
   * @return the int
   */
  public int Npk() {
    return cipherSuite.Npk();
  }

  /**
   * Nsk int.
   *
   * @return the int
   */
  public int Nsk() {
    return cipherSuite.Nsk();
  }

  /**
   * Noe int.
   *
   * @return the int
   */
  public int Noe() {
    return cipherSuite.Noe();
  }

  /**
   * Nok int.
   *
   * @return the int
   */
  public int Nok() {
    return cipherSuite.Nok();
  }

  /**
   * Envelope size = Nn + Nm.
   *
   * @return the int
   */
  public int envelopeSize() {
    return cipherSuite.envelopeSize();
  }

  /**
   * Masked response size = Npk + envelopeSize.
   *
   * @return the int
   */
  public int maskedResponseSize() {
    return cipherSuite.maskedResponseSize();
  }

  /**
   * Key Stretching Function interface.
   */
  public interface KeyStretchingFunction {
    /**
     * Stretch byte [ ].
     *
     * @param input  the input
     * @param config the config
     * @return the byte [ ]
     */
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
