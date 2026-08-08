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

  // The forTesting() factories that used to live here are now OpaqueTestConfigs, in
  // src/testFixtures. They build a config with the identity KSF — no password stretching at all —
  // and being public on this class put them one autocomplete away from a production caller,
  // behind nothing but a javadoc line. Test fixtures publish under a separate classifier and are
  // not on a consumer's compile classpath unless asked for by name.
  //
  // What that moved is the convenience, not the capability: IdentityKsf below is still public, and
  // has to be — both framework integrations construct it directly for their documented
  // dev/test branch. So an identity-KSF config still rebuilds in one expression on this API. The
  // guards that actually stop it reaching production are allowIdentityKsf on the server and
  // allowWeakServerKsf on the client, which is what OpaqueTestConfigs' own javadoc says. An
  // earlier version of this comment claimed the build now enforced the boundary; it enforces the
  // absence of the shortcut.

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
   * <p>Public deliberately: this is how a deployment installs an HSM-backed or policy-constrained
   * randomness source into OPAQUE, not a hook for fixing nonces. A caller who supplies a stub
   * provider has done that deliberately, and no visibility change here would stop them — the same
   * stub can be handed to the constructor.
   *
   * <p>It is also the fix for a real defect rather than a hypothetical capability. Both framework
   * integrations installed the deployment's {@link RandomProvider} on the identity-KSF branch and
   * then returned {@link #withArgon2id} on the Argon2id branch, which builds its own
   * {@code new RandomProvider()} internally — so on the production path the injected source was
   * silently dropped and every masking nonce, server AKE key seed, server nonce, envelope nonce
   * and client nonce came from the platform default. Both now chain this method; see
   * {@code InjectedSecureRandomReachesOpaqueTest}.
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
   * The salt is a 16-byte all-zero array per RFC 9807, matching the
   * TypeScript and Rust implementations for cross-implementation interop.
   */
  public static class Argon2idKsf implements KeyStretchingFunction {
    @Override
    public byte[] stretch(byte[] input, OpaqueConfig config) {
      Argon2BytesGenerator gen = new Argon2BytesGenerator();
      Argon2Parameters params =
          new Argon2Parameters.Builder(
              Argon2Parameters.ARGON2_id)
              .withSalt(new byte[16]) // 16-byte zero salt per RFC 9807
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
