package com.codeheadsystems.rfc.opaque.config;

import com.codeheadsystems.rfc.common.RandomProvider;
import java.nio.charset.StandardCharsets;

/**
 * Configurations for tests. <strong>Not for production, and no longer reachable from it.</strong>
 *
 * <p>These were {@code OpaqueConfig.forTesting()} on the production API. The only thing standing
 * between them and a caller who wanted a config quickly was a javadoc line saying "test
 * configuration" — and what they build is a config with the identity KSF, meaning
 * <em>no password stretching whatsoever</em>. An offline attacker who obtains the credential file
 * then guesses passwords at the speed of a hash rather than the speed of Argon2id, which is the
 * single property OPAQUE's key-stretching step exists to provide.
 *
 * <p>Moving them here is what makes the boundary real rather than advisory. Test fixtures are
 * published under a separate classifier and are not on a consumer's compile classpath unless they
 * ask for them by name, so "for testing" is now enforced by the build instead of by a comment
 * somebody has to read.
 *
 * <p>The deployment layers do already refuse the identity KSF —
 * {@code allowIdentityKsf} on the server, {@code allowWeakServerKsf} on the client — so this is
 * defence in depth rather than the only guard. It closes the gap for a caller who builds an
 * {@code OpaqueConfig} directly and never passes through either.
 *
 * <p>The CFRG context {@code "OPAQUE-POC"} is the one RFC 9807's test vectors use, which is the
 * other reason these belong beside the tests: the value is meaningful for vector reproduction and
 * meaningless for a deployment, where the context is what separates one deployment's transcripts
 * from another's.
 */
public final class OpaqueTestConfigs {

  /** The context RFC 9807's published test vectors are generated under. */
  private static final byte[] CFRG_TEST_CONTEXT = "OPAQUE-POC".getBytes(StandardCharsets.US_ASCII);

  private OpaqueTestConfigs() {
  }

  /**
   * P-256/SHA-256 with the identity KSF and the CFRG test context.
   *
   * @return a configuration suitable only for tests
   */
  public static OpaqueConfig forTesting() {
    return forTesting(OpaqueCipherSuite.P256_SHA256);
  }

  /**
   * The given suite with the identity KSF and the CFRG test context.
   *
   * @param suite the cipher suite
   * @return a configuration suitable only for tests
   */
  public static OpaqueConfig forTesting(OpaqueCipherSuite suite) {
    return new OpaqueConfig(
        suite,
        0, 0, 0,
        CFRG_TEST_CONTEXT.clone(),
        new OpaqueConfig.IdentityKsf(),
        new RandomProvider());
  }
}
