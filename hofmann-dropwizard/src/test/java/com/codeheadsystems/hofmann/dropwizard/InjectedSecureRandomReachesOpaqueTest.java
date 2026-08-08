package com.codeheadsystems.hofmann.dropwizard;

import static org.assertj.core.api.Assertions.assertThat;

import com.codeheadsystems.rfc.opaque.config.OpaqueConfig;
import java.lang.reflect.Method;
import java.security.SecureRandom;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;

/**
 * A {@link SecureRandom} supplied via {@code withSecureRandom} must reach OPAQUE nonce generation
 * on the <em>production</em> path, not just the identity-KSF one.
 *
 * <p>It did not. {@code buildOpaqueConfig} installed the injected source on the identity-KSF
 * branch and then returned {@code OpaqueConfig.withArgon2id(...)} on the Argon2id branch, which
 * constructs its own {@code new RandomProvider()} internally. So an operator wiring an HSM-backed
 * or otherwise policy-constrained source got it for OPRF scalars and blinds, and the platform
 * default for every masking nonce, server AKE key seed, server nonce, envelope nonce and client
 * nonce — on the branch that runs in production, and only there. Exactly inverted from the intent,
 * with no functional symptom to notice.
 *
 * <p>The bundle's own class javadoc advertises {@code withSecureRandom} for an HSM-backed source,
 * so this is the documented use case failing silently rather than an undocumented corner.
 *
 * <p>Counting rather than asserting on values: a {@link SecureRandom} that records how often it is
 * asked for bytes is the only way to observe which instance a config ended up holding, since
 * {@code RandomProvider} exposes no identity. Zero calls is the failure.
 */
class InjectedSecureRandomReachesOpaqueTest {

  /** Records every request for bytes while still producing usable randomness. */
  private static final class CountingSecureRandom extends SecureRandom {
    private final AtomicInteger calls = new AtomicInteger();
    private final SecureRandom delegate = new SecureRandom();

    @Override
    public void nextBytes(byte[] bytes) {
      calls.incrementAndGet();
      delegate.nextBytes(bytes);
    }
  }

  private OpaqueConfig buildConfigWith(CountingSecureRandom random, int argon2MemoryKib)
      throws Exception {
    HofmannConfiguration configuration = new HofmannConfiguration();
    configuration.setArgon2MemoryKib(argon2MemoryKib);
    configuration.setAllowIdentityKsf(argon2MemoryKib == 0);

    HofmannBundle<HofmannConfiguration> bundle =
        new HofmannBundle<HofmannConfiguration>().withSecureRandom(random);
    Method build = HofmannBundle.class
        .getDeclaredMethod("buildOpaqueConfig", HofmannConfiguration.class);
    build.setAccessible(true);
    return (OpaqueConfig) build.invoke(bundle, configuration);
  }

  /**
   * The Argon2id branch — what a production deployment actually runs.
   *
   * <p>This is the assertion that was failing before the fix, and no existing test covered it:
   * the integration tests all run with {@code argon2MemoryKib: 0}, so every one of them exercised
   * the branch that was already correct.
   */
  @Test
  void theArgon2idPathUsesTheInjectedSource() throws Exception {
    CountingSecureRandom random = new CountingSecureRandom();

    OpaqueConfig config = buildConfigWith(random, 1024);
    config.randomProvider().randomBytes(32);

    assertThat(random.calls.get())
        .as("the deployment's SecureRandom must generate OPAQUE nonces on the production path")
        .isPositive();
  }

  /** The identity-KSF branch was already correct; asserted so a fix here cannot regress it. */
  @Test
  void theIdentityKsfPathUsesTheInjectedSource() throws Exception {
    CountingSecureRandom random = new CountingSecureRandom();

    OpaqueConfig config = buildConfigWith(random, 0);
    config.randomProvider().randomBytes(32);

    assertThat(random.calls.get()).isPositive();
  }
}
