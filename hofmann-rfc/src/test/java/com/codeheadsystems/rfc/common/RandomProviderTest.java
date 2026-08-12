package com.codeheadsystems.rfc.common;

import static org.assertj.core.api.Assertions.assertThat;

import java.security.SecureRandom;
import org.junit.jupiter.api.Test;

class RandomProviderTest {

  // Removed: defaultConstructor_createsSecureRandom (isNotNull on a field the constructor cannot
  // leave null) and customRandom_isPreserved (isSameAs on a record accessor). Both are restated by
  // randomBytes_drawsFromTheInjectedRandom below, which exercises the injected instance rather
  // than asserting it was stored.

  @Test
  void randomBytes_returnsCorrectLength() {
    RandomProvider rp = new RandomProvider();
    assertThat(rp.randomBytes(0)).hasSize(0);
    assertThat(rp.randomBytes(1)).hasSize(1);
    assertThat(rp.randomBytes(32)).hasSize(32);
  }

  @Test
  void randomBytes_returnsDifferentValues() {
    RandomProvider rp = new RandomProvider();
    byte[] a = rp.randomBytes(32);
    byte[] b = rp.randomBytes(32);
    // Extremely unlikely to collide
    assertThat(a).isNotEqualTo(b);
  }

  /**
   * The injected {@link SecureRandom} must actually be the source of the bytes.
   *
   * <p>This replaces a test of the same name that asserted only {@code hasSize(16)} — which an
   * implementation ignoring the injected instance entirely, and reading from a private default
   * instead, would have passed. The injection point is load-bearing: it is how a deployment
   * supplies an entropy source, and how {@code InjectedSecureRandomReachesOpaqueTest} in the
   * dropwizard module proves the configured one reaches the crypto layer.
   *
   * <p>A subclass recording its own output is used rather than a fixed seed, because
   * {@code SecureRandom(byte[])} seeds rather than replaces the underlying algorithm and is not
   * contractually reproducible across JDK providers.
   */
  @Test
  void randomBytes_drawsFromTheInjectedRandom() {
    final byte[] canned = new byte[]{9, 8, 7, 6, 5, 4, 3, 2, 1, 0, 1, 2, 3, 4, 5, 6};
    SecureRandom stub = new SecureRandom() {
      @Override
      public void nextBytes(byte[] bytes) {
        System.arraycopy(canned, 0, bytes, 0, bytes.length);
      }
    };

    assertThat(new RandomProvider(stub).randomBytes(16)).isEqualTo(canned);
  }
}
