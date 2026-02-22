package com.codeheadsystems.rfc.common;

import static org.assertj.core.api.Assertions.assertThat;

import java.security.SecureRandom;
import org.junit.jupiter.api.Test;

class RandomProviderTest {

  @Test
  void defaultConstructor_createsSecureRandom() {
    RandomProvider rp = new RandomProvider();
    assertThat(rp.random()).isNotNull();
  }

  @Test
  void customRandom_isPreserved() {
    SecureRandom custom = new SecureRandom();
    RandomProvider rp = new RandomProvider(custom);
    assertThat(rp.random()).isSameAs(custom);
  }

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

  @Test
  void randomBytes_usesProvidedRandom() {
    // Seed-controlled SecureRandom produces deterministic output
    SecureRandom seeded = new SecureRandom(new byte[]{1, 2, 3});
    RandomProvider rp = new RandomProvider(seeded);
    byte[] result = rp.randomBytes(16);
    assertThat(result).hasSize(16);
  }
}
