package com.codeheadsystems.hofmann.springboot.config;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.codeheadsystems.rfc.opaque.config.OpaqueConfig;
import java.security.SecureRandom;
import org.junit.jupiter.api.Test;

class IdentityKsfEnforcementTest {

  private final HofmannAutoConfiguration autoConfig = new HofmannAutoConfiguration();
  private final SecureRandom secureRandom = new SecureRandom();

  @Test
  void identityKsf_rejectedByDefault() {
    HofmannProperties props = new HofmannProperties();
    props.setArgon2MemoryKib(0);
    // allowIdentityKsf defaults to false
    assertThatThrownBy(() -> autoConfig.opaqueConfig(props, secureRandom))
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining("allow-identity-ksf");
  }

  @Test
  void identityKsf_allowedWhenExplicitlyEnabled() {
    HofmannProperties props = new HofmannProperties();
    props.setArgon2MemoryKib(0);
    props.setAllowIdentityKsf(true);
    OpaqueConfig config = autoConfig.opaqueConfig(props, secureRandom);
    assertThat(config.ksf()).isInstanceOf(OpaqueConfig.IdentityKsf.class);
  }

  @Test
  void argon2id_allowedWithoutFlag() {
    HofmannProperties props = new HofmannProperties();
    // default argon2MemoryKib is 65536, allowIdentityKsf is false — should work fine
    OpaqueConfig config = autoConfig.opaqueConfig(props, secureRandom);
    assertThat(config.ksf()).isInstanceOf(OpaqueConfig.Argon2idKsf.class);
  }
}
