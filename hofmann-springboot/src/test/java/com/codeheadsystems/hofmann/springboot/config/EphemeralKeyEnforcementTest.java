package com.codeheadsystems.hofmann.springboot.config;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.security.SecureRandom;
import org.junit.jupiter.api.Test;

/**
 * Unset key material used to be generated at startup behind nothing but a {@code log.warn}, while
 * {@code oprfMasterKeyHex} and {@code allowIdentityKsf} both failed startup outright — the same
 * class of misconfiguration treated two different ways.
 *
 * <p>The generated key is random per process, so this was never a key-disclosure risk in library
 * code. The failure is availability and consistency: every node signs with a different key, so
 * tokens minted on one are rejected by another, credentials registered against one cannot
 * authenticate against another, and a restart invalidates every account. Those symptoms surface as
 * intermittent authentication failures long after deployment, which is a poor trade for a line in
 * a startup log.
 */
class EphemeralKeyEnforcementTest {

  private final HofmannAutoConfiguration autoConfig = new HofmannAutoConfiguration();
  private final SecureRandom secureRandom = new SecureRandom();

  private HofmannProperties props() {
    HofmannProperties p = new HofmannProperties();
    p.setOprfMasterKeyHex("2a");
    return p;
  }

  @Test
  void missingJwtSecretFailsStartupByDefault() {
    assertThatThrownBy(() -> autoConfig.jwtKeyDetailSupplier(props(), secureRandom))
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining("jwt-secret-hex")
        .hasMessageContaining("allow-ephemeral-keys");
  }

  @Test
  void missingJwtSecretIsAllowedWhenExplicitlyOptedIn() {
    HofmannProperties p = props();
    p.setAllowEphemeralKeys(true);

    assertThatCode(() -> autoConfig.jwtKeyDetailSupplier(p, secureRandom))
        .doesNotThrowAnyException();
  }

  @Test
  void configuredJwtSecretNeedsNoOptIn() {
    HofmannProperties p = props();
    p.setJwtSecretHex("ab".repeat(32));

    assertThatCode(() -> autoConfig.jwtKeyDetailSupplier(p, secureRandom))
        .doesNotThrowAnyException();
  }

  @Test
  void missingSeedsFailStartupByDefault() {
    HofmannProperties p = props();
    p.setJwtSecretHex("ab".repeat(32));

    assertThatThrownBy(() -> autoConfig.server(p, autoConfig.opaqueConfig(p, secureRandom)))
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining("allow-ephemeral-keys");
  }

  @Test
  void missingSeedsAreAllowedWhenExplicitlyOptedIn() {
    HofmannProperties p = props();
    p.setJwtSecretHex("ab".repeat(32));
    p.setAllowEphemeralKeys(true);

    assertThatCode(() -> autoConfig.server(p, autoConfig.opaqueConfig(p, secureRandom)))
        .doesNotThrowAnyException();
  }

  /** The opt-in must be a deliberate local decision, never the default. */
  @Test
  void ephemeralKeysAreNotAllowedByDefault() {
    assertThat(new HofmannProperties().isAllowEphemeralKeys()).isFalse();
  }
}
