package com.codeheadsystems.hofmann.dropwizard;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.dropwizard.core.setup.Environment;
import org.junit.jupiter.api.Test;

/**
 * Dropwizard is the framework the demo and testserver actually run, yet the fail-closed guard for
 * unset key material was only covered on the Spring side — neutering the Dropwizard half left the
 * whole build green.
 *
 * <p>The guard is reached through {@code run()}, so these drive the bundle rather than a single
 * method. The generated key is random per process, so the risk was never key disclosure: it is
 * that nodes disagree about signing keys and a restart invalidates every account, which surfaces
 * as intermittent authentication failures long after deployment.
 */
class EphemeralKeyEnforcementTest {

  private static HofmannConfiguration configWith(String jwtSecretHex,
                                                 String keySeedHex,
                                                 String oprfSeedHex,
                                                 boolean allowEphemeral) {
    HofmannConfiguration config = new HofmannConfiguration();
    config.setOprfMasterKeyHex("2a");
    config.setJwtSecretHex(jwtSecretHex);
    config.setServerKeySeedHex(keySeedHex);
    config.setOprfSeedHex(oprfSeedHex);
    config.setAllowEphemeralKeys(allowEphemeral);
    return config;
  }

  private static void run(HofmannConfiguration config) throws Exception {
    new HofmannBundle<HofmannConfiguration>().run(config, new Environment("test"));
  }

  private static final String HEX = "ab".repeat(32);

  @Test
  void missingKeyMaterialFailsStartupByDefault() {
    assertThatThrownBy(() -> run(configWith("", "", "", false)))
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining("allowEphemeralKeys");
  }

  @Test
  void missingJwtSecretAloneFailsStartup() {
    assertThatThrownBy(() -> run(configWith("", HEX, HEX, false)))
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining("jwtSecretHex");
  }

  @Test
  void missingSeedsAloneFailStartup() {
    assertThatThrownBy(() -> run(configWith(HEX, "", "", false)))
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining("oprfSeedHex");
  }

  @Test
  void everythingConfiguredNeedsNoOptIn() {
    assertThatCode(() -> run(configWith(HEX, HEX, HEX, false))).doesNotThrowAnyException();
  }

  @Test
  void optingInPermitsEphemeralKeys() {
    assertThatCode(() -> run(configWith("", "", "", true))).doesNotThrowAnyException();
  }

  /**
   * The opt-in has to cover every piece of key material, or it is not an escape hatch: an earlier
   * version left {@code oprfMasterKeyHex} out, so the documented "set allowEphemeralKeys for a
   * throwaway run" still died on the next setting along.
   */
  @Test
  void optingInAlsoCoversTheOprfMasterKey() {
    HofmannConfiguration config = configWith("", "", "", true);
    config.setOprfMasterKeyHex("");

    assertThatCode(() -> run(config)).doesNotThrowAnyException();
  }

  @Test
  void ephemeralKeysAreNotAllowedByDefault() {
    assertThat(new HofmannConfiguration().isAllowEphemeralKeys()).isFalse();
  }
}
