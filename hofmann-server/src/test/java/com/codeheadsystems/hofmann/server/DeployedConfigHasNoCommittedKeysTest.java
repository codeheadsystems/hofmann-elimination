package com.codeheadsystems.hofmann.server;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * The demo and testserver configs shipped working key material as environment-variable
 * fallbacks — {@code ${JWT_SECRET_HEX:-04fb5008...}} — and both Dockerfiles copy those files into
 * the published images. An operator running an image without setting the variables inherited a
 * signing key that is public in git history: anyone could mint valid tokens for that deployment,
 * and registrations under the equally public server key seed were forgeable.
 *
 * <p>These files are not compiled, so nothing else in the build would notice a key reappearing.
 * This test fails if one does.
 */
class DeployedConfigHasNoCommittedKeysTest {

  /** Any hex run long enough to be key material, sitting in a shell-style default. */
  private static final Pattern COMMITTED_KEY = Pattern.compile(
      // ${VAR:-<hex>} — a fallback that becomes the key when the variable is unset ...
      "\\$\\{[A-Z_]+:-\\s*[0-9a-fA-F]{16,}\\s*}"
      // ... or a hex literal committed outright, which an earlier version of this test missed.
      + "|(?i:seed|key|secret)[A-Za-z]*\\s*:\\s*\"?[0-9a-fA-F]{16,}\"?");

  static Stream<Path> deployedConfigs() {
    Path root = repositoryRoot();
    return Stream.of(
        root.resolve("hofmann-demo/server/config.yml"),
        root.resolve("hofmann-testserver/config/config.yml"));
  }

  private static Path repositoryRoot() {
    Path dir = Path.of("").toAbsolutePath();
    while (dir != null && !Files.isDirectory(dir.resolve("hofmann-demo"))) {
      dir = dir.getParent();
    }
    if (dir == null) {
      throw new IllegalStateException("could not locate the repository root");
    }
    return dir;
  }

  /** Guards the regex itself: a plainly committed key must be detected, not only a fallback. */
  @org.junit.jupiter.api.Test
  void theDetectorCatchesAPlainlyCommittedKey() {
    assertThat(COMMITTED_KEY.matcher(
        "jwtSecretHex: 04fb50080c93c055a4195cb535c9311381975a94eaaac8aeef3df0776aca4f6d").find())
        .as("a key committed without a ${VAR:-} wrapper must still be caught")
        .isTrue();
    assertThat(COMMITTED_KEY.matcher("jwtSecretHex: ${JWT_SECRET_HEX:-}").find())
        .as("the correct form must not be flagged")
        .isFalse();
  }

  @ParameterizedTest(name = "{0}")
  @MethodSource("deployedConfigs")
  void noKeyMaterialIsCommittedAsAnEnvironmentFallback(Path config) throws Exception {
    assertThat(config).exists();
    List<String> offenders = Files.readAllLines(config).stream()
        .filter(line -> !line.stripLeading().startsWith("#"))
        .filter(line -> {
          Matcher m = COMMITTED_KEY.matcher(line);
          return m.find();
        })
        .toList();

    assertThat(offenders)
        .as("%s is copied into a published image, so a committed fallback is a working key "
            + "shared by every deployment of that image — not a convenience", config.getFileName())
        .isEmpty();
  }

  /** The settings must still be present and wired to the environment, just without defaults. */
  @ParameterizedTest(name = "{0}")
  @MethodSource("deployedConfigs")
  void keySettingsAreStillWiredToTheEnvironment(Path config) throws Exception {
    String text = Files.readString(config);
    // The ":-" matters. Dropwizard's substitutor is non-strict, so a bare ${VAR} for an unset
    // variable is left as the literal string "${VAR}" — which reads as a configured value, skips
    // the fail-closed check, and dies in hex parsing instead. Asserting the bare form would pin
    // that bug in place, which an earlier version of this test did.
    assertThat(text).contains("${SERVER_KEY_SEED_HEX:-}");
    assertThat(text).contains("${OPRF_SEED_HEX:-}");
    assertThat(text).contains("${OPRF_MASTER_KEY_HEX:-}");
    assertThat(text).contains("${JWT_SECRET_HEX:-}");
  }
}
