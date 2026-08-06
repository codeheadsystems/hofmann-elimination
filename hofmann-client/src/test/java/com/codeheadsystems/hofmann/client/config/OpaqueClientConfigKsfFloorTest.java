package com.codeheadsystems.hofmann.client.config;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.codeheadsystems.hofmann.model.opaque.OpaqueClientConfigResponse;
import com.codeheadsystems.rfc.opaque.config.OpaqueConfig;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

/**
 * In OPAQUE the key-stretching function runs entirely on the client, so the Argon2id
 * parameters decide how expensive an offline dictionary attack is against the record the
 * server stores. Taking them from the server unchecked lets a malicious, breached, or MITM'd
 * server switch its own users' password hashing off — and because it keeps serving the same
 * config afterwards, authentication continues to work and nothing looks wrong.
 */
class OpaqueClientConfigKsfFloorTest {

  private static OpaqueClientConfigResponse serverOffering(int memoryKib, int iterations) {
    return new OpaqueClientConfigResponse("P256_SHA256", "ctx", memoryKib, iterations, 1);
  }

  @Test
  void identityKsfFromServerIsRefused() {
    assertThatThrownBy(() -> OpaqueClientConfig.fromServerConfig(serverOffering(0, 0)))
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining("identity KSF")
        .hasMessageContaining("offline dictionary attack");
  }

  @ParameterizedTest(name = "memory={0} KiB, iterations={1}")
  @CsvSource({
      "8, 1",          // the quiet variant of the same attack
      "1024, 3",       // plausible-looking but far below the floor
      "19455, 2",      // one KiB under
      "65536, 1",      // strong memory, too few iterations
  })
  void belowFloorParametersAreRefused(int memoryKib, int iterations) {
    assertThatThrownBy(
        () -> OpaqueClientConfig.fromServerConfig(serverOffering(memoryKib, iterations)))
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining("below the client's minimum");
  }

  @ParameterizedTest(name = "memory={0} KiB, iterations={1}")
  @CsvSource({
      "19456, 2",      // exactly at the floor
      "65536, 3",      // the server's own default
      "131072, 4",
  })
  void atOrAboveFloorIsAccepted(int memoryKib, int iterations) {
    assertThatCode(() -> OpaqueClientConfig.fromServerConfig(serverOffering(memoryKib, iterations)))
        .doesNotThrowAnyException();
  }

  @Test
  void acceptedConfigUsesTheServerParameters() {
    OpaqueConfig cfg =
        OpaqueClientConfig.fromServerConfig(serverOffering(65536, 3)).opaqueConfig();

    assertThat(cfg.argon2Memory()).isEqualTo(65536);
    assertThat(cfg.argon2Iterations()).isEqualTo(3);
  }

  /**
   * The opt-in must be a local decision. A server cannot set this flag — it exists so a
   * developer running against a dev server configured with {@code allowIdentityKsf} can say so
   * explicitly at the call site.
   */
  @Test
  void explicitLocalOptInAllowsIdentityKsf() {
    assertThatCode(() -> OpaqueClientConfig.fromServerConfig(serverOffering(0, 0), true))
        .doesNotThrowAnyException();
  }

  @Test
  void explicitLocalOptInAllowsBelowFloorParameters() {
    assertThatCode(() -> OpaqueClientConfig.fromServerConfig(serverOffering(8, 1), true))
        .doesNotThrowAnyException();
  }

  @Test
  void absurdMemoryRequestIsRefused() {
    assertThatThrownBy(() -> OpaqueClientConfig.fromServerConfig(
        serverOffering(OpaqueClientConfig.MAX_ARGON2_MEMORY_KIB + 1, 3)))
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining("ceiling");
  }

  @Test
  void absurdIterationCountIsRefused() {
    // Argon2id cost is linear in iterations, so an unbounded value is the same DoS the memory
    // ceiling exists to prevent: Integer.MAX_VALUE iterations extrapolates to well over a year.
    assertThatThrownBy(() -> OpaqueClientConfig.fromServerConfig(
        serverOffering(65536, OpaqueClientConfig.MAX_ARGON2_ITERATIONS + 1)))
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining("ceiling");
    assertThatThrownBy(
        () -> OpaqueClientConfig.fromServerConfig(serverOffering(65536, Integer.MAX_VALUE)))
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining("ceiling");
  }

  @Test
  void iterationsExactlyAtTheCeilingAreAccepted() {
    assertThatCode(() -> OpaqueClientConfig.fromServerConfig(
        serverOffering(65536, OpaqueClientConfig.MAX_ARGON2_ITERATIONS)))
        .doesNotThrowAnyException();
  }

  @Test
  void parallelismAboveTheCeilingIsRefused() {
    assertThatThrownBy(() -> OpaqueClientConfig.fromServerConfig(
        new OpaqueClientConfigResponse("P256_SHA256", "ctx", 65536, 3,
            OpaqueClientConfig.MAX_ARGON2_PARALLELISM + 1)))
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining("between 1 and");
  }

  @Test
  void parallelismBelowOneIsRefused() {
    assertThatThrownBy(() -> OpaqueClientConfig.fromServerConfig(
        new OpaqueClientConfigResponse("P256_SHA256", "ctx", 65536, 3, 0)))
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining("between 1 and");
  }

  /**
   * Jackson binds these fields to {@code int}, so a non-numeric payload is refused before it
   * ever reaches the floor check. This is what makes the Java client immune to the type
   * confusion that defeats a magnitude-only guard in TypeScript.
   */
  @Test
  void negativeMemoryIsRefused() {
    assertThatThrownBy(() -> OpaqueClientConfig.fromServerConfig(serverOffering(-1, 3)))
        .isInstanceOf(IllegalStateException.class);
    assertThatThrownBy(
        () -> OpaqueClientConfig.fromServerConfig(serverOffering(Integer.MIN_VALUE, 3)))
        .isInstanceOf(IllegalStateException.class);
  }

  @Test
  void floorMatchesTheDocumentedOwaspMinimum() {
    assertThat(OpaqueClientConfig.MIN_ARGON2_MEMORY_KIB).isEqualTo(19456);
    assertThat(OpaqueClientConfig.MIN_ARGON2_ITERATIONS).isEqualTo(2);
  }
}
