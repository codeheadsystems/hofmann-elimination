package com.codeheadsystems.hofmann.dropwizard;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.codeheadsystems.hofmann.client.accessor.HofmannOprfAccessor;
import com.codeheadsystems.hofmann.client.config.OprfClientConfig;
import com.codeheadsystems.hofmann.client.exceptions.OprfPublicKeyMismatchException;
import com.codeheadsystems.hofmann.client.manager.HofmannOprfClientManager;
import com.codeheadsystems.hofmann.client.model.HofmannHashResult;
import com.codeheadsystems.hofmann.client.model.ServerConnectionInfo;
import com.codeheadsystems.hofmann.client.model.ServerIdentifier;
import com.codeheadsystems.hofmann.model.oprf.OprfClientConfigResponse;
import com.codeheadsystems.hofmann.model.oprf.OprfModeInfo;
import com.codeheadsystems.hofmann.server.oprf.VerifiableKeyConfig;
import com.codeheadsystems.rfc.oprf.rfc9497.OprfCipherSuite;
import com.codeheadsystems.rfc.oprf.rfc9497.OprfMode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.dropwizard.testing.ResourceHelpers;
import io.dropwizard.testing.junit5.DropwizardAppExtension;
import io.dropwizard.testing.junit5.DropwizardExtensionsSupport;
import java.net.URI;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

/**
 * The VOPRF and POPRF endpoints driven over real HTTP by the real client stack.
 *
 * <p>The public keys this test pins are <strong>derived here</strong> from the same master keys
 * the server's YAML configures, rather than read back from the server. That is what makes the
 * assertions mean something: a proof graded against a key the server supplied would verify no
 * matter which key the server actually used.
 */
@ExtendWith(DropwizardExtensionsSupport.class)
class OprfVerifiableIntegrationTest {

  static final DropwizardAppExtension<HofmannConfiguration> APP =
      new DropwizardAppExtension<>(
          HofmannApplication.class,
          ResourceHelpers.resourceFilePath("test-config-verifiable.yml"));

  /** Must match test-config-verifiable.yml. */
  private static final String VOPRF_MASTER_KEY_HEX =
      "4a1f9c3e7b25d8064f13a9e5c72b8d40e916f3a7c5b2d894e0163a7fc9d5b2e8";
  private static final String POPRF_MASTER_KEY_HEX =
      "7d2e5b91c4f38a06e7b1d945c83f2b60a94e7d31f85c206b3e7a9d148f5c2b30";
  private static final String SUITE = "P256_SHA256";

  private static final ServerIdentifier SERVER_ID = new ServerIdentifier("local");
  private static final byte[] INPUT_A = "verifiable-alpha".getBytes(StandardCharsets.UTF_8);
  private static final byte[] INPUT_B = "verifiable-beta".getBytes(StandardCharsets.UTF_8);
  private static final byte[] INFO = "tenant-a".getBytes(StandardCharsets.UTF_8);

  private static String publicKeyHex(final OprfMode mode, final String masterKeyHex) {
    OprfCipherSuite suite = VerifiableKeyConfig.suiteFor(SUITE, mode, new SecureRandom());
    return HexFormat.of().formatHex(VerifiableKeyConfig.detailFrom(
        suite, masterKeyHex, "test-processor-" + mode.name().toLowerCase(), "test").publicKey());
  }

  private HofmannOprfAccessor accessor() {
    return new HofmannOprfAccessor(new OprfClientConfig(), HttpClient.newHttpClient(),
        new ObjectMapper(),
        Map.of(SERVER_ID, new ServerConnectionInfo(URI.create(baseUrl() + "/oprf"))));
  }

  private HofmannOprfClientManager pinnedManager() {
    OprfClientConfig cfg = new OprfClientConfig(
        OprfCipherSuite.builder().withSuite(SUITE).build())
        .withVoprfServerPublicKey(publicKeyHex(OprfMode.VOPRF, VOPRF_MASTER_KEY_HEX))
        .withPoprfServerPublicKey(publicKeyHex(OprfMode.POPRF, POPRF_MASTER_KEY_HEX));
    return new HofmannOprfClientManager(accessor(), Map.of(SERVER_ID, cfg));
  }

  private String baseUrl() {
    return String.format("http://localhost:%d", APP.getLocalPort());
  }

  // ─── /oprf/config ──────────────────────────────────────────────────────────

  @Test
  void config_advertisesBothModesWithTheKeysAClientMustPin() {
    OprfClientConfigResponse config = accessor().getOprfConfig(SERVER_ID);

    assertThat(config.cipherSuite()).isEqualTo(SUITE);
    assertThat(config.modes()).hasSize(2);
    assertThat(config.modes()).extracting(OprfModeInfo::mode)
        .containsExactly("VOPRF", "POPRF");
    assertThat(modeInfo(config, "VOPRF").publicKeyHex())
        .isEqualTo(publicKeyHex(OprfMode.VOPRF, VOPRF_MASTER_KEY_HEX));
    assertThat(modeInfo(config, "POPRF").publicKeyHex())
        .isEqualTo(publicKeyHex(OprfMode.POPRF, POPRF_MASTER_KEY_HEX));
  }

  /**
   * One secret must not serve two modes, and the derived public keys differing is the visible
   * consequence of the mode byte being in the DeriveKeyPair tag.
   */
  @Test
  void config_advertisesADistinctKeyPerMode() {
    OprfClientConfigResponse config = accessor().getOprfConfig(SERVER_ID);

    assertThat(modeInfo(config, "VOPRF").publicKeyHex())
        .isNotEqualTo(modeInfo(config, "POPRF").publicKeyHex());
  }

  @Test
  void config_advertisesTheBatchCapSoAClientCanRefuseLocally() {
    OprfClientConfigResponse config = accessor().getOprfConfig(SERVER_ID);

    assertThat(modeInfo(config, "VOPRF").maxBatchSize()).isEqualTo(64);
  }

  private static OprfModeInfo modeInfo(final OprfClientConfigResponse config, final String mode) {
    return config.modes().stream().filter(m -> m.mode().equals(mode)).findFirst().orElseThrow();
  }

  // ─── VOPRF ─────────────────────────────────────────────────────────────────

  @Test
  void performVerifiableHash_overRealHttp_verifiesAndReturnsAHash() {
    HofmannHashResult result = pinnedManager().performVerifiableHash(INPUT_A, SERVER_ID);

    assertThat(result.hash()).isNotEmpty();
    assertThat(result.processIdentifier()).isEqualTo("test-processor-voprf");
    assertThat(result.serverIdentifier()).isEqualTo(SERVER_ID);
  }

  @Test
  void performVerifiableHash_batch_isCoveredByOneProofAndKeepsOrder() {
    HofmannOprfClientManager manager = pinnedManager();

    List<HofmannHashResult> batch =
        manager.performVerifiableHash(List.of(INPUT_A, INPUT_B), SERVER_ID);

    assertThat(batch).hasSize(2);
    assertThat(batch.get(0).hash())
        .isEqualTo(manager.performVerifiableHash(INPUT_A, SERVER_ID).hash());
    assertThat(batch.get(1).hash())
        .isEqualTo(manager.performVerifiableHash(INPUT_B, SERVER_ID).hash());
  }

  /**
   * The key is fixed in configuration rather than ephemeral, so the same input must survive a
   * restart-shaped boundary. Within one run this is the weaker claim that evaluation is
   * deterministic, which is still the property a stored hash depends on.
   */
  @Test
  void performVerifiableHash_isDeterministic() {
    HofmannOprfClientManager manager = pinnedManager();

    assertThat(manager.performVerifiableHash(INPUT_A, SERVER_ID).hash())
        .isEqualTo(manager.performVerifiableHash(INPUT_A, SERVER_ID).hash());
  }

  // ─── POPRF ─────────────────────────────────────────────────────────────────

  @Test
  void performPartiallyObliviousHash_overRealHttp_verifiesAndReturnsAHash() {
    HofmannHashResult result =
        pinnedManager().performPartiallyObliviousHash(INPUT_A, INFO, SERVER_ID);

    assertThat(result.hash()).isNotEmpty();
    assertThat(result.processIdentifier()).isEqualTo("test-processor-poprf");
  }

  @Test
  void performPartiallyObliviousHash_differentPublicInputs_giveUnrelatedOutputs() {
    HofmannOprfClientManager manager = pinnedManager();

    assertThat(manager.performPartiallyObliviousHash(INPUT_A, INFO, SERVER_ID).hash())
        .isNotEqualTo(manager.performPartiallyObliviousHash(
            INPUT_A, "tenant-b".getBytes(StandardCharsets.UTF_8), SERVER_ID).hash());
  }

  /**
   * The two modes are separate functions on separate keys, so the same input under each must not
   * collide even with an empty public input.
   */
  @Test
  void theTwoModes_produceDifferentOutputsForTheSameInput() {
    HofmannOprfClientManager manager = pinnedManager();

    assertThat(manager.performVerifiableHash(INPUT_A, SERVER_ID).hash())
        .isNotEqualTo(manager.performPartiallyObliviousHash(
            INPUT_A, new byte[0], SERVER_ID).hash());
  }

  // ─── Pinning ───────────────────────────────────────────────────────────────

  /**
   * The diagnostic doing its job: a wrong pin fails at the config cross-check, naming the problem,
   * rather than as an unexplained proof failure after a round trip.
   */
  @Test
  void aWrongPinnedKey_failsAtTheConfigCrossCheck() {
    OprfClientConfig wrong = new OprfClientConfig(
        OprfCipherSuite.builder().withSuite(SUITE).build())
        // The POPRF key is a real key, just not this mode's.
        .withVoprfServerPublicKey(publicKeyHex(OprfMode.POPRF, POPRF_MASTER_KEY_HEX));
    HofmannOprfClientManager manager =
        new HofmannOprfClientManager(accessor(), Map.of(SERVER_ID, wrong));

    assertThatThrownBy(() -> manager.performVerifiableHash(INPUT_A, SERVER_ID))
        .isInstanceOf(OprfPublicKeyMismatchException.class)
        .hasMessageContaining("Refusing to proceed");
  }
}
