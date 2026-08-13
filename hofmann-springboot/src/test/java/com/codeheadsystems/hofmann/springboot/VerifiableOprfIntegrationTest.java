package com.codeheadsystems.hofmann.springboot;

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
import java.net.URI;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.test.context.TestPropertySource;

/**
 * The Spring adapter's VOPRF and POPRF endpoints, driven over real HTTP by the real client stack.
 *
 * <p>Deliberately parallel to the Dropwizard {@code OprfVerifiableIntegrationTest}, down to the
 * master keys. The two adapters share {@code VerifiableKeyConfig} precisely so a client cannot get
 * a different answer from each, and asserting the same facts against both is what would notice if
 * that stopped being true.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@TestPropertySource(properties = {
    "hofmann.oprf-cipher-suite=P256_SHA256",
    "hofmann.voprf-master-key-hex="
        + VerifiableOprfIntegrationTest.VOPRF_MASTER_KEY_HEX,
    "hofmann.poprf-master-key-hex="
        + VerifiableOprfIntegrationTest.POPRF_MASTER_KEY_HEX,
})
class VerifiableOprfIntegrationTest {

  /**
   * Fixed, not ephemeral. The value of a verifiable mode is that the client pins the server's
   * public key, so a key regenerated on restart would invalidate every pin.
   */
  static final String VOPRF_MASTER_KEY_HEX =
      "4a1f9c3e7b25d8064f13a9e5c72b8d40e916f3a7c5b2d894e0163a7fc9d5b2e8";
  static final String POPRF_MASTER_KEY_HEX =
      "7d2e5b91c4f38a06e7b1d945c83f2b60a94e7d31f85c206b3e7a9d148f5c2b30";

  private static final String SUITE = "P256_SHA256";
  private static final ServerIdentifier SERVER_ID = new ServerIdentifier("local");
  private static final byte[] INPUT_A = "verifiable-alpha".getBytes(StandardCharsets.UTF_8);
  private static final byte[] INPUT_B = "verifiable-beta".getBytes(StandardCharsets.UTF_8);
  private static final byte[] INFO = "tenant-a".getBytes(StandardCharsets.UTF_8);

  @LocalServerPort
  private int port;

  private static String publicKeyHex(final OprfMode mode, final String masterKeyHex,
                                     final String processorId) {
    OprfCipherSuite suite = VerifiableKeyConfig.suiteFor(SUITE, mode, new SecureRandom());
    return HexFormat.of().formatHex(
        VerifiableKeyConfig.detailFrom(suite, masterKeyHex, processorId, "test").publicKey());
  }

  private HofmannOprfAccessor accessor() {
    return new HofmannOprfAccessor(new OprfClientConfig(), HttpClient.newHttpClient(),
        new ObjectMapper(),
        Map.of(SERVER_ID, new ServerConnectionInfo(
            URI.create("http://localhost:" + port + "/oprf"))));
  }

  /**
   * The processor identifiers the adapter derives are read back from the advertised config rather
   * than hardcoded here, because the two adapters spell them differently and this test is about
   * the keys, not the labels.
   */
  private HofmannOprfClientManager pinnedManager() {
    OprfClientConfigResponse advertised = accessor().getOprfConfig(SERVER_ID);
    OprfClientConfig cfg = new OprfClientConfig(
        OprfCipherSuite.builder().withSuite(SUITE).build())
        .withVoprfServerPublicKey(publicKeyHex(OprfMode.VOPRF, VOPRF_MASTER_KEY_HEX,
            modeInfo(advertised, "VOPRF").processIdentifier()))
        .withPoprfServerPublicKey(publicKeyHex(OprfMode.POPRF, POPRF_MASTER_KEY_HEX,
            modeInfo(advertised, "POPRF").processIdentifier()));
    return new HofmannOprfClientManager(accessor(), Map.of(SERVER_ID, cfg));
  }

  private static OprfModeInfo modeInfo(final OprfClientConfigResponse config, final String mode) {
    return config.modes().stream().filter(m -> m.mode().equals(mode)).findFirst().orElseThrow();
  }

  @Test
  void config_advertisesBothModes() {
    OprfClientConfigResponse config = accessor().getOprfConfig(SERVER_ID);

    assertThat(config.cipherSuite()).isEqualTo(SUITE);
    assertThat(config.modes()).extracting(OprfModeInfo::mode).containsExactly("VOPRF", "POPRF");
    assertThat(modeInfo(config, "VOPRF").publicKeyHex())
        .isNotEqualTo(modeInfo(config, "POPRF").publicKeyHex());
  }

  /**
   * The advertised key is the one a client derives independently from the same master key. If this
   * fails, the client's cross-check would reject a correctly configured server.
   */
  @Test
  void config_advertisesTheIndependentlyDerivableKey() {
    OprfClientConfigResponse config = accessor().getOprfConfig(SERVER_ID);
    OprfModeInfo voprf = modeInfo(config, "VOPRF");

    assertThat(voprf.publicKeyHex()).isEqualTo(
        publicKeyHex(OprfMode.VOPRF, VOPRF_MASTER_KEY_HEX, voprf.processIdentifier()));
  }

  @Test
  void performVerifiableHash_overRealHttp_verifiesAndReturnsAHash() {
    HofmannHashResult result = pinnedManager().performVerifiableHash(INPUT_A, SERVER_ID);

    assertThat(result.hash()).isNotEmpty();
    assertThat(result.serverIdentifier()).isEqualTo(SERVER_ID);
  }

  @Test
  void performVerifiableHash_batch_keepsOrder() {
    HofmannOprfClientManager manager = pinnedManager();

    List<HofmannHashResult> batch =
        manager.performVerifiableHash(List.of(INPUT_A, INPUT_B), SERVER_ID);

    assertThat(batch).hasSize(2);
    assertThat(batch.get(0).hash())
        .isEqualTo(manager.performVerifiableHash(INPUT_A, SERVER_ID).hash());
    assertThat(batch.get(1).hash())
        .isEqualTo(manager.performVerifiableHash(INPUT_B, SERVER_ID).hash());
  }

  @Test
  void performPartiallyObliviousHash_overRealHttp_verifiesAndReturnsAHash() {
    assertThat(pinnedManager().performPartiallyObliviousHash(INPUT_A, INFO, SERVER_ID).hash())
        .isNotEmpty();
  }

  @Test
  void performPartiallyObliviousHash_differentPublicInputs_giveUnrelatedOutputs() {
    HofmannOprfClientManager manager = pinnedManager();

    assertThat(manager.performPartiallyObliviousHash(INPUT_A, INFO, SERVER_ID).hash())
        .isNotEqualTo(manager.performPartiallyObliviousHash(
            INPUT_A, "tenant-b".getBytes(StandardCharsets.UTF_8), SERVER_ID).hash());
  }

  @Test
  void aWrongPinnedKey_failsAtTheConfigCrossCheck() {
    OprfClientConfigResponse advertised = accessor().getOprfConfig(SERVER_ID);
    OprfClientConfig wrong = new OprfClientConfig(
        OprfCipherSuite.builder().withSuite(SUITE).build())
        .withVoprfServerPublicKey(publicKeyHex(OprfMode.POPRF, POPRF_MASTER_KEY_HEX,
            modeInfo(advertised, "POPRF").processIdentifier()));
    HofmannOprfClientManager manager =
        new HofmannOprfClientManager(accessor(), Map.of(SERVER_ID, wrong));

    assertThatThrownBy(() -> manager.performVerifiableHash(INPUT_A, SERVER_ID))
        .isInstanceOf(OprfPublicKeyMismatchException.class);
  }
}
