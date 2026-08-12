package com.codeheadsystems.hofmann.integration;

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
import com.codeheadsystems.rfc.oprf.rfc9497.CurveHashSuite;
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
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.web.server.LocalServerPort;

/**
 * VOPRF and POPRF over real HTTP, across every supported cipher suite.
 *
 * <p>The per-suite sweep is the reason this class exists rather than a single P-256 test. RFC 9497
 * puts the suite identifier in every domain-separation tag and the group's own encoding rules
 * differ underneath — ristretto255 serializes scalars little-endian where the NIST curves are
 * big-endian, and its identity element has a valid encoding where theirs do not. The DLEQ proof is
 * a new code path over both, so a bug that only shows on one curve is exactly the shape of bug
 * this project has shipped before.
 *
 * <p>The pinned public keys are derived in the test from the master keys in {@code application.yml},
 * never read back from the server. A proof graded against a key the server supplied would verify
 * regardless of which key the server actually used.
 */
abstract class AbstractVerifiableOprfIntegrationTest {

  /** Must match {@code application.yml}. */
  private static final String VOPRF_MASTER_KEY_HEX =
      "4a1f9c3e7b25d8064f13a9e5c72b8d40e916f3a7c5b2d894e0163a7fc9d5b2e8";
  private static final String POPRF_MASTER_KEY_HEX =
      "7d2e5b91c4f38a06e7b1d945c83f2b60a94e7d31f85c206b3e7a9d148f5c2b30";

  protected static final ServerIdentifier SERVER_ID = new ServerIdentifier("local");

  private static final byte[] INPUT_A = "verifiable-alpha".getBytes(StandardCharsets.UTF_8);
  private static final byte[] INPUT_B = "verifiable-beta".getBytes(StandardCharsets.UTF_8);
  private static final byte[] INFO = "tenant-a".getBytes(StandardCharsets.UTF_8);

  @LocalServerPort
  private int port;

  private HofmannOprfAccessor accessor;
  private HofmannOprfClientManager manager;
  private OprfClientConfigResponse advertised;

  /**
   * Returns the cipher suite name for this test class (e.g. "P256_SHA256").
   *
   * @return the suite name
   */
  protected abstract String cipherSuiteName();

  @BeforeEach
  void setUp() {
    accessor = new HofmannOprfAccessor(new OprfClientConfig(), HttpClient.newHttpClient(),
        new ObjectMapper(),
        Map.of(SERVER_ID, new ServerConnectionInfo(
            URI.create("http://localhost:" + port + "/oprf"))));
    advertised = accessor.getOprfConfig(SERVER_ID);
    manager = new HofmannOprfClientManager(accessor, Map.of(SERVER_ID, pinnedConfig()));
  }

  private OprfClientConfig pinnedConfig() {
    return new OprfClientConfig(
        OprfCipherSuite.builder().withSuite(CurveHashSuite.valueOf(cipherSuiteName())).build())
        .withVoprfServerPublicKey(derivedPublicKeyHex(OprfMode.VOPRF))
        .withPoprfServerPublicKey(derivedPublicKeyHex(OprfMode.POPRF));
  }

  private String derivedPublicKeyHex(final OprfMode mode) {
    OprfCipherSuite suite =
        VerifiableKeyConfig.suiteFor(cipherSuiteName(), mode, new SecureRandom());
    String masterKey = mode == OprfMode.VOPRF ? VOPRF_MASTER_KEY_HEX : POPRF_MASTER_KEY_HEX;
    return HexFormat.of().formatHex(VerifiableKeyConfig.detailFrom(
        suite, masterKey, modeInfo(mode.name()).processIdentifier(), "test").publicKey());
  }

  private OprfModeInfo modeInfo(final String mode) {
    return advertised.modes().stream()
        .filter(m -> m.mode().equals(mode)).findFirst().orElseThrow();
  }

  // ─── Config advertisement ──────────────────────────────────────────────────

  @Test
  void config_advertisesBothModesForThisSuite() {
    assertThat(advertised.cipherSuite()).isEqualTo(cipherSuiteName());
    assertThat(advertised.modes()).extracting(OprfModeInfo::mode)
        .containsExactly("VOPRF", "POPRF");
  }

  /**
   * The advertised key must equal the one derived independently from the same master key. This is
   * what makes the client's cross-check usable rather than a source of false alarms.
   */
  @Test
  void config_advertisesTheIndependentlyDerivableKeys() {
    assertThat(modeInfo("VOPRF").publicKeyHex())
        .isEqualToIgnoringCase(derivedPublicKeyHex(OprfMode.VOPRF));
    assertThat(modeInfo("POPRF").publicKeyHex())
        .isEqualToIgnoringCase(derivedPublicKeyHex(OprfMode.POPRF));
  }

  /**
   * One secret must not serve two modes. The mode byte is in the DeriveKeyPair tag, so the same
   * master key would give different keys anyway — but these are different master keys, and the
   * derived public keys differing is the check that neither the config nor the derivation crossed
   * the two over.
   */
  @Test
  void config_advertisesADistinctKeyPerMode() {
    assertThat(modeInfo("VOPRF").publicKeyHex())
        .isNotEqualToIgnoringCase(modeInfo("POPRF").publicKeyHex());
  }

  // ─── VOPRF ─────────────────────────────────────────────────────────────────

  @Test
  void performVerifiableHash_verifiesAndReturnsAHash() {
    HofmannHashResult result = manager.performVerifiableHash(INPUT_A, SERVER_ID);

    assertThat(result.hash()).isNotEmpty();
    assertThat(result.serverIdentifier()).isEqualTo(SERVER_ID);
  }

  @Test
  void performVerifiableHash_batchOfTwo_isCoveredByOneProofAndKeepsOrder() {
    List<HofmannHashResult> batch =
        manager.performVerifiableHash(List.of(INPUT_A, INPUT_B), SERVER_ID);

    assertThat(batch).hasSize(2);
    assertThat(batch.get(0).hash())
        .isEqualTo(manager.performVerifiableHash(INPUT_A, SERVER_ID).hash());
    assertThat(batch.get(1).hash())
        .isEqualTo(manager.performVerifiableHash(INPUT_B, SERVER_ID).hash());
    assertThat(batch.get(0).hash()).isNotEqualTo(batch.get(1).hash());
  }

  @Test
  void performVerifiableHash_isDeterministic() {
    assertThat(manager.performVerifiableHash(INPUT_A, SERVER_ID).hash())
        .isEqualTo(manager.performVerifiableHash(INPUT_A, SERVER_ID).hash());
  }

  // ─── POPRF ─────────────────────────────────────────────────────────────────

  @Test
  void performPartiallyObliviousHash_verifiesAndReturnsAHash() {
    assertThat(manager.performPartiallyObliviousHash(INPUT_A, INFO, SERVER_ID).hash())
        .isNotEmpty();
  }

  @Test
  void performPartiallyObliviousHash_differentPublicInputs_giveUnrelatedOutputs() {
    assertThat(manager.performPartiallyObliviousHash(INPUT_A, INFO, SERVER_ID).hash())
        .isNotEqualTo(manager.performPartiallyObliviousHash(
            INPUT_A, "tenant-b".getBytes(StandardCharsets.UTF_8), SERVER_ID).hash());
  }

  /**
   * Empty is a public input, not the absence of one. RFC 9497's POPRF Finalize emits the two-byte
   * length prefix even when the info is empty, where base-mode Finalize omits it entirely — a port
   * that reuses the base-mode finalize computes a different function and nothing else notices.
   */
  @Test
  void performPartiallyObliviousHash_emptyInfo_isDistinctFromANonEmptyOne() {
    assertThat(manager.performPartiallyObliviousHash(INPUT_A, new byte[0], SERVER_ID).hash())
        .isNotEmpty()
        .isNotEqualTo(manager.performPartiallyObliviousHash(INPUT_A, INFO, SERVER_ID).hash());
  }

  @Test
  void theTwoModes_produceDifferentOutputsForTheSameInput() {
    assertThat(manager.performVerifiableHash(INPUT_A, SERVER_ID).hash())
        .isNotEqualTo(manager.performPartiallyObliviousHash(
            INPUT_A, new byte[0], SERVER_ID).hash());
  }

  // ─── Pinning ───────────────────────────────────────────────────────────────

  @Test
  void aWrongPinnedKey_failsAtTheConfigCrossCheck() {
    OprfClientConfig wrong = new OprfClientConfig(
        OprfCipherSuite.builder().withSuite(CurveHashSuite.valueOf(cipherSuiteName())).build())
        .withVoprfServerPublicKey(derivedPublicKeyHex(OprfMode.POPRF));

    assertThatThrownBy(() ->
        new HofmannOprfClientManager(accessor, Map.of(SERVER_ID, wrong))
            .performVerifiableHash(INPUT_A, SERVER_ID))
        .isInstanceOf(OprfPublicKeyMismatchException.class);
  }
}
