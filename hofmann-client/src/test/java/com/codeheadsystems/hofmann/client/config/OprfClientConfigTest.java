package com.codeheadsystems.hofmann.client.config;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.codeheadsystems.hofmann.client.exceptions.OprfModeNotEnabledException;
import com.codeheadsystems.hofmann.client.exceptions.OprfPublicKeyMismatchException;
import com.codeheadsystems.hofmann.model.oprf.OprfClientConfigResponse;
import com.codeheadsystems.hofmann.model.oprf.OprfModeInfo;
import com.codeheadsystems.rfc.oprf.rfc9497.CurveHashSuite;
import com.codeheadsystems.rfc.oprf.rfc9497.OprfCipherSuite;
import com.codeheadsystems.rfc.oprf.rfc9497.OprfMode;
import java.util.List;
import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.Test;

/**
 * Pinning, mode-specific suite derivation, and the config cross-check.
 *
 * <p>{@code assertMatches} is a diagnostic rather than a security control — the response it reads
 * is unauthenticated, so it can only refuse, never accept. These tests pin that down in both
 * directions: it must fail loudly on a real disagreement, and it must not fail on a difference
 * that is only a spelling (hex case), because a false mismatch refuses a perfectly good server.
 */
class OprfClientConfigTest {

  private static final String VOPRF_KEY =
      "02f4a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f";
  private static final String POPRF_KEY =
      "0311223344556677889900aabbccddeeff11223344556677889900aabbccddeeff";

  private static OprfClientConfig config() {
    return new OprfClientConfig(
        OprfCipherSuite.builder().withSuite(CurveHashSuite.P256_SHA256).build());
  }

  // ─── Pinning ───────────────────────────────────────────────────────────────

  @Test
  void defaultConfig_pinsNothing() {
    assertThat(config().pinnedPublicKey(OprfMode.VOPRF)).isNull();
    assertThat(config().pinnedPublicKey(OprfMode.POPRF)).isNull();
  }

  /**
   * The structural guarantee: there is no path from an HTTP response into a pinned key. A proof
   * graded against a key the same server supplied proves nothing.
   */
  @Test
  void fromServerConfig_carriesTheSuiteButPinsNothing() {
    OprfClientConfig cfg = OprfClientConfig.fromServerConfig(
        new OprfClientConfigResponse("P256_SHA256", List.of(
            new OprfModeInfo("VOPRF", VOPRF_KEY, "proc", 64),
            new OprfModeInfo("POPRF", POPRF_KEY, "proc", 64))));

    assertThat(cfg.suite().curveHashSuite()).isEqualTo(CurveHashSuite.P256_SHA256);
    assertThat(cfg.pinnedPublicKey(OprfMode.VOPRF)).isNull();
    assertThat(cfg.pinnedPublicKey(OprfMode.POPRF)).isNull();
  }

  @Test
  void withVoprfServerPublicKey_pinsOnlyThatMode() {
    OprfClientConfig cfg = config().withVoprfServerPublicKey(VOPRF_KEY);

    assertThat(cfg.pinnedPublicKey(OprfMode.VOPRF)).isEqualTo(Hex.decode(VOPRF_KEY));
    assertThat(cfg.pinnedPublicKey(OprfMode.POPRF)).isNull();
  }

  @Test
  void withPoprfServerPublicKey_pinsOnlyThatMode() {
    OprfClientConfig cfg = config().withPoprfServerPublicKey(POPRF_KEY);

    assertThat(cfg.pinnedPublicKey(OprfMode.POPRF)).isEqualTo(Hex.decode(POPRF_KEY));
    assertThat(cfg.pinnedPublicKey(OprfMode.VOPRF)).isNull();
  }

  @Test
  void withBothKeys_pinsBothIndependently() {
    OprfClientConfig cfg = config()
        .withVoprfServerPublicKey(VOPRF_KEY)
        .withPoprfServerPublicKey(POPRF_KEY);

    assertThat(cfg.pinnedPublicKey(OprfMode.VOPRF)).isEqualTo(Hex.decode(VOPRF_KEY));
    assertThat(cfg.pinnedPublicKey(OprfMode.POPRF)).isEqualTo(Hex.decode(POPRF_KEY));
  }

  @Test
  void pinnedPublicKey_baseMode_isRejected() {
    assertThatThrownBy(() -> config().pinnedPublicKey(OprfMode.OPRF))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("Base mode has no server public key");
  }

  @Test
  void pinnedPublicKey_nonHex_saysSoRatherThanFailingLater() {
    assertThatThrownBy(() -> config().withVoprfServerPublicKey("zzz").pinnedPublicKey(OprfMode.VOPRF))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("not valid hex");
  }

  @Test
  void pinnedPublicKey_blankIsTreatedAsUnpinned() {
    assertThat(config().withVoprfServerPublicKey("   ").pinnedPublicKey(OprfMode.VOPRF)).isNull();
  }

  // ─── Mode-specific suites ──────────────────────────────────────────────────

  /**
   * The mode byte is in every domain-separation tag, so a base-mode suite handed to a verifiable
   * manager computes a different function rather than failing. These accessors are what stop a
   * caller having to know that.
   */
  @Test
  void voprfSuite_andPoprfSuite_keepTheCurveAndChangeOnlyTheMode() {
    OprfClientConfig cfg = config();

    assertThat(cfg.suite().mode()).isEqualTo(OprfMode.OPRF);
    assertThat(cfg.voprfSuite().mode()).isEqualTo(OprfMode.VOPRF);
    assertThat(cfg.poprfSuite().mode()).isEqualTo(OprfMode.POPRF);
    assertThat(cfg.voprfSuite().curveHashSuite()).isEqualTo(CurveHashSuite.P256_SHA256);
    assertThat(cfg.poprfSuite().curveHashSuite()).isEqualTo(CurveHashSuite.P256_SHA256);
    assertThat(cfg.voprfSuite().contextString()).isNotEqualTo(cfg.poprfSuite().contextString());
  }

  @Test
  void modeSuites_workForEveryCurve() {
    for (CurveHashSuite curve : CurveHashSuite.values()) {
      OprfClientConfig cfg = new OprfClientConfig(
          OprfCipherSuite.builder().withSuite(curve).build());

      assertThat(cfg.voprfSuite().curveHashSuite()).isEqualTo(curve);
      assertThat(cfg.poprfSuite().mode()).isEqualTo(OprfMode.POPRF);
    }
  }

  // ─── assertMatches ─────────────────────────────────────────────────────────

  private static OprfClientConfigResponse advertising(final String mode, final String keyHex) {
    return new OprfClientConfigResponse("P256_SHA256",
        List.of(new OprfModeInfo(mode, keyHex, "proc", 64)));
  }

  /**
   * State one of three: no mode list at all — an older server, or one with no verifiable mode.
   * Nothing can be cross-checked, so it proceeds and leaves the endpoint's 404 as the probe.
   */
  @Test
  void assertMatches_absentModeList_proceeds() {
    assertThatCode(() -> config().withVoprfServerPublicKey(VOPRF_KEY)
        .assertMatches(new OprfClientConfigResponse("P256_SHA256"), OprfMode.VOPRF))
        .doesNotThrowAnyException();
  }

  @Test
  void assertMatches_nullResponse_proceeds() {
    assertThatCode(() -> config().withVoprfServerPublicKey(VOPRF_KEY)
        .assertMatches(null, OprfMode.VOPRF))
        .doesNotThrowAnyException();
  }

  /** State two: the mode is listed and the keys agree. */
  @Test
  void assertMatches_matchingKey_proceeds() {
    assertThatCode(() -> config().withVoprfServerPublicKey(VOPRF_KEY)
        .assertMatches(advertising("VOPRF", VOPRF_KEY), OprfMode.VOPRF))
        .doesNotThrowAnyException();
  }

  /**
   * Hex case is a spelling difference, not a disagreement. Comparing the strings rather than the
   * decoded bytes would refuse a perfectly good server.
   */
  @Test
  void assertMatches_differingHexCase_isNotAMismatch() {
    assertThatCode(() -> config().withVoprfServerPublicKey(VOPRF_KEY.toUpperCase())
        .assertMatches(advertising("VOPRF", VOPRF_KEY.toLowerCase()), OprfMode.VOPRF))
        .doesNotThrowAnyException();
  }

  @Test
  void assertMatches_surroundingWhitespace_isNotAMismatch() {
    assertThatCode(() -> config().withVoprfServerPublicKey("  " + VOPRF_KEY + "  ")
        .assertMatches(advertising("VOPRF", " " + VOPRF_KEY + " "), OprfMode.VOPRF))
        .doesNotThrowAnyException();
  }

  /** The case this whole mechanism exists for. */
  @Test
  void assertMatches_differentKey_failsLoudlyAndExplainsBothCauses() {
    assertThatThrownBy(() -> config().withVoprfServerPublicKey(VOPRF_KEY)
        .assertMatches(advertising("VOPRF", POPRF_KEY), OprfMode.VOPRF))
        .isInstanceOf(OprfPublicKeyMismatchException.class)
        .hasMessageContaining("rotated its key")
        .hasMessageContaining("Refusing to proceed");
  }

  /**
   * A {@code SecurityException}, not an {@code OprfAccessorException} — this says the peer is not
   * who was pinned, and must not be swallowed by a catch written for transport trouble.
   */
  @Test
  void assertMatches_mismatch_isASecurityException() {
    assertThatThrownBy(() -> config().withVoprfServerPublicKey(VOPRF_KEY)
        .assertMatches(advertising("VOPRF", POPRF_KEY), OprfMode.VOPRF))
        .isInstanceOf(SecurityException.class);
  }

  /** State three: the server publishes a complete list and this mode is not on it. */
  @Test
  void assertMatches_modeNotAdvertised_failsBeforeARoundTrip() {
    assertThatThrownBy(() -> config().withPoprfServerPublicKey(POPRF_KEY)
        .assertMatches(advertising("VOPRF", VOPRF_KEY), OprfMode.POPRF))
        .isInstanceOf(OprfModeNotEnabledException.class)
        .hasMessageContaining("POPRF");
  }

  @Test
  void assertMatches_emptyModeList_meansEveryModeIsOff() {
    assertThatThrownBy(() -> config().withVoprfServerPublicKey(VOPRF_KEY)
        .assertMatches(new OprfClientConfigResponse("P256_SHA256", List.of()), OprfMode.VOPRF))
        .isInstanceOf(OprfModeNotEnabledException.class);
  }

  @Test
  void assertMatches_suiteDisagreement_failsWithTheReason() {
    assertThatThrownBy(() -> config()
        .assertMatches(new OprfClientConfigResponse("P384_SHA384"), OprfMode.VOPRF))
        .isInstanceOf(OprfPublicKeyMismatchException.class)
        .hasMessageContaining("P256_SHA256")
        .hasMessageContaining("P384_SHA384");
  }

  /**
   * An unpinned client still gets the mode-availability half of the check, but has no key to
   * compare — so a listed mode is simply accepted.
   */
  @Test
  void assertMatches_unpinnedButModeAdvertised_proceeds() {
    assertThatCode(() -> config().assertMatches(advertising("VOPRF", VOPRF_KEY), OprfMode.VOPRF))
        .doesNotThrowAnyException();
  }

  @Test
  void assertMatches_advertisedKeyNotHex_isAMismatchRatherThanACrash() {
    assertThatThrownBy(() -> config().withVoprfServerPublicKey(VOPRF_KEY)
        .assertMatches(advertising("VOPRF", "not-hex"), OprfMode.VOPRF))
        .isInstanceOf(OprfPublicKeyMismatchException.class)
        .hasMessageContaining("not valid hex");
  }

  @Test
  void assertMatches_modeNameCaseIsIgnored() {
    assertThatCode(() -> config().withVoprfServerPublicKey(VOPRF_KEY)
        .assertMatches(advertising("voprf", VOPRF_KEY), OprfMode.VOPRF))
        .doesNotThrowAnyException();
  }
}
