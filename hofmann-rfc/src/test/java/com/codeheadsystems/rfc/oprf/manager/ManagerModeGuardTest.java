package com.codeheadsystems.rfc.oprf.manager;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.codeheadsystems.rfc.oprf.model.ServerProcessorDetail;
import com.codeheadsystems.rfc.oprf.model.VerifiableProcessorDetail;
import com.codeheadsystems.rfc.oprf.rfc9497.CurveHashSuite;
import com.codeheadsystems.rfc.oprf.rfc9497.OprfCipherSuite;
import com.codeheadsystems.rfc.oprf.rfc9497.OprfMode;
import java.math.BigInteger;
import org.junit.jupiter.api.Test;

/**
 * Every manager rejects a suite in the wrong mode at construction.
 *
 * <p>{@code OPRF.md} has stated this as a property of all six managers since the verifiable modes
 * landed — "Managers reject a suite in the wrong mode at construction, because the mismatch is
 * otherwise silent" — and four of them enforced it. The two base-mode managers did not, so the
 * sentence was true of the modes that were added and false of the mode it was originally written
 * about.
 *
 * <p>Nothing downstream noticed, because a mode mismatch does not fail. The mode byte is folded
 * into {@code contextString}, so a base-mode manager handed a VOPRF suite computes every
 * domain-separation tag under {@code 0x01} and returns a well-formed, stable hash of a different
 * function — one no base-mode counterpart can reproduce and no proof is ever checked against. The
 * natural way to reach it is to build one suite for a curve and reuse it across modes.
 *
 * <p>This is a class rather than two assertions because the guard is only worth having if it holds
 * for the whole set: the value of "managers reject a wrong-mode suite" is that a reader can rely on
 * it without checking which manager they are holding.
 */
class ManagerModeGuardTest {

  private static final BigInteger MASTER_KEY = BigInteger.valueOf(42);

  private static OprfCipherSuite suite(final OprfMode mode) {
    return OprfCipherSuite.builder().withSuite(CurveHashSuite.P256_SHA256).withMode(mode).build();
  }

  /** A public key derived under {@code mode}, for constructing a verifiable-mode client. */
  private static byte[] publicKey(final OprfMode mode) {
    OprfCipherSuite s = suite(mode);
    return VerifiableProcessorDetail.derive(s, s.randomScalar(), "key-v1").publicKey();
  }

  // ─── base mode: the gap this class was written for ──────────────────────────

  @Test
  void baseClientManagerRejectsAVerifiableSuite() {
    for (OprfMode wrong : new OprfMode[] {OprfMode.VOPRF, OprfMode.POPRF}) {
      assertThatThrownBy(() -> new OprfClientManager(suite(wrong)))
          .as("OprfClientManager must refuse a %s suite", wrong)
          .isInstanceOf(IllegalArgumentException.class)
          .hasMessageContaining(wrong.name())
          .hasMessageContaining(OprfMode.OPRF.name());
    }
  }

  @Test
  void baseServerManagerRejectsAVerifiableSuite() {
    ServerProcessorDetail detail = new ServerProcessorDetail(MASTER_KEY, "key-v1");
    for (OprfMode wrong : new OprfMode[] {OprfMode.VOPRF, OprfMode.POPRF}) {
      assertThatThrownBy(() -> new OprfServerManager(suite(wrong), () -> detail))
          .as("OprfServerManager must refuse a %s suite", wrong)
          .isInstanceOf(IllegalArgumentException.class)
          .hasMessageContaining(wrong.name())
          .hasMessageContaining(OprfMode.OPRF.name());
    }
  }

  // ─── the four that already enforced it, pinned so the set stays whole ───────

  @Test
  void verifiableManagersRejectABaseModeSuite() {
    OprfCipherSuite base = suite(OprfMode.OPRF);
    byte[] voprfKey = publicKey(OprfMode.VOPRF);
    byte[] poprfKey = publicKey(OprfMode.POPRF);
    VerifiableProcessorDetail voprfDetail =
        VerifiableProcessorDetail.derive(suite(OprfMode.VOPRF), MASTER_KEY, "key-v1");
    VerifiableProcessorDetail poprfDetail =
        VerifiableProcessorDetail.derive(suite(OprfMode.POPRF), MASTER_KEY, "key-v1");

    assertThatThrownBy(() -> new VoprfClientManager(base, voprfKey))
        .isInstanceOf(IllegalArgumentException.class);
    assertThatThrownBy(() -> new VoprfServerManager(base, () -> voprfDetail))
        .isInstanceOf(IllegalArgumentException.class);
    assertThatThrownBy(() -> new PoprfClientManager(base, poprfKey))
        .isInstanceOf(IllegalArgumentException.class);
    assertThatThrownBy(() -> new PoprfServerManager(base, () -> poprfDetail))
        .isInstanceOf(IllegalArgumentException.class);
  }

  /** VOPRF and POPRF are both verifiable; neither may stand in for the other. */
  @Test
  void theTwoVerifiableModesAreNotInterchangeable() {
    VerifiableProcessorDetail voprfDetail =
        VerifiableProcessorDetail.derive(suite(OprfMode.VOPRF), MASTER_KEY, "key-v1");
    VerifiableProcessorDetail poprfDetail =
        VerifiableProcessorDetail.derive(suite(OprfMode.POPRF), MASTER_KEY, "key-v1");

    assertThatThrownBy(() -> new VoprfClientManager(suite(OprfMode.POPRF), publicKey(OprfMode.POPRF)))
        .isInstanceOf(IllegalArgumentException.class);
    assertThatThrownBy(() -> new PoprfClientManager(suite(OprfMode.VOPRF), publicKey(OprfMode.VOPRF)))
        .isInstanceOf(IllegalArgumentException.class);
    assertThatThrownBy(() -> new VoprfServerManager(suite(OprfMode.POPRF), () -> poprfDetail))
        .isInstanceOf(IllegalArgumentException.class);
    assertThatThrownBy(() -> new PoprfServerManager(suite(OprfMode.VOPRF), () -> voprfDetail))
        .isInstanceOf(IllegalArgumentException.class);
  }

  // ─── the matching case still works ──────────────────────────────────────────

  @Test
  void eachManagerAcceptsItsOwnMode() {
    ServerProcessorDetail baseDetail = new ServerProcessorDetail(MASTER_KEY, "key-v1");
    VerifiableProcessorDetail voprfDetail =
        VerifiableProcessorDetail.derive(suite(OprfMode.VOPRF), MASTER_KEY, "key-v1");
    VerifiableProcessorDetail poprfDetail =
        VerifiableProcessorDetail.derive(suite(OprfMode.POPRF), MASTER_KEY, "key-v1");

    assertThatCode(() -> {
      new OprfClientManager(suite(OprfMode.OPRF));
      new OprfServerManager(suite(OprfMode.OPRF), () -> baseDetail);
      new VoprfClientManager(suite(OprfMode.VOPRF), voprfDetail.publicKey());
      new VoprfServerManager(suite(OprfMode.VOPRF), () -> voprfDetail);
      new PoprfClientManager(suite(OprfMode.POPRF), poprfDetail.publicKey());
      new PoprfServerManager(suite(OprfMode.POPRF), () -> poprfDetail);
    }).doesNotThrowAnyException();
  }
}
