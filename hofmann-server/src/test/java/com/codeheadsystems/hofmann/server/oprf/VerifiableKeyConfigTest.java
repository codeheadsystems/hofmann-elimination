package com.codeheadsystems.hofmann.server.oprf;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.codeheadsystems.rfc.oprf.model.VerifiableProcessorDetail;
import com.codeheadsystems.rfc.oprf.rfc9497.OprfCipherSuite;
import com.codeheadsystems.rfc.oprf.rfc9497.OprfMode;
import java.security.SecureRandom;
import org.junit.jupiter.api.Test;

/**
 * Startup-time handling of the VOPRF/POPRF key configuration.
 *
 * <p>These are diagnostics rather than defences — a misconfigured key fails either way. What they
 * buy is that it fails saying which property is wrong, instead of as a
 * {@code NumberFormatException: Zero length BigInteger} from inside bean construction.
 */
class VerifiableKeyConfigTest {

  private static final SecureRandom RANDOM = new SecureRandom();

  private OprfCipherSuite suite() {
    return VerifiableKeyConfig.suiteFor("P256_SHA256", OprfMode.VOPRF, RANDOM);
  }

  @Test
  void suiteFor_carriesTheRequestedMode() {
    // The mode byte is in every domain-separation tag, so a suite built for the wrong mode
    // computes a different function rather than failing.
    assertThat(VerifiableKeyConfig.suiteFor("P256_SHA256", OprfMode.VOPRF, RANDOM).mode())
        .isEqualTo(OprfMode.VOPRF);
    assertThat(VerifiableKeyConfig.suiteFor("P256_SHA256", OprfMode.POPRF, RANDOM).mode())
        .isEqualTo(OprfMode.POPRF);
  }

  @Test
  void isConfigured_treatsNullBlankAndEmptyAsAbsent() {
    assertThat(VerifiableKeyConfig.isConfigured(null)).isFalse();
    assertThat(VerifiableKeyConfig.isConfigured("")).isFalse();
    assertThat(VerifiableKeyConfig.isConfigured("   ")).isFalse();
    assertThat(VerifiableKeyConfig.isConfigured("a1")).isTrue();
  }

  @Test
  void detailFrom_validKey_derivesAMatchingPair() {
    VerifiableProcessorDetail detail = VerifiableKeyConfig.detailFrom(
        suite(), "42424242424242424242424242", "test-voprf", "hofmann.voprf-master-key-hex");

    assertThat(detail.processorIdentifier()).isEqualTo("test-voprf");
    assertThat(detail.mode()).isEqualTo(OprfMode.VOPRF);
    // derive() computes the public key rather than accepting one, so the pair cannot be mismatched.
    assertThat(detail.publicKey()).isNotEmpty();
  }

  @Test
  void detailFrom_emptyKey_isAWiringBugAndSaysSo() {
    // Both adapters treat empty as "mode disabled" and check isConfigured() first, so reaching
    // this method with an empty key means a caller skipped that check rather than an operator
    // misconfiguring. The message says which, instead of "Zero length BigInteger".
    assertThatThrownBy(() -> VerifiableKeyConfig.detailFrom(
        suite(), "", "test-voprf", "hofmann.voprf-master-key-hex"))
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining("hofmann.voprf-master-key-hex")
        .hasMessageContaining("disables the mode on both adapters");
  }

  @Test
  void detailFrom_nonHexKey_namesTheProperty() {
    assertThatThrownBy(() -> VerifiableKeyConfig.detailFrom(
        suite(), "not-hex", "test-voprf", "hofmann.voprf-master-key-hex"))
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining("hofmann.voprf-master-key-hex")
        .hasMessageContaining("not valid hex");
  }

  @Test
  void detailFrom_zeroKey_isRejected() {
    // Every evaluation under a zero key returns the identity element, which is the verifiable
    // mode's version of the P1 the base-mode key supplier already guards against. Rejected by
    // VerifiableProcessorDetail.derive rather than re-checked here, so one place decides it.
    assertThatThrownBy(() -> VerifiableKeyConfig.detailFrom(
        suite(), "00", "test-voprf", "hofmann.voprf-master-key-hex"))
        .isInstanceOf(IllegalArgumentException.class);
  }
}
