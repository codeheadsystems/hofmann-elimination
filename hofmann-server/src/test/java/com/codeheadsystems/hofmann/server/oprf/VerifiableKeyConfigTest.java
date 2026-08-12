package com.codeheadsystems.hofmann.server.oprf;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.codeheadsystems.hofmann.model.oprf.OprfClientConfigResponse;
import com.codeheadsystems.rfc.oprf.manager.PoprfServerManager;
import com.codeheadsystems.rfc.oprf.manager.VoprfServerManager;
import com.codeheadsystems.rfc.oprf.model.VerifiableProcessorDetail;
import com.codeheadsystems.rfc.oprf.rfc9497.OprfCipherSuite;
import com.codeheadsystems.rfc.oprf.rfc9497.OprfMode;
import java.security.SecureRandom;
import org.bouncycastle.util.encoders.Hex;
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

  // ─── clientConfigResponse ──────────────────────────────────────────────────

  private VoprfServerManager voprfManager() {
    OprfCipherSuite s = VerifiableKeyConfig.suiteFor("P256_SHA256", OprfMode.VOPRF, RANDOM);
    VerifiableProcessorDetail detail = VerifiableKeyConfig.detailFrom(
        s, "42424242424242424242424242", "test-voprf", "hofmann.voprf-master-key-hex");
    return new VoprfServerManager(s, () -> detail, 16);
  }

  private PoprfServerManager poprfManager() {
    OprfCipherSuite s = VerifiableKeyConfig.suiteFor("P256_SHA256", OprfMode.POPRF, RANDOM);
    VerifiableProcessorDetail detail = VerifiableKeyConfig.detailFrom(
        s, "5353535353535353535353535353", "test-poprf", "hofmann.poprf-master-key-hex");
    return new PoprfServerManager(s, () -> detail, 8);
  }

  /**
   * The compatibility case. A base-mode deployment must emit the document it emitted before the
   * field existed, because an already-released client's {@code ObjectMapper} rejects unknown
   * properties. An empty list would not do — it is a different document.
   */
  @Test
  void clientConfigResponse_noModes_omitsTheFieldEntirely() {
    OprfClientConfigResponse response =
        VerifiableKeyConfig.clientConfigResponse("P256_SHA256", null, null);

    assertThat(response.cipherSuite()).isEqualTo("P256_SHA256");
    assertThat(response.modes()).isNull();
  }

  @Test
  void clientConfigResponse_voprfOnly_advertisesOnlyVoprf() {
    OprfClientConfigResponse response =
        VerifiableKeyConfig.clientConfigResponse("P256_SHA256", voprfManager(), null);

    assertThat(response.modes()).hasSize(1);
    assertThat(response.modes().get(0).mode()).isEqualTo("VOPRF");
    assertThat(response.modes().get(0).processIdentifier()).isEqualTo("test-voprf");
    assertThat(response.modes().get(0).maxBatchSize()).isEqualTo(16);
  }

  @Test
  void clientConfigResponse_poprfOnly_advertisesOnlyPoprf() {
    OprfClientConfigResponse response =
        VerifiableKeyConfig.clientConfigResponse("P256_SHA256", null, poprfManager());

    assertThat(response.modes()).hasSize(1);
    assertThat(response.modes().get(0).mode()).isEqualTo("POPRF");
    assertThat(response.modes().get(0).maxBatchSize()).isEqualTo(8);
  }

  /**
   * The advertised key must be the one a client's proof verification is graded against. Derived
   * independently here from the same master key, so a wrong key or a wrong mode fails rather than
   * being compared against itself.
   */
  @Test
  void clientConfigResponse_advertisesTheKeyClientsMustPin() {
    OprfCipherSuite voprfSuite =
        VerifiableKeyConfig.suiteFor("P256_SHA256", OprfMode.VOPRF, RANDOM);
    VerifiableProcessorDetail expected = VerifiableKeyConfig.detailFrom(
        voprfSuite, "42424242424242424242424242", "test-voprf", "hofmann.voprf-master-key-hex");

    OprfClientConfigResponse response =
        VerifiableKeyConfig.clientConfigResponse("P256_SHA256", voprfManager(), null);

    assertThat(response.modes().get(0).publicKeyHex())
        .isEqualTo(Hex.toHexString(expected.publicKey()));
  }

  /**
   * POPRF advertises {@code pkS}, never a tweaked key. The client derives {@code m*G + pkS} from
   * the public input it chooses, so a tweaked key would be the answer to one {@code info} and
   * wrong for every other — and nothing would notice until a POPRF client existed.
   */
  @Test
  void clientConfigResponse_poprfAdvertisesTheUntweakedKey() {
    OprfCipherSuite poprfSuite =
        VerifiableKeyConfig.suiteFor("P256_SHA256", OprfMode.POPRF, RANDOM);
    VerifiableProcessorDetail expected = VerifiableKeyConfig.detailFrom(
        poprfSuite, "5353535353535353535353535353", "test-poprf",
        "hofmann.poprf-master-key-hex");

    OprfClientConfigResponse response =
        VerifiableKeyConfig.clientConfigResponse("P256_SHA256", null, poprfManager());

    assertThat(response.modes().get(0).publicKeyHex())
        .isEqualTo(Hex.toHexString(expected.publicKey()));
  }

  /**
   * Order matters only in that it is stable; a client looks modes up by name. Asserted so a
   * reordering is a deliberate change rather than an accident.
   */
  @Test
  void clientConfigResponse_bothModes_advertisesVoprfThenPoprf() {
    OprfClientConfigResponse response =
        VerifiableKeyConfig.clientConfigResponse("P256_SHA256", voprfManager(), poprfManager());

    assertThat(response.modes()).hasSize(2);
    assertThat(response.modes().get(0).mode()).isEqualTo("VOPRF");
    assertThat(response.modes().get(1).mode()).isEqualTo("POPRF");
    assertThat(response.modes().get(0).publicKeyHex())
        .isNotEqualTo(response.modes().get(1).publicKeyHex());
  }
}
