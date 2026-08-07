package com.codeheadsystems.hofmann.model.oprf;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import org.junit.jupiter.api.Test;

/**
 * Bounds on the verifiable OPRF wire models.
 *
 * <p>These are the checks that run before the batch reaches the crypto layer. They are not the
 * batch cap — the manager owns that, because it owns the configured value — and not the transport
 * size bound, which acts before the body is parsed at all. They reject what is structurally
 * unusable, and they live on the model so both adapters get them.
 */
class VerifiableOprfWireModelTest {

  private static final String ELEMENT = "02".repeat(33);

  @Test
  void voprf_validRequest_roundTripsToTheProtocolModel() {
    VoprfRequest request = new VoprfRequest(List.of(ELEMENT, ELEMENT), "req-1");
    assertThat(request.blindedRequest().blindedPoints()).containsExactly(ELEMENT, ELEMENT);
    assertThat(request.blindedRequest().requestId()).isEqualTo("req-1");
  }

  @Test
  void voprf_emptyOrMissingBatch_isRejected() {
    assertThatThrownBy(() -> new VoprfRequest(List.of(), "req-1").blindedRequest())
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("blindedElements");
    assertThatThrownBy(() -> new VoprfRequest(null, "req-1").blindedRequest())
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("blindedElements");
  }

  @Test
  void voprf_batchBeyondTheAbsoluteMaximum_isRejectedWithoutConsultingTheManager() {
    // The configured cap may be lower and the manager enforces it; this is the ceiling no
    // configuration can raise, so a list far beyond any legal batch is refused before it is copied.
    List<String> huge = new ArrayList<>(
        Collections.nCopies(OprfWireFields.ABSOLUTE_MAX_BATCH + 1, ELEMENT));
    assertThatThrownBy(() -> new VoprfRequest(huge, "req-1").blindedRequest())
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("exceeds the absolute maximum");
  }

  @Test
  void voprf_blankOrOversizedElement_isRejected() {
    assertThatThrownBy(() -> new VoprfRequest(List.of(ELEMENT, "  "), "req-1").blindedRequest())
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("index 1");
    String oversized = "0".repeat(OprfWireFields.MAX_ELEMENT_HEX_LENGTH + 1);
    assertThatThrownBy(() -> new VoprfRequest(List.of(oversized), "req-1").blindedRequest())
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("Element too large");
  }

  @Test
  void voprf_missingOrOversizedRequestId_isRejected() {
    assertThatThrownBy(() -> new VoprfRequest(List.of(ELEMENT), " ").blindedRequest())
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("requestId");
    String longId = "x".repeat(OprfWireFields.MAX_REQUEST_ID_LENGTH + 1);
    assertThatThrownBy(() -> new VoprfRequest(List.of(ELEMENT), longId).blindedRequest())
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("Field too large");
  }

  @Test
  void poprf_absentInfoIsRejectedRatherThanDefaulted() {
    // An absent public input and an empty one are different public inputs producing different
    // outputs. Guessing which the caller meant would silently change the function evaluated.
    assertThatThrownBy(() -> new PoprfRequest(List.of(ELEMENT), null, "req-1").blindedRequest())
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("info");

    assertThatCode(() -> new PoprfRequest(List.of(ELEMENT), "", "req-1").blindedRequest())
        .doesNotThrowAnyException();
  }

  @Test
  void poprf_oversizedInfo_isRejected() {
    String oversized = "0".repeat(OprfWireFields.MAX_INFO_HEX_LENGTH + 1);
    assertThatThrownBy(() -> new PoprfRequest(List.of(ELEMENT), oversized, "req-1").blindedRequest())
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("Field too large: info");
  }

  @Test
  void transportBound_admitsAFullBatchAndRefusesMuchMore() {
    long bound = VerifiableOprfLimits.maxRequestBodyBytes(64);

    // A full batch of the largest supported element must fit, or the bound would reject traffic
    // the manager is configured to accept.
    long fullBatchBytes = 64L * (2 * VerifiableOprfLimits.MAX_ELEMENT_BYTES + 4);
    assertThat(bound).isGreaterThan(fullBatchBytes);

    // And it must be far below the generic 64 KiB limit, which is the gap this closes.
    assertThat(bound).isLessThan(65536L);
  }

  @Test
  void transportBound_rejectsANonsenseBatchSize() {
    assertThatThrownBy(() -> VerifiableOprfLimits.maxRequestBodyBytes(0))
        .isInstanceOf(IllegalArgumentException.class);
  }
}
