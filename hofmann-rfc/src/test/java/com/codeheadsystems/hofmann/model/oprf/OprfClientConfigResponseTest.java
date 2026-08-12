package com.codeheadsystems.hofmann.model.oprf;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * Covers the wire contract of {@code GET /oprf/config}.
 *
 * <p>The tests that matter here are the compatibility ones. This record gained a component in a
 * release where clients in the field were already parsing it, and the two directions of that break
 * fail differently: a new client against an old server sees a missing field, and an old client
 * against a new server sees an unexpected one. Both are asserted.
 */
class OprfClientConfigResponseTest {

  private static final String SUITE = "P256_SHA256";
  private static final String VOPRF_KEY = "02aabbccdd";
  private static final String POPRF_KEY = "03eeff0011";

  private ObjectMapper objectMapper;

  @BeforeEach
  void setUp() {
    objectMapper = new ObjectMapper();
  }

  /**
   * The one-arg form emits exactly the document shipped before {@code modes} existed. If this
   * fails, every already-released client breaks against a base-mode server on upgrade.
   */
  @Test
  void baseModeForm_serializesToTheSameDocumentAsBeforeTheModesFieldExisted() throws Exception {
    String json = objectMapper.writeValueAsString(new OprfClientConfigResponse(SUITE));

    assertThat(json).isEqualTo("{\"cipherSuite\":\"" + SUITE + "\"}");
  }

  /**
   * Same, via the canonical constructor with an explicit null — the path the server takes when no
   * verifiable mode is configured.
   */
  @Test
  void nullModes_areOmittedRatherThanEmittedAsNull() throws Exception {
    String json = objectMapper.writeValueAsString(new OprfClientConfigResponse(SUITE, null));

    assertThat(json).doesNotContain("modes");
  }

  /**
   * An empty list is a different document from an absent one, and the server is expected never to
   * send it — but if it does, it must survive the round trip as empty rather than becoming null,
   * because "server publishes a complete list and this mode is not on it" is a distinct client
   * outcome from "server does not publish a list".
   */
  @Test
  void emptyModes_survivesTheRoundTripAsEmptyRatherThanNull() throws Exception {
    String json = objectMapper.writeValueAsString(
        new OprfClientConfigResponse(SUITE, List.of()));
    OprfClientConfigResponse restored =
        objectMapper.readValue(json, OprfClientConfigResponse.class);

    assertThat(json).contains("\"modes\":[]");
    assertThat(restored.modes()).isNotNull().isEmpty();
  }

  @Test
  void modes_roundTripPreservesEveryField() throws Exception {
    OprfClientConfigResponse original = new OprfClientConfigResponse(SUITE, List.of(
        new OprfModeInfo("VOPRF", VOPRF_KEY, "hofmann-oprf-v1", 64),
        new OprfModeInfo("POPRF", POPRF_KEY, "hofmann-oprf-v1", 32)));

    String json = objectMapper.writeValueAsString(original);
    OprfClientConfigResponse restored =
        objectMapper.readValue(json, OprfClientConfigResponse.class);

    assertThat(restored).isEqualTo(original);
    assertThat(restored.modes()).hasSize(2);
    assertThat(restored.modes().get(0).mode()).isEqualTo("VOPRF");
    assertThat(restored.modes().get(0).publicKeyHex()).isEqualTo(VOPRF_KEY);
    assertThat(restored.modes().get(0).maxBatchSize()).isEqualTo(64);
    assertThat(restored.modes().get(1).mode()).isEqualTo("POPRF");
    assertThat(restored.modes().get(1).publicKeyHex()).isEqualTo(POPRF_KEY);
    assertThat(restored.modes().get(1).maxBatchSize()).isEqualTo(32);
  }

  /**
   * The new-client-against-old-server direction: no {@code modes} key at all.
   */
  @Test
  void deserialization_withoutModes_yieldsNullRatherThanFailing() throws Exception {
    OprfClientConfigResponse restored = objectMapper.readValue(
        "{\"cipherSuite\":\"" + SUITE + "\"}", OprfClientConfigResponse.class);

    assertThat(restored.cipherSuite()).isEqualTo(SUITE);
    assertThat(restored.modes()).isNull();
  }

  /**
   * Forward compatibility for the next field to be added here, on both records. A bare
   * {@code ObjectMapper} has {@code FAIL_ON_UNKNOWN_PROPERTIES} on, and every caller in tree
   * constructs one bare, so without {@code @JsonIgnoreProperties} this throws.
   */
  @Test
  void deserialization_toleratesUnknownPropertiesAtBothLevels() throws Exception {
    OprfClientConfigResponse restored = objectMapper.readValue(
        "{\"cipherSuite\":\"" + SUITE + "\",\"somethingNew\":true,"
            + "\"modes\":[{\"mode\":\"VOPRF\",\"publicKeyHex\":\"" + VOPRF_KEY + "\","
            + "\"processIdentifier\":\"p\",\"maxBatchSize\":8,\"alsoNew\":[1,2]}]}",
        OprfClientConfigResponse.class);

    assertThat(restored.cipherSuite()).isEqualTo(SUITE);
    assertThat(restored.modes()).hasSize(1);
    assertThat(restored.modes().get(0).maxBatchSize()).isEqualTo(8);
  }

  /**
   * The list is copied on the way in, so a caller mutating the list it passed cannot change what a
   * shared, long-lived config response reports. Both adapters hold exactly one of these for the
   * lifetime of the process.
   */
  @Test
  void modes_areDefensivelyCopied() {
    List<OprfModeInfo> mutable = new ArrayList<>();
    mutable.add(new OprfModeInfo("VOPRF", VOPRF_KEY, "p", 64));

    OprfClientConfigResponse response = new OprfClientConfigResponse(SUITE, mutable);
    mutable.add(new OprfModeInfo("POPRF", POPRF_KEY, "p", 64));

    assertThat(response.modes()).hasSize(1);
    assertThatThrownBy(() -> response.modes().add(new OprfModeInfo("POPRF", POPRF_KEY, "p", 64)))
        .isInstanceOf(UnsupportedOperationException.class);
  }
}
