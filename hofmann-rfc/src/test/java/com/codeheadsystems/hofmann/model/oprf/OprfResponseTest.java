package com.codeheadsystems.hofmann.model.oprf;

import static org.assertj.core.api.Assertions.assertThat;

import com.codeheadsystems.oprf.model.EvaluatedResponse;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class OprfResponseTest {

  // Use deliberately distinct, non-symmetric values so transposition is visible
  private static final String EC_POINT = "ec-point-value";
  private static final String PROCESS_IDENTIFIER = "process-identifier-value";

  private ObjectMapper objectMapper;

  @BeforeEach
  void setUp() {
    objectMapper = new ObjectMapper();
  }

  @Test
  void constructor_stringFields_storedCorrectly() {
    OprfResponse response = new OprfResponse(EC_POINT, PROCESS_IDENTIFIER);

    assertThat(response.ecPoint()).isEqualTo(EC_POINT);
    assertThat(response.processIdentifier()).isEqualTo(PROCESS_IDENTIFIER);
  }

  @Test
  void constructor_fromEvaluatedResponse_mapsFieldsCorrectly() {
    EvaluatedResponse evaluatedResponse = new EvaluatedResponse(EC_POINT, PROCESS_IDENTIFIER);

    OprfResponse response = new OprfResponse(evaluatedResponse);

    assertThat(response.ecPoint()).isEqualTo(EC_POINT);
    assertThat(response.processIdentifier()).isEqualTo(PROCESS_IDENTIFIER);
  }

  @Test
  void evaluatedResponse_mapsFieldsCorrectly() {
    OprfResponse response = new OprfResponse(EC_POINT, PROCESS_IDENTIFIER);

    EvaluatedResponse evaluatedResponse = response.evaluatedResponse();

    assertThat(evaluatedResponse.evaluatedPoint()).isEqualTo(EC_POINT);
    assertThat(evaluatedResponse.processIdentifier()).isEqualTo(PROCESS_IDENTIFIER);
  }

  @Test
  void json_serialization_usesCorrectPropertyNames() throws Exception {
    OprfResponse response = new OprfResponse(EC_POINT, PROCESS_IDENTIFIER);

    String json = objectMapper.writeValueAsString(response);

    assertThat(json).contains("\"ecPoint\":\"" + EC_POINT + "\"");
    assertThat(json).contains("\"processIdentifier\":\"" + PROCESS_IDENTIFIER + "\"");
  }

  @Test
  void json_deserialization_mapsToCorrectFields() throws Exception {
    String json = "{\"ecPoint\":\"" + EC_POINT + "\",\"processIdentifier\":\"" + PROCESS_IDENTIFIER + "\"}";

    OprfResponse response = objectMapper.readValue(json, OprfResponse.class);

    assertThat(response.ecPoint()).isEqualTo(EC_POINT);
    assertThat(response.processIdentifier()).isEqualTo(PROCESS_IDENTIFIER);
  }

  @Test
  void json_roundTrip_preservesAllFields() throws Exception {
    OprfResponse original = new OprfResponse(EC_POINT, PROCESS_IDENTIFIER);

    String json = objectMapper.writeValueAsString(original);
    OprfResponse restored = objectMapper.readValue(json, OprfResponse.class);

    assertThat(restored.ecPoint()).isEqualTo(original.ecPoint());
    assertThat(restored.processIdentifier()).isEqualTo(original.processIdentifier());
  }
}
