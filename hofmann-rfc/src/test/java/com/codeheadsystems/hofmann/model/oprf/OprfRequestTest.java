package com.codeheadsystems.hofmann.model.oprf;

import static org.assertj.core.api.Assertions.assertThat;

import com.codeheadsystems.rfc.oprf.model.BlindedRequest;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class OprfRequestTest {

  // Use deliberately distinct, non-symmetric values so transposition is visible
  private static final String EC_POINT = "ec-point-value";
  private static final String REQUEST_ID = "request-id-value";

  private ObjectMapper objectMapper;

  @BeforeEach
  void setUp() {
    objectMapper = new ObjectMapper();
  }

  @Test
  void constructor_stringFields_storedCorrectly() {
    OprfRequest request = new OprfRequest(EC_POINT, REQUEST_ID);

    assertThat(request.ecPoint()).isEqualTo(EC_POINT);
    assertThat(request.requestId()).isEqualTo(REQUEST_ID);
  }

  @Test
  void constructor_fromBlindedRequest_mapsFieldsCorrectly() {
    BlindedRequest blindedRequest = new BlindedRequest(EC_POINT, REQUEST_ID);

    OprfRequest request = new OprfRequest(blindedRequest);

    assertThat(request.ecPoint()).isEqualTo(EC_POINT);
    assertThat(request.requestId()).isEqualTo(REQUEST_ID);
  }

  @Test
  void blindedRequest_mapsFieldsCorrectly() {
    OprfRequest request = new OprfRequest(EC_POINT, REQUEST_ID);

    BlindedRequest blindedRequest = request.blindedRequest();

    assertThat(blindedRequest.blindedPoint()).isEqualTo(EC_POINT);
    assertThat(blindedRequest.requestId()).isEqualTo(REQUEST_ID);
  }

  @Test
  void json_serialization_usesCorrectPropertyNames() throws Exception {
    OprfRequest request = new OprfRequest(EC_POINT, REQUEST_ID);

    String json = objectMapper.writeValueAsString(request);

    assertThat(json).contains("\"ecPoint\":\"" + EC_POINT + "\"");
    assertThat(json).contains("\"requestId\":\"" + REQUEST_ID + "\"");
  }

  @Test
  void json_deserialization_mapsToCorrectFields() throws Exception {
    String json = "{\"ecPoint\":\"" + EC_POINT + "\",\"requestId\":\"" + REQUEST_ID + "\"}";

    OprfRequest request = objectMapper.readValue(json, OprfRequest.class);

    assertThat(request.ecPoint()).isEqualTo(EC_POINT);
    assertThat(request.requestId()).isEqualTo(REQUEST_ID);
  }

  @Test
  void json_roundTrip_preservesAllFields() throws Exception {
    OprfRequest original = new OprfRequest(EC_POINT, REQUEST_ID);

    String json = objectMapper.writeValueAsString(original);
    OprfRequest restored = objectMapper.readValue(json, OprfRequest.class);

    assertThat(restored.ecPoint()).isEqualTo(original.ecPoint());
    assertThat(restored.requestId()).isEqualTo(original.requestId());
  }
}
