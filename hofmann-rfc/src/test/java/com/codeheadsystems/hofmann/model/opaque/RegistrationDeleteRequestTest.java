package com.codeheadsystems.hofmann.model.opaque;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

class RegistrationDeleteRequestTest {

  private final ObjectMapper mapper = new ObjectMapper();

  @Test
  void constructor_fromBytes_encodesCorrectly() {
    byte[] credId = {1, 2, 3};
    RegistrationDeleteRequest req = new RegistrationDeleteRequest(credId);
    assertThat(req.credentialIdentifier()).isEqualTo(credId);
  }

  @Test
  void credentialIdentifier_null_throwsIAE() {
    RegistrationDeleteRequest req = new RegistrationDeleteRequest((String) null);
    assertThatThrownBy(req::credentialIdentifier)
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("Missing required field");
  }

  @Test
  void credentialIdentifier_blank_throwsIAE() {
    RegistrationDeleteRequest req = new RegistrationDeleteRequest("   ");
    assertThatThrownBy(req::credentialIdentifier)
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("Missing required field");
  }

  @Test
  void credentialIdentifier_invalidBase64_throwsIAE() {
    RegistrationDeleteRequest req = new RegistrationDeleteRequest("not!valid!");
    assertThatThrownBy(req::credentialIdentifier)
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("Invalid base64");
  }

  @Test
  void jsonRoundTrip() throws Exception {
    byte[] credId = "user@example.com".getBytes();
    RegistrationDeleteRequest original = new RegistrationDeleteRequest(credId);

    String json = mapper.writeValueAsString(original);
    RegistrationDeleteRequest restored = mapper.readValue(json, RegistrationDeleteRequest.class);

    assertThat(restored.credentialIdentifier()).isEqualTo(credId);
  }
}
