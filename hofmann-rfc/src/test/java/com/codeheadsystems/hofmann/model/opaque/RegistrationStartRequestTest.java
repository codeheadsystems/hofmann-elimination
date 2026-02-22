package com.codeheadsystems.hofmann.model.opaque;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.codeheadsystems.rfc.opaque.model.RegistrationRequest;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.Base64;
import org.junit.jupiter.api.Test;

class RegistrationStartRequestTest {

  private final ObjectMapper mapper = new ObjectMapper();

  @Test
  void constructor_fromDomainObjects_encodesCorrectly() {
    byte[] credId = {1, 2, 3};
    byte[] blinded = {4, 5, 6};
    RegistrationStartRequest req = new RegistrationStartRequest(credId, new RegistrationRequest(blinded));

    assertThat(req.credentialIdentifier()).isEqualTo(credId);
    assertThat(req.registrationRequest().blindedElement()).isEqualTo(blinded);
  }

  @Test
  void credentialIdentifier_null_throwsIAE() {
    RegistrationStartRequest req = new RegistrationStartRequest(null, "dGVzdA==");
    assertThatThrownBy(req::credentialIdentifier)
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("Missing required field");
  }

  @Test
  void credentialIdentifier_blank_throwsIAE() {
    RegistrationStartRequest req = new RegistrationStartRequest("  ", "dGVzdA==");
    assertThatThrownBy(req::credentialIdentifier)
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("Missing required field");
  }

  @Test
  void credentialIdentifier_invalidBase64_throwsIAE() {
    RegistrationStartRequest req = new RegistrationStartRequest("not!valid!base64!", "dGVzdA==");
    assertThatThrownBy(req::credentialIdentifier)
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("Invalid base64");
  }

  @Test
  void registrationRequest_nullBlinded_throwsIAE() {
    RegistrationStartRequest req = new RegistrationStartRequest("dGVzdA==", null);
    assertThatThrownBy(req::registrationRequest)
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("Missing required field");
  }

  @Test
  void jsonRoundTrip() throws Exception {
    byte[] credId = "user@example.com".getBytes();
    byte[] blinded = new byte[33];
    blinded[0] = 0x02;
    RegistrationStartRequest original = new RegistrationStartRequest(credId, new RegistrationRequest(blinded));

    String json = mapper.writeValueAsString(original);
    RegistrationStartRequest restored = mapper.readValue(json, RegistrationStartRequest.class);

    assertThat(restored.credentialIdentifier()).isEqualTo(credId);
    assertThat(restored.registrationRequest().blindedElement()).isEqualTo(blinded);
  }
}
