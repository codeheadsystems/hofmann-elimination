package com.codeheadsystems.hofmann.model.opaque;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.codeheadsystems.rfc.opaque.model.RegistrationResponse;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

class RegistrationStartResponseTest {

  private final ObjectMapper mapper = new ObjectMapper();

  @Test
  void constructor_fromDomainObject_encodesCorrectly() {
    byte[] evaluated = {1, 2, 3};
    byte[] serverPk = {4, 5, 6};
    RegistrationStartResponse resp = new RegistrationStartResponse(
        new RegistrationResponse(evaluated, serverPk));

    RegistrationResponse rr = resp.registrationResponse();
    assertThat(rr.evaluatedElement()).isEqualTo(evaluated);
    assertThat(rr.serverPublicKey()).isEqualTo(serverPk);
  }

  @Test
  void registrationResponse_nullField_throwsIAE() {
    RegistrationStartResponse resp = new RegistrationStartResponse(null, "dGVzdA==");
    assertThatThrownBy(resp::registrationResponse)
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("Missing required field");
  }

  @Test
  void registrationResponse_blankField_throwsIAE() {
    RegistrationStartResponse resp = new RegistrationStartResponse("dGVzdA==", "");
    assertThatThrownBy(resp::registrationResponse)
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("Missing required field");
  }

  @Test
  void jsonRoundTrip() throws Exception {
    byte[] evaluated = {10, 20, 30};
    byte[] serverPk = {40, 50, 60};
    RegistrationStartResponse original = new RegistrationStartResponse(
        new RegistrationResponse(evaluated, serverPk));

    String json = mapper.writeValueAsString(original);
    RegistrationStartResponse restored = mapper.readValue(json, RegistrationStartResponse.class);

    assertThat(restored.registrationResponse().evaluatedElement()).isEqualTo(evaluated);
    assertThat(restored.registrationResponse().serverPublicKey()).isEqualTo(serverPk);
  }
}
