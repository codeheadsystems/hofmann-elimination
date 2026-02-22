package com.codeheadsystems.hofmann.model.opaque;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.codeheadsystems.rfc.opaque.model.Envelope;
import com.codeheadsystems.rfc.opaque.model.RegistrationRecord;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

class RegistrationFinishRequestTest {

  private final ObjectMapper mapper = new ObjectMapper();

  @Test
  void constructor_fromDomainObjects_encodesCorrectly() {
    byte[] credId = {1, 2};
    byte[] clientPk = {3, 4};
    byte[] maskingKey = {5, 6};
    byte[] nonce = {7, 8};
    byte[] authTag = {9, 10};
    RegistrationRecord rec = new RegistrationRecord(clientPk, maskingKey, new Envelope(nonce, authTag));
    RegistrationFinishRequest req = new RegistrationFinishRequest(credId, rec);

    assertThat(req.credentialIdentifier()).isEqualTo(credId);
    RegistrationRecord restored = req.registrationRecord();
    assertThat(restored.clientPublicKey()).isEqualTo(clientPk);
    assertThat(restored.maskingKey()).isEqualTo(maskingKey);
    assertThat(restored.envelope().envelopeNonce()).isEqualTo(nonce);
    assertThat(restored.envelope().authTag()).isEqualTo(authTag);
  }

  @Test
  void credentialIdentifier_null_throwsIAE() {
    RegistrationFinishRequest req = new RegistrationFinishRequest(null, "dGVzdA==", "dGVzdA==", "dGVzdA==", "dGVzdA==");
    assertThatThrownBy(req::credentialIdentifier)
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("Missing required field");
  }

  @Test
  void registrationRecord_blankField_throwsIAE() {
    RegistrationFinishRequest req = new RegistrationFinishRequest("dGVzdA==", "", "dGVzdA==", "dGVzdA==", "dGVzdA==");
    assertThatThrownBy(req::registrationRecord)
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("Missing required field");
  }

  @Test
  void registrationRecord_invalidBase64InAuthTag_throwsIAE() {
    RegistrationFinishRequest req = new RegistrationFinishRequest("dGVzdA==", "dGVzdA==", "dGVzdA==", "dGVzdA==", "!!!bad!!!");
    assertThatThrownBy(req::registrationRecord)
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("Invalid base64");
  }

  @Test
  void jsonRoundTrip() throws Exception {
    byte[] credId = {1};
    byte[] clientPk = {2};
    byte[] maskingKey = {3};
    byte[] nonce = {4};
    byte[] authTag = {5};
    RegistrationRecord rec = new RegistrationRecord(clientPk, maskingKey, new Envelope(nonce, authTag));
    RegistrationFinishRequest original = new RegistrationFinishRequest(credId, rec);

    String json = mapper.writeValueAsString(original);
    RegistrationFinishRequest restored = mapper.readValue(json, RegistrationFinishRequest.class);

    assertThat(restored.credentialIdentifier()).isEqualTo(credId);
    assertThat(restored.registrationRecord().clientPublicKey()).isEqualTo(clientPk);
    assertThat(restored.registrationRecord().maskingKey()).isEqualTo(maskingKey);
    assertThat(restored.registrationRecord().envelope().envelopeNonce()).isEqualTo(nonce);
    assertThat(restored.registrationRecord().envelope().authTag()).isEqualTo(authTag);
  }
}
