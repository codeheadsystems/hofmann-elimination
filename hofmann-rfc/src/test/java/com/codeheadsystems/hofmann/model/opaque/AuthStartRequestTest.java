package com.codeheadsystems.hofmann.model.opaque;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.codeheadsystems.rfc.opaque.model.CredentialRequest;
import com.codeheadsystems.rfc.opaque.model.KE1;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

class AuthStartRequestTest {

  private final ObjectMapper mapper = new ObjectMapper();

  @Test
  void constructor_fromDomainObjects_encodesCorrectly() {
    byte[] credId = {1, 2};
    byte[] blinded = {3, 4};
    byte[] nonce = {5, 6};
    byte[] akePk = {7, 8};
    KE1 ke1 = new KE1(new CredentialRequest(blinded), nonce, akePk);
    AuthStartRequest req = new AuthStartRequest(credId, ke1);

    assertThat(req.credentialIdentifier()).isEqualTo(credId);
    KE1 restored = req.ke1();
    assertThat(restored.credentialRequest().blindedElement()).isEqualTo(blinded);
    assertThat(restored.clientNonce()).isEqualTo(nonce);
    assertThat(restored.clientAkePublicKey()).isEqualTo(akePk);
  }

  @Test
  void credentialIdentifier_null_throwsIAE() {
    AuthStartRequest req = new AuthStartRequest(null, "dGVzdA==", "dGVzdA==", "dGVzdA==");
    assertThatThrownBy(req::credentialIdentifier)
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("Missing required field");
  }

  @Test
  void ke1_blankBlindedElement_throwsIAE() {
    AuthStartRequest req = new AuthStartRequest("dGVzdA==", "  ", "dGVzdA==", "dGVzdA==");
    assertThatThrownBy(req::ke1)
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("Missing required field");
  }

  @Test
  void ke1_invalidBase64InNonce_throwsIAE() {
    AuthStartRequest req = new AuthStartRequest("dGVzdA==", "dGVzdA==", "!!!invalid!!!", "dGVzdA==");
    assertThatThrownBy(req::ke1)
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("Invalid base64");
  }

  @Test
  void jsonRoundTrip() throws Exception {
    byte[] credId = {10};
    byte[] blinded = {20};
    byte[] nonce = {30};
    byte[] akePk = {40};
    KE1 ke1 = new KE1(new CredentialRequest(blinded), nonce, akePk);
    AuthStartRequest original = new AuthStartRequest(credId, ke1);

    String json = mapper.writeValueAsString(original);
    AuthStartRequest restored = mapper.readValue(json, AuthStartRequest.class);

    assertThat(restored.credentialIdentifier()).isEqualTo(credId);
    assertThat(restored.ke1().credentialRequest().blindedElement()).isEqualTo(blinded);
    assertThat(restored.ke1().clientNonce()).isEqualTo(nonce);
    assertThat(restored.ke1().clientAkePublicKey()).isEqualTo(akePk);
  }
}
