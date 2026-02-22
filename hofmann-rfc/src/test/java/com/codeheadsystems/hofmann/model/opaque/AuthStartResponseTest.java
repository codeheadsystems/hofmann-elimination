package com.codeheadsystems.hofmann.model.opaque;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.codeheadsystems.rfc.opaque.model.CredentialResponse;
import com.codeheadsystems.rfc.opaque.model.KE2;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

class AuthStartResponseTest {

  private final ObjectMapper mapper = new ObjectMapper();

  @Test
  void constructor_fromDomainObjects_encodesCorrectly() {
    byte[] eval = {1};
    byte[] maskNonce = {2};
    byte[] masked = {3};
    byte[] sNonce = {4};
    byte[] sAkePk = {5};
    byte[] sMac = {6};
    KE2 ke2 = new KE2(new CredentialResponse(eval, maskNonce, masked), sNonce, sAkePk, sMac);
    AuthStartResponse resp = new AuthStartResponse("session-1", ke2);

    assertThat(resp.sessionToken()).isEqualTo("session-1");
    KE2 restored = resp.ke2();
    assertThat(restored.credentialResponse().evaluatedElement()).isEqualTo(eval);
    assertThat(restored.credentialResponse().maskingNonce()).isEqualTo(maskNonce);
    assertThat(restored.credentialResponse().maskedResponse()).isEqualTo(masked);
    assertThat(restored.serverNonce()).isEqualTo(sNonce);
    assertThat(restored.serverAkePublicKey()).isEqualTo(sAkePk);
    assertThat(restored.serverMac()).isEqualTo(sMac);
  }

  @Test
  void ke2_nullField_throwsIAE() {
    AuthStartResponse resp = new AuthStartResponse("s", null, "dGVzdA==", "dGVzdA==",
        "dGVzdA==", "dGVzdA==", "dGVzdA==");
    assertThatThrownBy(resp::ke2)
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("Missing required field");
  }

  @Test
  void ke2_blankField_throwsIAE() {
    AuthStartResponse resp = new AuthStartResponse("s", "dGVzdA==", "dGVzdA==", "dGVzdA==",
        " ", "dGVzdA==", "dGVzdA==");
    assertThatThrownBy(resp::ke2)
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("Missing required field");
  }

  @Test
  void jsonRoundTrip() throws Exception {
    byte[] eval = {10};
    byte[] maskNonce = {20};
    byte[] masked = {30};
    byte[] sNonce = {40};
    byte[] sAkePk = {50};
    byte[] sMac = {60};
    KE2 ke2 = new KE2(new CredentialResponse(eval, maskNonce, masked), sNonce, sAkePk, sMac);
    AuthStartResponse original = new AuthStartResponse("tok", ke2);

    String json = mapper.writeValueAsString(original);
    AuthStartResponse restored = mapper.readValue(json, AuthStartResponse.class);

    assertThat(restored.sessionToken()).isEqualTo("tok");
    assertThat(restored.ke2().credentialResponse().evaluatedElement()).isEqualTo(eval);
    assertThat(restored.ke2().serverMac()).isEqualTo(sMac);
  }
}
