package com.codeheadsystems.hofmann.model.opaque;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.codeheadsystems.rfc.opaque.model.KE3;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

class AuthFinishRequestTest {

  private final ObjectMapper mapper = new ObjectMapper();

  @Test
  void constructor_fromDomainObjects_encodesCorrectly() {
    byte[] mac = {1, 2, 3, 4};
    AuthFinishRequest req = new AuthFinishRequest("session-123", new KE3(mac));

    assertThat(req.sessionToken()).isEqualTo("session-123");
    assertThat(req.ke3().clientMac()).isEqualTo(mac);
  }

  @Test
  void ke3_nullMac_throwsIAE() {
    AuthFinishRequest req = new AuthFinishRequest("session", (String) null);
    assertThatThrownBy(req::ke3)
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("Missing required field");
  }

  @Test
  void ke3_blankMac_throwsIAE() {
    AuthFinishRequest req = new AuthFinishRequest("session", "  ");
    assertThatThrownBy(req::ke3)
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("Missing required field");
  }

  @Test
  void ke3_invalidBase64_throwsIAE() {
    AuthFinishRequest req = new AuthFinishRequest("session", "not!valid!");
    assertThatThrownBy(req::ke3)
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("Invalid base64");
  }

  @Test
  void jsonRoundTrip() throws Exception {
    byte[] mac = {10, 20, 30};
    AuthFinishRequest original = new AuthFinishRequest("tok-1", new KE3(mac));

    String json = mapper.writeValueAsString(original);
    AuthFinishRequest restored = mapper.readValue(json, AuthFinishRequest.class);

    assertThat(restored.sessionToken()).isEqualTo("tok-1");
    assertThat(restored.ke3().clientMac()).isEqualTo(mac);
  }
}
