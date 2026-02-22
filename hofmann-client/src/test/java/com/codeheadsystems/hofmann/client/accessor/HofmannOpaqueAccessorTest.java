package com.codeheadsystems.hofmann.client.accessor;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.when;

import com.codeheadsystems.hofmann.client.exceptions.OpaqueAccessorException;
import com.codeheadsystems.hofmann.client.model.ServerConnectionInfo;
import com.codeheadsystems.hofmann.client.model.ServerIdentifier;
import com.codeheadsystems.hofmann.model.opaque.AuthFinishRequest;
import com.codeheadsystems.hofmann.model.opaque.AuthStartRequest;
import com.codeheadsystems.hofmann.model.opaque.AuthStartResponse;
import com.codeheadsystems.hofmann.model.opaque.RegistrationStartRequest;
import com.codeheadsystems.hofmann.model.opaque.RegistrationStartResponse;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpResponse;
import java.util.HashMap;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

/**
 * The type Hofmann opaque accessor test.
 */
@ExtendWith(MockitoExtension.class)
class HofmannOpaqueAccessorTest {

  private static final ServerIdentifier SERVER_ID = new ServerIdentifier("test-server");
  private static final URI BASE_URI = URI.create("http://localhost:8080");

  @Mock private HttpClient httpClient;
  @Mock private HttpResponse<String> httpResponse;
  @Mock private ObjectMapper objectMapper;

  private HofmannOpaqueAccessor accessor;

  /**
   * Sets up.
   */
  @BeforeEach
  void setUp() {
    Map<ServerIdentifier, ServerConnectionInfo> connections = new HashMap<>();
    connections.put(SERVER_ID, new ServerConnectionInfo(BASE_URI));
    accessor = new HofmannOpaqueAccessor(httpClient, objectMapper, connections);
  }

  // ── Registration start ────────────────────────────────────────────────────

  /**
   * Registration start success returns response.
   *
   * @throws Exception the exception
   */
  @Test
  @SuppressWarnings("unchecked")
  void registrationStart_success_returnsResponse() throws Exception {
    RegistrationStartResponse expected = new RegistrationStartResponse("evalElem", "serverPk");
    String body = "{\"evaluatedElement\":\"evalElem\",\"serverPublicKey\":\"serverPk\"}";

    when(objectMapper.writeValueAsString(any())).thenReturn("{}");
    doReturn(httpResponse).when(httpClient).send(any(), any());
    when(httpResponse.statusCode()).thenReturn(200);
    when(httpResponse.body()).thenReturn(body);
    when(objectMapper.readValue(eq(body), eq(RegistrationStartResponse.class))).thenReturn(expected);

    RegistrationStartResponse result = accessor.registrationStart(SERVER_ID,
        new RegistrationStartRequest("credId", "blindedElem"));

    assertThat(result.evaluatedElementBase64()).isEqualTo("evalElem");
    assertThat(result.serverPublicKeyBase64()).isEqualTo("serverPk");
  }

  /**
   * Registration start io exception throws opaque accessor exception.
   *
   * @throws Exception the exception
   */
  @Test
  @SuppressWarnings("unchecked")
  void registrationStart_ioException_throwsOpaqueAccessorException() throws Exception {
    when(objectMapper.writeValueAsString(any())).thenReturn("{}");
    doThrow(new IOException("connection refused")).when(httpClient).send(any(), any());

    assertThatThrownBy(() -> accessor.registrationStart(SERVER_ID,
        new RegistrationStartRequest("credId", "blindedElem")))
        .isInstanceOf(OpaqueAccessorException.class)
        .hasMessageContaining("test-server")
        .hasCauseInstanceOf(IOException.class);
  }

  // ── Auth finish — 401 handling ────────────────────────────────────────────

  /**
   * Auth finish 401 throws security exception.
   *
   * @throws Exception the exception
   */
  @Test
  @SuppressWarnings("unchecked")
  void authFinish_401_throwsSecurityException() throws Exception {
    when(objectMapper.writeValueAsString(any())).thenReturn("{}");
    doReturn(httpResponse).when(httpClient).send(any(), any());
    when(httpResponse.statusCode()).thenReturn(401);

    assertThatThrownBy(() -> accessor.authFinish(SERVER_ID,
        new AuthFinishRequest("session-token", "clientMac")))
        .isInstanceOf(SecurityException.class)
        .hasMessageContaining("401");
  }

  // ── Auth start ────────────────────────────────────────────────────────────

  /**
   * Auth start success returns response.
   *
   * @throws Exception the exception
   */
  @Test
  @SuppressWarnings("unchecked")
  void authStart_success_returnsResponse() throws Exception {
    AuthStartResponse expected = new AuthStartResponse(
        "tok", "evalElem", "maskNonce", "maskedResp", "srvNonce", "srvAkePk", "srvMac");
    String body = "{}";

    when(objectMapper.writeValueAsString(any())).thenReturn("{}");
    doReturn(httpResponse).when(httpClient).send(any(), any());
    when(httpResponse.statusCode()).thenReturn(200);
    when(httpResponse.body()).thenReturn(body);
    when(objectMapper.readValue(eq(body), eq(AuthStartResponse.class))).thenReturn(expected);

    AuthStartResponse result = accessor.authStart(SERVER_ID,
        new AuthStartRequest("credId", "blindedElem", "clientNonce", "clientAkePk"));

    assertThat(result.sessionToken()).isEqualTo("tok");
    assertThat(result.serverMacBase64()).isEqualTo("srvMac");
  }

  // ── Unknown server ────────────────────────────────────────────────────────

  /**
   * Any method unknown server throws illegal argument exception.
   */
  @Test
  void anyMethod_unknownServer_throwsIllegalArgumentException() {
    ServerIdentifier unknown = new ServerIdentifier("not-registered");

    assertThatThrownBy(() -> accessor.registrationStart(unknown,
        new RegistrationStartRequest("credId", "blindedElem")))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("not-registered");
  }

  // ── Interrupted ───────────────────────────────────────────────────────────

  /**
   * Auth start interrupted throws opaque accessor exception and restores interrupt flag.
   *
   * @throws Exception the exception
   */
  @Test
  @SuppressWarnings("unchecked")
  void authStart_interrupted_throwsOpaqueAccessorExceptionAndRestoresInterruptFlag()
      throws Exception {
    when(objectMapper.writeValueAsString(any())).thenReturn("{}");
    doThrow(new InterruptedException("interrupted")).when(httpClient).send(any(), any());

    try {
      assertThatThrownBy(() -> accessor.authStart(SERVER_ID,
          new AuthStartRequest("credId", "blindedElem", "clientNonce", "clientAkePk")))
          .isInstanceOf(OpaqueAccessorException.class)
          .hasCauseInstanceOf(InterruptedException.class);

      assertThat(Thread.currentThread().isInterrupted()).isTrue();
    } finally {
      Thread.interrupted(); // clear flag so it doesn't bleed into other tests
    }
  }
}
