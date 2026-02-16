package com.codeheadsystems.hofmann.client.accessor;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.when;

import com.codeheadsystems.hofmann.client.config.OprfConfig;
import com.codeheadsystems.hofmann.client.exceptions.OprfAccessorException;
import com.codeheadsystems.hofmann.client.model.ServerConnectionInfo;
import com.codeheadsystems.hofmann.client.model.ServerIdentifier;
import com.codeheadsystems.hofmann.model.OprfResponse;
import com.codeheadsystems.oprf.curve.Curve;
import com.codeheadsystems.oprf.curve.OctetStringUtils;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpResponse;
import java.util.HashMap;
import java.util.Map;
import org.bouncycastle.math.ec.ECPoint;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class OprfAccessorTest {

  private static final Curve CURVE = Curve.P256_CURVE;
  private static final OprfConfig CONFIG = new OprfConfig();
  private static final ServerIdentifier SERVER_ID = new ServerIdentifier("test-server");
  private static final URI ENDPOINT = URI.create("http://localhost:8080/oprf");

  @Mock private HttpClient httpClient;
  @Mock private HttpResponse<String> httpResponse;
  @Mock private ObjectMapper objectMapper;

  private OprfAccessor accessor;

  @BeforeEach
  void setUp() {
    Map<ServerIdentifier, ServerConnectionInfo> connections = new HashMap<>();
    connections.put(SERVER_ID, new ServerConnectionInfo(ENDPOINT));
    accessor = new OprfAccessor(CONFIG, httpClient, objectMapper, connections);
  }

  @Test
  @SuppressWarnings("unchecked")
  void handleRequest_success_returnsEvaluatedPointAndProcessIdentifier() throws Exception {
    ECPoint blindedPoint = CURVE.g();
    String responseHex = OctetStringUtils.toHex(blindedPoint);
    String processIdentifier = "proc-abc";
    String responseBody = "{\"ecPoint\":\"" + responseHex + "\",\"processIdentifier\":\"" + processIdentifier + "\"}";

    when(objectMapper.writeValueAsString(any())).thenReturn("{}");
    doReturn(httpResponse).when(httpClient).send(any(), any());
    when(httpResponse.body()).thenReturn(responseBody);
    when(objectMapper.readValue(eq(responseBody), eq(OprfResponse.class)))
        .thenReturn(new OprfResponse(responseHex, processIdentifier));

    OprfAccessor.Response result = accessor.handleRequest(SERVER_ID, "req-1", blindedPoint);

    assertThat(result.processIdentifier()).isEqualTo(processIdentifier);
    assertThat(OctetStringUtils.toHex(result.evaluatedPoint())).isEqualTo(responseHex);
  }

  @Test
  void handleRequest_unknownServer_throwsIllegalArgumentException() {
    ServerIdentifier unknown = new ServerIdentifier("not-registered");

    assertThatThrownBy(() -> accessor.handleRequest(unknown, "req-1", CURVE.g()))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("not-registered");
  }

  @Test
  @SuppressWarnings("unchecked")
  void handleRequest_ioException_throwsOprfAccessorException() throws Exception {
    when(objectMapper.writeValueAsString(any())).thenReturn("{}");
    doThrow(new IOException("connection refused")).when(httpClient).send(any(), any());

    assertThatThrownBy(() -> accessor.handleRequest(SERVER_ID, "req-1", CURVE.g()))
        .isInstanceOf(OprfAccessorException.class)
        .hasMessageContaining("test-server")
        .hasCauseInstanceOf(IOException.class);
  }

  @Test
  @SuppressWarnings("unchecked")
  void handleRequest_interrupted_throwsOprfAccessorExceptionAndRestoresInterruptFlag() throws Exception {
    when(objectMapper.writeValueAsString(any())).thenReturn("{}");
    doThrow(new InterruptedException("interrupted")).when(httpClient).send(any(), any());

    try {
      assertThatThrownBy(() -> accessor.handleRequest(SERVER_ID, "req-1", CURVE.g()))
          .isInstanceOf(OprfAccessorException.class)
          .hasCauseInstanceOf(InterruptedException.class);

      assertThat(Thread.currentThread().isInterrupted()).isTrue();
    } finally {
      Thread.interrupted(); // clear flag so it doesn't bleed into other tests
    }
  }
}
