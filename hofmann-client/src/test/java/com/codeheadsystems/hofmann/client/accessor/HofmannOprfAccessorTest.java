package com.codeheadsystems.hofmann.client.accessor;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

import com.codeheadsystems.hofmann.client.config.OprfClientConfig;
import com.codeheadsystems.hofmann.client.exceptions.OprfAccessorException;
import com.codeheadsystems.hofmann.client.model.ServerConnectionInfo;
import com.codeheadsystems.hofmann.client.model.ServerIdentifier;
import com.codeheadsystems.hofmann.model.oprf.OprfRequest;
import com.codeheadsystems.hofmann.model.oprf.OprfResponse;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.HashMap;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class HofmannOprfAccessorTest {

  private static final OprfClientConfig CONFIG = new OprfClientConfig();
  private static final ServerIdentifier SERVER_ID = new ServerIdentifier("test-server");
  private static final ServerIdentifier UNKNOWN_SERVER_ID = new ServerIdentifier("unknown-server");
  private static final URI ENDPOINT = URI.create("http://localhost:8080/oprf");
  private static final String EC_POINT = "03abcdef";
  private static final String REQUEST_ID = "req-001";
  private static final String REQUEST_JSON = "{\"ecPoint\":\"03abcdef\",\"requestId\":\"req-001\"}";
  private static final String RESPONSE_JSON = "{\"ecPoint\":\"02fedcba\",\"processIdentifier\":\"proc-1\"}";

  @Mock private HttpClient httpClient;
  @Mock private HttpResponse<String> httpResponse;
  @Mock private ObjectMapper objectMapper;

  private HofmannOprfAccessor accessor;

  @BeforeEach
  void setUp() {
    Map<ServerIdentifier, ServerConnectionInfo> connections = new HashMap<>();
    connections.put(SERVER_ID, new ServerConnectionInfo(ENDPOINT));
    accessor = new HofmannOprfAccessor(CONFIG, httpClient, objectMapper, connections);
  }

  @Test
  @SuppressWarnings("unchecked")
  void handleRequest_success_returnsDeserializedResponse() throws Exception {
    OprfRequest request = new OprfRequest(EC_POINT, REQUEST_ID);
    OprfResponse expectedResponse = new OprfResponse("02fedcba", "proc-1");

    when(objectMapper.writeValueAsString(request)).thenReturn(REQUEST_JSON);
    when(httpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class))).thenReturn(httpResponse);
    when(httpResponse.body()).thenReturn(RESPONSE_JSON);
    when(objectMapper.readValue(RESPONSE_JSON, OprfResponse.class)).thenReturn(expectedResponse);

    OprfResponse result = accessor.handleRequest(SERVER_ID, request);

    assertThat(result.ecPoint()).isEqualTo(expectedResponse.ecPoint());
    assertThat(result.processIdentifier()).isEqualTo(expectedResponse.processIdentifier());
  }

  @Test
  void handleRequest_unknownServer_throwsIllegalArgument() {
    OprfRequest request = new OprfRequest(EC_POINT, REQUEST_ID);

    assertThatThrownBy(() -> accessor.handleRequest(UNKNOWN_SERVER_ID, request))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("unknown-server");
  }

  @Test
  @SuppressWarnings("unchecked")
  void handleRequest_ioException_throwsOprfAccessorException() throws Exception {
    OprfRequest request = new OprfRequest(EC_POINT, REQUEST_ID);

    when(objectMapper.writeValueAsString(request)).thenReturn(REQUEST_JSON);
    when(httpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
        .thenThrow(new IOException("network error"));

    assertThatThrownBy(() -> accessor.handleRequest(SERVER_ID, request))
        .isInstanceOf(OprfAccessorException.class)
        .hasMessageContaining("test-server")
        .hasCauseInstanceOf(IOException.class);
  }

  @Test
  @SuppressWarnings("unchecked")
  void handleRequest_interruptedException_throwsOprfAccessorException() throws Exception {
    OprfRequest request = new OprfRequest(EC_POINT, REQUEST_ID);

    when(objectMapper.writeValueAsString(request)).thenReturn(REQUEST_JSON);
    when(httpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
        .thenThrow(new InterruptedException("interrupted"));

    assertThatThrownBy(() -> accessor.handleRequest(SERVER_ID, request))
        .isInstanceOf(OprfAccessorException.class)
        .hasMessageContaining("test-server")
        .hasCauseInstanceOf(InterruptedException.class);

    assertThat(Thread.currentThread().isInterrupted()).isTrue();
    Thread.interrupted(); // clear the flag so it doesn't bleed into other tests
  }
}
