package com.codeheadsystems.hofmann.client.accessor;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

import com.codeheadsystems.hofmann.client.config.OprfClientConfig;
import com.codeheadsystems.hofmann.client.exceptions.OprfAccessorException;
import com.codeheadsystems.hofmann.client.exceptions.OprfModeNotEnabledException;
import com.codeheadsystems.hofmann.client.exceptions.OprfRateLimitedException;
import com.codeheadsystems.hofmann.client.exceptions.OprfRequestTooLargeException;
import com.codeheadsystems.hofmann.client.model.ServerConnectionInfo;
import com.codeheadsystems.hofmann.client.model.ServerIdentifier;
import com.codeheadsystems.hofmann.model.oprf.PoprfRequest;
import com.codeheadsystems.hofmann.model.oprf.PoprfResponse;
import com.codeheadsystems.hofmann.model.oprf.VoprfRequest;
import com.codeheadsystems.hofmann.model.oprf.VoprfResponse;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpHeaders;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

/**
 * Transport behaviour of the verifiable-mode endpoints, and the URI resolution all four OPRF paths
 * now share.
 *
 * <p>The URI cases are the ones worth reading. {@code getOprfConfig} previously built
 * {@code endpoint().resolve(endpoint().getPath() + "/oprf/config")}, which against the
 * {@code .../oprf} base every caller in this repository configures resolved to
 * {@code /oprf/oprf/config}. It went unnoticed because every one of those callers also passes a
 * config override, so the auto-fetch path never ran against a live server. Adding two more paths
 * to the same accessor made picking a convention unavoidable.
 */
@ExtendWith(MockitoExtension.class)
class HofmannOprfAccessorVerifiableTest {

  private static final OprfClientConfig CONFIG = new OprfClientConfig();
  private static final ServerIdentifier SERVER_ID = new ServerIdentifier("test-server");
  private static final String REQUEST_JSON = "{}";
  private static final String VOPRF_RESPONSE_JSON =
      "{\"evaluatedElements\":[\"02aa\"],\"proof\":\"beef\",\"processIdentifier\":\"proc-1\"}";
  private static final String POPRF_RESPONSE_JSON =
      "{\"evaluatedElements\":[\"03bb\"],\"proof\":\"cafe\",\"processIdentifier\":\"proc-2\"}";

  @Mock private HttpClient httpClient;
  @Mock private HttpResponse<String> httpResponse;
  @Mock private ObjectMapper objectMapper;

  private HofmannOprfAccessor accessorFor(final ServerConnectionInfo info) {
    return new HofmannOprfAccessor(CONFIG, httpClient, objectMapper, Map.of(SERVER_ID, info));
  }

  private HofmannOprfAccessor accessor;

  @BeforeEach
  void setUp() {
    accessor = accessorFor(new ServerConnectionInfo(URI.create("http://localhost:8080/oprf")));
  }

  // ─── URI resolution ────────────────────────────────────────────────────────

  private static ServerConnectionInfo info(final String uri) {
    return new ServerConnectionInfo(URI.create(uri));
  }

  @Test
  void oprfUri_oprfBaseEndpoint_doesNotDoubleTheSegment() {
    ServerConnectionInfo base = info("http://localhost:8080/oprf");

    assertThat(HofmannOprfAccessor.oprfUri(base, "").toString())
        .isEqualTo("http://localhost:8080/oprf");
    assertThat(HofmannOprfAccessor.oprfUri(base, "/config").toString())
        .isEqualTo("http://localhost:8080/oprf/config");
    assertThat(HofmannOprfAccessor.oprfUri(base, "/verifiable").toString())
        .isEqualTo("http://localhost:8080/oprf/verifiable");
    assertThat(HofmannOprfAccessor.oprfUri(base, "/partially-oblivious").toString())
        .isEqualTo("http://localhost:8080/oprf/partially-oblivious");
  }

  @Test
  void oprfUri_rootEndpoint_appendsTheSegment() {
    assertThat(HofmannOprfAccessor.oprfUri(info("http://localhost:8080"), "/config").toString())
        .isEqualTo("http://localhost:8080/oprf/config");
    assertThat(HofmannOprfAccessor.oprfUri(info("http://localhost:8080"), "").toString())
        .isEqualTo("http://localhost:8080/oprf");
  }

  @Test
  void oprfUri_trailingSlashes_areStrippedBeforeTheDecision() {
    assertThat(HofmannOprfAccessor.oprfUri(info("http://localhost:8080/oprf/"), "/config")
        .toString()).isEqualTo("http://localhost:8080/oprf/config");
    assertThat(HofmannOprfAccessor.oprfUri(info("http://localhost:8080/oprf//"), "/config")
        .toString()).isEqualTo("http://localhost:8080/oprf/config");
    assertThat(HofmannOprfAccessor.oprfUri(info("http://localhost:8080/"), "/config")
        .toString()).isEqualTo("http://localhost:8080/oprf/config");
  }

  @Test
  void oprfUri_contextPath_isPreserved() {
    assertThat(HofmannOprfAccessor.oprfUri(info("http://localhost:8080/api"), "/verifiable")
        .toString()).isEqualTo("http://localhost:8080/api/oprf/verifiable");
    assertThat(HofmannOprfAccessor.oprfUri(info("http://localhost:8080/api/oprf"), "/verifiable")
        .toString()).isEqualTo("http://localhost:8080/api/oprf/verifiable");
  }

  /**
   * The escape hatch for a deployment that mounts the resource somewhere whose path does not end
   * in {@code /oprf} — where the inference would otherwise append a segment that is not there.
   */
  @Test
  void oprfUri_explicitBasePath_overridesTheInference() {
    ServerConnectionInfo custom = new ServerConnectionInfo(
        URI.create("http://localhost:8080/gateway"), "/gateway/crypto");

    assertThat(HofmannOprfAccessor.oprfUri(custom, "/verifiable").toString())
        .isEqualTo("http://localhost:8080/gateway/crypto/verifiable");
  }

  @Test
  @SuppressWarnings("unchecked")
  void getOprfConfig_oprfBaseEndpoint_requestsTheConfigPathOnce() throws Exception {
    when(httpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
        .thenReturn(httpResponse);
    when(httpResponse.statusCode()).thenReturn(200);
    when(httpResponse.body()).thenReturn("{\"cipherSuite\":\"P256_SHA256\"}");
    when(objectMapper.readValue(any(String.class), any(Class.class))).thenReturn(null);

    accessor.getOprfConfig(SERVER_ID);

    ArgumentCaptor<HttpRequest> captor = ArgumentCaptor.forClass(HttpRequest.class);
    org.mockito.Mockito.verify(httpClient)
        .send(captor.capture(), any(HttpResponse.BodyHandler.class));
    assertThat(captor.getValue().uri().toString())
        .isEqualTo("http://localhost:8080/oprf/config");
  }

  // ─── Verifiable round trips ────────────────────────────────────────────────

  @SuppressWarnings("unchecked")
  private void stubPost(final int status, final String body) throws Exception {
    when(objectMapper.writeValueAsString(any())).thenReturn(REQUEST_JSON);
    when(httpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
        .thenReturn(httpResponse);
    when(httpResponse.statusCode()).thenReturn(status);
    if (body != null) {
      when(httpResponse.body()).thenReturn(body);
    }
  }

  @Test
  @SuppressWarnings("unchecked")
  void handleVerifiableRequest_success_postsToVerifiableAndDeserializes() throws Exception {
    VoprfResponse expected = new VoprfResponse(List.of("02aa"), "beef", "proc-1");
    stubPost(200, VOPRF_RESPONSE_JSON);
    when(objectMapper.readValue(VOPRF_RESPONSE_JSON, VoprfResponse.class)).thenReturn(expected);

    VoprfResponse result =
        accessor.handleVerifiableRequest(SERVER_ID, new VoprfRequest(List.of("02cc"), "req-1"));

    assertThat(result).isEqualTo(expected);
    ArgumentCaptor<HttpRequest> captor = ArgumentCaptor.forClass(HttpRequest.class);
    org.mockito.Mockito.verify(httpClient)
        .send(captor.capture(), any(HttpResponse.BodyHandler.class));
    assertThat(captor.getValue().uri().toString())
        .isEqualTo("http://localhost:8080/oprf/verifiable");
    assertThat(captor.getValue().method()).isEqualTo("POST");
  }

  @Test
  @SuppressWarnings("unchecked")
  void handlePartiallyObliviousRequest_success_postsToPartiallyOblivious() throws Exception {
    PoprfResponse expected = new PoprfResponse(List.of("03bb"), "cafe", "proc-2");
    stubPost(200, POPRF_RESPONSE_JSON);
    when(objectMapper.readValue(POPRF_RESPONSE_JSON, PoprfResponse.class)).thenReturn(expected);

    PoprfResponse result = accessor.handlePartiallyObliviousRequest(
        SERVER_ID, new PoprfRequest(List.of("02cc"), "", "req-1"));

    assertThat(result).isEqualTo(expected);
    ArgumentCaptor<HttpRequest> captor = ArgumentCaptor.forClass(HttpRequest.class);
    org.mockito.Mockito.verify(httpClient)
        .send(captor.capture(), any(HttpResponse.BodyHandler.class));
    assertThat(captor.getValue().uri().toString())
        .isEqualTo("http://localhost:8080/oprf/partially-oblivious");
  }

  // ─── Status mapping ────────────────────────────────────────────────────────

  /**
   * A 404 is how a deployment without a key for the mode answers. It is the capability probe, so
   * it gets its own type rather than the generic accessor exception.
   */
  @Test
  void handleVerifiableRequest_404_throwsModeNotEnabled() throws Exception {
    stubPost(404, null);

    assertThatThrownBy(() -> accessor.handleVerifiableRequest(
        SERVER_ID, new VoprfRequest(List.of("02cc"), "req-1")))
        .isInstanceOf(OprfModeNotEnabledException.class)
        .hasMessageContaining("VOPRF")
        .hasMessageContaining("test-server");
  }

  @Test
  void handlePartiallyObliviousRequest_404_namesPoprf() throws Exception {
    stubPost(404, null);

    assertThatThrownBy(() -> accessor.handlePartiallyObliviousRequest(
        SERVER_ID, new PoprfRequest(List.of("02cc"), "", "req-1")))
        .isInstanceOf(OprfModeNotEnabledException.class)
        .hasMessageContaining("POPRF");
  }

  @Test
  void handleVerifiableRequest_413_throwsRequestTooLarge() throws Exception {
    stubPost(413, null);

    assertThatThrownBy(() -> accessor.handleVerifiableRequest(
        SERVER_ID, new VoprfRequest(List.of("02cc"), "req-1")))
        .isInstanceOf(OprfRequestTooLargeException.class)
        .hasMessageContaining("too large");
  }

  @Test
  void handleVerifiableRequest_429_carriesTheRetryAfter() throws Exception {
    stubPost(429, null);
    when(httpResponse.headers()).thenReturn(
        HttpHeaders.of(Map.of("Retry-After", List.of("60")), (a, b) -> true));

    assertThatThrownBy(() -> accessor.handleVerifiableRequest(
        SERVER_ID, new VoprfRequest(List.of("02cc"), "req-1")))
        .isInstanceOf(OprfRateLimitedException.class)
        .satisfies(e -> assertThat(((OprfRateLimitedException) e).retryAfter())
            .isEqualTo(Duration.ofSeconds(60)));
  }

  /**
   * Spring's adapter does not set {@code Retry-After}. Null means "no guidance", which a caller
   * must not read as "retry immediately".
   */
  @Test
  void handleVerifiableRequest_429_withoutRetryAfter_leavesItNull() throws Exception {
    stubPost(429, null);
    when(httpResponse.headers()).thenReturn(HttpHeaders.of(Map.of(), (a, b) -> true));

    assertThatThrownBy(() -> accessor.handleVerifiableRequest(
        SERVER_ID, new VoprfRequest(List.of("02cc"), "req-1")))
        .isInstanceOf(OprfRateLimitedException.class)
        .satisfies(e -> assertThat(((OprfRateLimitedException) e).retryAfter()).isNull());
  }

  @Test
  void handleVerifiableRequest_429_withUnparseableRetryAfter_leavesItNull() throws Exception {
    stubPost(429, null);
    when(httpResponse.headers()).thenReturn(
        HttpHeaders.of(Map.of("Retry-After", List.of("Wed, 21 Oct 2026 07:28:00 GMT")),
            (a, b) -> true));

    assertThatThrownBy(() -> accessor.handleVerifiableRequest(
        SERVER_ID, new VoprfRequest(List.of("02cc"), "req-1")))
        .isInstanceOf(OprfRateLimitedException.class)
        .satisfies(e -> assertThat(((OprfRateLimitedException) e).retryAfter()).isNull());
  }

  @Test
  void handleVerifiableRequest_400_throwsGenericAccessorException() throws Exception {
    stubPost(400, null);

    assertThatThrownBy(() -> accessor.handleVerifiableRequest(
        SERVER_ID, new VoprfRequest(List.of("02cc"), "req-1")))
        .isInstanceOf(OprfAccessorException.class)
        .hasMessageContaining("400");
  }

  @Test
  void handleVerifiableRequest_401_throwsSecurityException() throws Exception {
    stubPost(401, null);

    assertThatThrownBy(() -> accessor.handleVerifiableRequest(
        SERVER_ID, new VoprfRequest(List.of("02cc"), "req-1")))
        .isInstanceOf(SecurityException.class);
  }

  /**
   * Every new exception type extends {@code OprfAccessorException} so a caller that already wrote
   * {@code catch (OprfAccessorException)} keeps working. The one that does not is the key
   * mismatch, and it is not raised from here.
   */
  @Test
  void newStatusExceptions_remainCatchableAsAccessorExceptions() throws Exception {
    stubPost(404, null);

    assertThatThrownBy(() -> accessor.handleVerifiableRequest(
        SERVER_ID, new VoprfRequest(List.of("02cc"), "req-1")))
        .isInstanceOf(OprfAccessorException.class);
  }

  @Test
  void handleVerifiableRequest_unknownServer_throwsIllegalArgument() {
    assertThatThrownBy(() -> accessor.handleVerifiableRequest(
        new ServerIdentifier("nope"), new VoprfRequest(List.of("02cc"), "req-1")))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("nope");
  }
}
