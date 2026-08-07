package com.codeheadsystems.hofmann.server.resource;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.codeheadsystems.hofmann.model.oprf.OprfClientConfigResponse;
import com.codeheadsystems.hofmann.model.oprf.PoprfRequest;
import com.codeheadsystems.hofmann.model.oprf.PoprfResponse;
import com.codeheadsystems.hofmann.model.oprf.VoprfRequest;
import com.codeheadsystems.hofmann.model.oprf.VoprfResponse;
import com.codeheadsystems.rfc.oprf.manager.OprfServerManager;
import com.codeheadsystems.rfc.oprf.manager.PoprfClientManager;
import com.codeheadsystems.rfc.oprf.manager.PoprfServerManager;
import com.codeheadsystems.rfc.oprf.manager.VoprfClientManager;
import com.codeheadsystems.rfc.oprf.manager.VoprfServerManager;
import com.codeheadsystems.rfc.oprf.model.PoprfClientContext;
import com.codeheadsystems.rfc.oprf.model.VerifiableProcessorDetail;
import com.codeheadsystems.rfc.oprf.model.VoprfClientContext;
import com.codeheadsystems.rfc.oprf.rfc9497.CurveHashSuite;
import com.codeheadsystems.rfc.oprf.rfc9497.OprfCipherSuite;
import com.codeheadsystems.rfc.oprf.rfc9497.OprfMode;
import jakarta.ws.rs.WebApplicationException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.List;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.ext.RuntimeDelegate;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * End-to-end tests for the verifiable OPRF endpoints: a real client blinds, the resource
 * evaluates, and the client verifies the proof.
 *
 * <p>Mocking the managers would test the plumbing and nothing else. The property that matters is
 * that a response coming back through the wire models still verifies against the server's public
 * key — if the batch order, the proof, or the hex encoding were mangled anywhere in the transport,
 * verification is what notices.
 */
@ExtendWith(MockitoExtension.class)
class OprfResourceVerifiableTest {

  private static final BigInteger VOPRF_KEY = new BigInteger("42424242424242424242424242", 16);
  private static final BigInteger POPRF_KEY = new BigInteger("13131313131313131313131313", 16);

  @Mock private OprfServerManager baseManager;

  private static final AtomicInteger LAST_STATUS = new AtomicInteger(-1);

  /**
   * Installs the same mock {@link RuntimeDelegate} the base-mode resource test uses. Building a
   * {@code WebApplicationException} with a {@code Response} needs a JAX-RS runtime, and this
   * module's tests have the API jar only, so the status is recorded as the builder sees it.
   */
  @BeforeAll
  static void installRuntimeDelegate() {
    RuntimeDelegate mockRd = mock(RuntimeDelegate.class);
    Response.ResponseBuilder mockBuilder = mock(Response.ResponseBuilder.class, Mockito.RETURNS_SELF);
    Response mockResponse = mock(Response.class);

    when(mockRd.createResponseBuilder()).thenReturn(mockBuilder);
    when(mockBuilder.status(anyInt())).thenAnswer(inv -> {
      LAST_STATUS.set(inv.getArgument(0));
      return mockBuilder;
    });
    when(mockBuilder.status(anyInt(), Mockito.nullable(String.class))).thenAnswer(inv -> {
      LAST_STATUS.set(inv.getArgument(0));
      return mockBuilder;
    });
    when(mockBuilder.status(Mockito.any(Response.StatusType.class))).thenAnswer(inv -> {
      LAST_STATUS.set(((Response.StatusType) inv.getArgument(0)).getStatusCode());
      return mockBuilder;
    });
    when(mockBuilder.build()).thenReturn(mockResponse);
    when(mockResponse.getStatus()).thenAnswer(inv -> LAST_STATUS.get());
    when(mockResponse.getStatusInfo())
        .thenAnswer(inv -> Response.Status.fromStatusCode(LAST_STATUS.get()));

    RuntimeDelegate.setInstance(mockRd);
  }

  @AfterAll
  static void removeRuntimeDelegate() {
    RuntimeDelegate.setInstance(null);
  }

  private OprfCipherSuite voprfSuite;
  private OprfCipherSuite poprfSuite;
  private VerifiableProcessorDetail voprfDetail;
  private VerifiableProcessorDetail poprfDetail;
  private OprfResource resource;

  @BeforeEach
  void setUp() {
    voprfSuite = OprfCipherSuite.builder()
        .withSuite(CurveHashSuite.P256_SHA256).withMode(OprfMode.VOPRF).build();
    poprfSuite = OprfCipherSuite.builder()
        .withSuite(CurveHashSuite.P256_SHA256).withMode(OprfMode.POPRF).build();
    voprfDetail = VerifiableProcessorDetail.derive(voprfSuite, VOPRF_KEY, "test-voprf");
    poprfDetail = VerifiableProcessorDetail.derive(poprfSuite, POPRF_KEY, "test-poprf");
    resource = new OprfResource(baseManager, new OprfClientConfigResponse("P256_SHA256"),
        key -> true, false,
        new VoprfServerManager(voprfSuite, () -> voprfDetail),
        new PoprfServerManager(poprfSuite, () -> poprfDetail));
  }

  @Test
  void voprf_batchRoundTripsAndTheProofVerifies() {
    VoprfClientManager client = new VoprfClientManager(voprfSuite, voprfDetail.publicKey());
    VoprfClientContext context = client.hashingContext(List.of(
        "alice".getBytes(StandardCharsets.UTF_8),
        "bob".getBytes(StandardCharsets.UTF_8)));

    VoprfRequest request = new VoprfRequest(client.eliminationRequest(context));
    VoprfResponse response = resource.evaluateVerifiable(request, null, null);

    assertThat(response.evaluatedElements()).hasSize(2);
    assertThat(response.processIdentifier()).isEqualTo("test-voprf");
    // The proof verifying is the assertion; hashResults throws if it does not.
    assertThat(client.hashResults(response.evaluatedResponse(), context)).hasSize(2);
  }

  @Test
  void voprf_orderIsPreservedAcrossTheWireModels() {
    VoprfClientManager client = new VoprfClientManager(voprfSuite, voprfDetail.publicKey());
    VoprfClientContext one = client.hashingContext(List.of("a".getBytes(StandardCharsets.UTF_8)));
    VoprfClientContext two = client.hashingContext(List.of("b".getBytes(StandardCharsets.UTF_8)));

    var first = client.hashResults(
        resource.evaluateVerifiable(new VoprfRequest(client.eliminationRequest(one)), null, null)
            .evaluatedResponse(), one);
    var second = client.hashResults(
        resource.evaluateVerifiable(new VoprfRequest(client.eliminationRequest(two)), null, null)
            .evaluatedResponse(), two);

    assertThat(first.get(0).hash()).isNotEqualTo(second.get(0).hash());
  }

  @Test
  void poprf_theSameInputUnderDifferentPublicInputsGivesUnrelatedOutputs() {
    PoprfClientManager client = new PoprfClientManager(poprfSuite, poprfDetail.publicKey());
    byte[] input = "alice".getBytes(StandardCharsets.UTF_8);
    byte[] infoA = "tenant-a".getBytes(StandardCharsets.UTF_8);
    byte[] infoB = "tenant-b".getBytes(StandardCharsets.UTF_8);

    PoprfClientContext ctxA = client.hashingContext(List.of(input), infoA);
    PoprfClientContext ctxB = client.hashingContext(List.of(input), infoB);

    PoprfResponse respA = resource.evaluatePartiallyOblivious(
        new PoprfRequest(client.eliminationRequest(ctxA)), null, null);
    PoprfResponse respB = resource.evaluatePartiallyOblivious(
        new PoprfRequest(client.eliminationRequest(ctxB)), null, null);

    // Separation by public input is the whole point of the mode: the proof is graded against the
    // tweaked key the client derived from the info it asked for, so both verify, and yet the
    // outputs are unrelated.
    assertThat(client.hashResults(respA.evaluatedResponse(), ctxA).get(0).hash())
        .isNotEqualTo(client.hashResults(respB.evaluatedResponse(), ctxB).get(0).hash());
  }

  @Test
  void malformedElement_is400ratherThan500() {
    VoprfRequest request = new VoprfRequest(List.of("not-a-point"), "req-1");
    assertThatThrownBy(() -> resource.evaluateVerifiable(request, null, null))
        .isInstanceOf(WebApplicationException.class)
        .satisfies(e -> assertThat(LAST_STATUS.get()).isEqualTo(400));
  }

  @Test
  void batchOverTheConfiguredCap_is400() {
    VoprfServerManager small = new VoprfServerManager(voprfSuite, () -> voprfDetail, 1);
    OprfResource capped = new OprfResource(baseManager,
        new OprfClientConfigResponse("P256_SHA256"), key -> true, false, small, null);

    VoprfClientManager client = new VoprfClientManager(voprfSuite, voprfDetail.publicKey());
    VoprfClientContext context = client.hashingContext(List.of(
        "a".getBytes(StandardCharsets.UTF_8), "b".getBytes(StandardCharsets.UTF_8)));

    assertThatThrownBy(() -> capped.evaluateVerifiable(
        new VoprfRequest(client.eliminationRequest(context)), null, null))
        .isInstanceOf(WebApplicationException.class)
        .satisfies(e -> assertThat(LAST_STATUS.get()).isEqualTo(400));
  }

  @Test
  void modeNotConfigured_is404ratherThan500() {
    OprfResource baseOnly = new OprfResource(baseManager,
        new OprfClientConfigResponse("P256_SHA256"), key -> true, false, null, null);

    assertThatThrownBy(() -> baseOnly.evaluateVerifiable(
        new VoprfRequest(List.of("02".repeat(33)), "req-1"), null, null))
        .isInstanceOf(WebApplicationException.class)
        .satisfies(e -> assertThat(LAST_STATUS.get()).isEqualTo(404));

    assertThatThrownBy(() -> baseOnly.evaluatePartiallyOblivious(
        new PoprfRequest(List.of("02".repeat(33)), "", "req-1"), null, null))
        .isInstanceOf(WebApplicationException.class)
        .satisfies(e -> assertThat(LAST_STATUS.get()).isEqualTo(404));
  }

  @Test
  void rateLimited_is429() {
    OprfResource limited = new OprfResource(baseManager,
        new OprfClientConfigResponse("P256_SHA256"), key -> false, false,
        new VoprfServerManager(voprfSuite, () -> voprfDetail), null);

    assertThatThrownBy(() -> limited.evaluateVerifiable(
        new VoprfRequest(List.of("02".repeat(33)), "req-1"), null, null))
        .isInstanceOf(WebApplicationException.class)
        .satisfies(e -> assertThat(LAST_STATUS.get()).isEqualTo(429));
  }
}
