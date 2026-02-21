package com.codeheadsystems.hofmann.server.resource;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.codeheadsystems.hofmann.model.oprf.OprfRequest;
import com.codeheadsystems.hofmann.model.oprf.OprfResponse;
import com.codeheadsystems.oprf.manager.OprfServerManager;
import com.codeheadsystems.oprf.model.EvaluatedResponse;
import jakarta.ws.rs.WebApplicationException;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.ext.RuntimeDelegate;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class OprfResourceTest {

  private static final String EC_POINT = "03abcdef1234567890";
  private static final String REQUEST_ID = "req-001";
  private static final String PROCESS_ID = "proc-xyz";
  private static final String EVALUATED_POINT = "02fedcba0987654321";
  @Mock private OprfServerManager oprfServerManager;
  private OprfResource resource;

  @BeforeAll
  static void installRuntimeDelegate() {
    // WebApplicationException constructor requires a JAX-RS RuntimeDelegate implementation.
    // Since tests only have the API jar (no container), we install a mock delegate so that
    // WebApplicationException can be constructed and its HTTP status can be verified.
    RuntimeDelegate mockRd = mock(RuntimeDelegate.class);
    Response.ResponseBuilder mockBuilder = mock(Response.ResponseBuilder.class, Mockito.RETURNS_SELF);
    Response mock400 = mock(Response.class);

    when(mockRd.createResponseBuilder()).thenReturn(mockBuilder);
    when(mockBuilder.status(anyInt(), anyString())).thenReturn(mockBuilder);
    when(mockBuilder.build()).thenReturn(mock400);
    when(mock400.getStatus()).thenReturn(Response.Status.BAD_REQUEST.getStatusCode());

    RuntimeDelegate.setInstance(mockRd);
  }

  @AfterAll
  static void removeRuntimeDelegate() {
    RuntimeDelegate.setInstance(null);
  }

  @BeforeEach
  void setUp() {
    resource = new OprfResource(oprfServerManager);
  }

  @Test
  void evaluate_validRequest_returnsOprfResponse() {
    OprfRequest request = new OprfRequest(EC_POINT, REQUEST_ID);
    EvaluatedResponse evaluatedResponse = new EvaluatedResponse(EVALUATED_POINT, PROCESS_ID);
    when(oprfServerManager.process(request.blindedRequest())).thenReturn(evaluatedResponse);

    OprfResponse response = resource.evaluate(request);

    assertThat(response.ecPoint()).isEqualTo(EVALUATED_POINT);
    assertThat(response.processIdentifier()).isEqualTo(PROCESS_ID);
  }

  @Test
  void evaluate_nullEcPoint_throwsBadRequest() {
    OprfRequest request = new OprfRequest(null, REQUEST_ID);

    assertThatThrownBy(() -> resource.evaluate(request))
        .isInstanceOf(WebApplicationException.class)
        .satisfies(e -> assertThat(((WebApplicationException) e).getResponse().getStatus())
            .isEqualTo(Response.Status.BAD_REQUEST.getStatusCode()));
  }

  @Test
  void evaluate_blankEcPoint_throwsBadRequest() {
    OprfRequest request = new OprfRequest("   ", REQUEST_ID);

    assertThatThrownBy(() -> resource.evaluate(request))
        .isInstanceOf(WebApplicationException.class)
        .satisfies(e -> assertThat(((WebApplicationException) e).getResponse().getStatus())
            .isEqualTo(Response.Status.BAD_REQUEST.getStatusCode()));
  }

  @Test
  void evaluate_nullRequestId_throwsBadRequest() {
    OprfRequest request = new OprfRequest(EC_POINT, null);

    assertThatThrownBy(() -> resource.evaluate(request))
        .isInstanceOf(WebApplicationException.class)
        .satisfies(e -> assertThat(((WebApplicationException) e).getResponse().getStatus())
            .isEqualTo(Response.Status.BAD_REQUEST.getStatusCode()));
  }

  @Test
  void evaluate_blankRequestId_throwsBadRequest() {
    OprfRequest request = new OprfRequest(EC_POINT, "  ");

    assertThatThrownBy(() -> resource.evaluate(request))
        .isInstanceOf(WebApplicationException.class)
        .satisfies(e -> assertThat(((WebApplicationException) e).getResponse().getStatus())
            .isEqualTo(Response.Status.BAD_REQUEST.getStatusCode()));
  }

  @Test
  void evaluate_illegalArgumentFromServerManager_throwsBadRequest() {
    OprfRequest request = new OprfRequest(EC_POINT, REQUEST_ID);
    when(oprfServerManager.process(request.blindedRequest()))
        .thenThrow(new IllegalArgumentException("bad point"));

    assertThatThrownBy(() -> resource.evaluate(request))
        .isInstanceOf(WebApplicationException.class)
        .satisfies(e -> assertThat(((WebApplicationException) e).getResponse().getStatus())
            .isEqualTo(Response.Status.BAD_REQUEST.getStatusCode()));
  }
}
