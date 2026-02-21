package com.codeheadsystems.hofmann.server.resource;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

import com.codeheadsystems.hofmann.model.oprf.OprfRequest;
import com.codeheadsystems.hofmann.model.oprf.OprfResponse;
import com.codeheadsystems.hofmann.server.manager.OprfManager;
import com.codeheadsystems.ellipticcurve.rfc9380.WeierstrassGroupSpecImpl;
import org.bouncycastle.math.ec.ECPoint;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class OprfResourceTest {

  private static final WeierstrassGroupSpecImpl GROUP_SPEC = WeierstrassGroupSpecImpl.P256_SHA256;

  @Mock private OprfManager oprfManager;

  private OprfResource resource;

  @BeforeEach
  void setUp() {
    resource = new OprfResource(oprfManager, GROUP_SPEC);
  }

  @Test
  void evaluate_success_returnsOprfResponseWithEvaluatedPoint() {
    ECPoint inputPoint = GROUP_SPEC.curve().g();
    ECPoint evaluatedPoint = GROUP_SPEC.curve().g().multiply(GROUP_SPEC.curve().n().subtract(java.math.BigInteger.ONE)).normalize();
    String requestId = "req-42";
    String processIdentifier = "proc-xyz";
    String inputHex = GROUP_SPEC.toHex(inputPoint);
    String evaluatedHex = GROUP_SPEC.toHex(evaluatedPoint);

    OprfRequest request = new OprfRequest(inputHex, requestId);
    OprfManager.EvaluationResult evaluationResult =
        new OprfManager.EvaluationResult(processIdentifier, requestId, evaluatedPoint);

    when(oprfManager.evaluate(requestId, inputPoint)).thenReturn(evaluationResult);

    OprfResponse response = resource.evaluate(request);

    assertThat(response.hexCodedEcPoint()).isEqualTo(evaluatedHex);
    assertThat(response.processIdentifier()).isEqualTo(processIdentifier);
  }

  @Test
  void evaluate_hexRoundTrip_pointDecodedCorrectly() {
    ECPoint point = GROUP_SPEC.curve().g().multiply(java.math.BigInteger.TWO).normalize();
    String hex = GROUP_SPEC.toHex(point);
    String requestId = "req-rt";
    String processIdentifier = "proc-rt";

    OprfRequest request = new OprfRequest(hex, requestId);
    OprfManager.EvaluationResult evaluationResult =
        new OprfManager.EvaluationResult(processIdentifier, requestId, point);

    when(oprfManager.evaluate(requestId, point)).thenReturn(evaluationResult);

    OprfResponse response = resource.evaluate(request);

    // The hex in the response should decode back to the same point
    ECPoint decoded = GROUP_SPEC.toEcPoint(response.hexCodedEcPoint());
    assertThat(decoded.normalize()).isEqualTo(point);
  }
}
