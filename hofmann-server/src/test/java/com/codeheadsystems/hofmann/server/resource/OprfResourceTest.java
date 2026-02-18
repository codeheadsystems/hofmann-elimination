package com.codeheadsystems.hofmann.server.resource;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

import com.codeheadsystems.hofmann.model.oprf.OprfRequest;
import com.codeheadsystems.hofmann.model.oprf.OprfResponse;
import com.codeheadsystems.hofmann.server.manager.OprfManager;
import com.codeheadsystems.oprf.curve.Curve;
import com.codeheadsystems.oprf.curve.OctetStringUtils;
import org.bouncycastle.math.ec.ECPoint;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class OprfResourceTest {

  private static final Curve CURVE = Curve.P256_CURVE;

  @Mock private OprfManager oprfManager;

  private OprfResource resource;

  @BeforeEach
  void setUp() {
    resource = new OprfResource(oprfManager, CURVE);
  }

  @Test
  void evaluate_success_returnsOprfResponseWithEvaluatedPoint() {
    ECPoint inputPoint = CURVE.g();
    ECPoint evaluatedPoint = CURVE.g().multiply(CURVE.n().subtract(java.math.BigInteger.ONE)).normalize();
    String requestId = "req-42";
    String processIdentifier = "proc-xyz";
    String inputHex = OctetStringUtils.toHex(inputPoint);
    String evaluatedHex = OctetStringUtils.toHex(evaluatedPoint);

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
    ECPoint point = CURVE.g().multiply(java.math.BigInteger.TWO).normalize();
    String hex = OctetStringUtils.toHex(point);
    String requestId = "req-rt";
    String processIdentifier = "proc-rt";

    OprfRequest request = new OprfRequest(hex, requestId);
    OprfManager.EvaluationResult evaluationResult =
        new OprfManager.EvaluationResult(processIdentifier, requestId, point);

    when(oprfManager.evaluate(requestId, point)).thenReturn(evaluationResult);

    OprfResponse response = resource.evaluate(request);

    // The hex in the response should decode back to the same point
    ECPoint decoded = OctetStringUtils.toEcPoint(CURVE, response.hexCodedEcPoint());
    assertThat(decoded.normalize()).isEqualTo(point);
  }
}
