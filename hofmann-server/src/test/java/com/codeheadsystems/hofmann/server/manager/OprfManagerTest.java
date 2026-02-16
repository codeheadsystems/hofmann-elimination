package com.codeheadsystems.hofmann.server.manager;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

import com.codeheadsystems.hofmann.server.model.ProcessorDetail;
import com.codeheadsystems.oprf.curve.Curve;
import com.codeheadsystems.oprf.curve.OctetStringUtils;
import java.math.BigInteger;
import java.util.function.Supplier;
import org.bouncycastle.math.ec.ECPoint;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class OprfManagerTest {

  private static final Curve CURVE = Curve.P256_CURVE;
  private static final BigInteger MASTER_KEY = BigInteger.valueOf(42L);
  private static final String PROCESS_ID = "proc-test";

  @Mock private Supplier<ProcessorDetail> processorDetailSupplier;

  private OprfManager manager;

  @BeforeEach
  void setUp() {
    manager = new OprfManager(processorDetailSupplier);
  }

  @Test
  void evaluate_returnsCorrectlyMultipliedPoint() {
    ECPoint blindedPoint = CURVE.g();
    ECPoint expectedPoint = blindedPoint.multiply(MASTER_KEY).normalize();
    when(processorDetailSupplier.get()).thenReturn(new ProcessorDetail(MASTER_KEY, PROCESS_ID));

    OprfManager.EvaluationResult result = manager.evaluate("req-1", blindedPoint);

    assertThat(result.requestId()).isEqualTo("req-1");
    assertThat(result.processIdentifier()).isEqualTo(PROCESS_ID);
    assertThat(OctetStringUtils.toHex(result.evaluatedPoint()))
        .isEqualTo(OctetStringUtils.toHex(expectedPoint));
  }

  @Test
  void evaluate_supplierCalledOnEachRequest() {
    ECPoint blindedPoint = CURVE.g();
    BigInteger key1 = BigInteger.valueOf(7L);
    BigInteger key2 = BigInteger.valueOf(13L);

    when(processorDetailSupplier.get())
        .thenReturn(new ProcessorDetail(key1, "proc-1"))
        .thenReturn(new ProcessorDetail(key2, "proc-2"));

    OprfManager.EvaluationResult result1 = manager.evaluate("req-1", blindedPoint);
    OprfManager.EvaluationResult result2 = manager.evaluate("req-2", blindedPoint);

    assertThat(result1.processIdentifier()).isEqualTo("proc-1");
    assertThat(result2.processIdentifier()).isEqualTo("proc-2");
    assertThat(OctetStringUtils.toHex(result1.evaluatedPoint()))
        .isNotEqualTo(OctetStringUtils.toHex(result2.evaluatedPoint()));
  }

  @Test
  void evaluate_differentBlindedPoints_produceDifferentResults() {
    ECPoint point1 = CURVE.g();
    ECPoint point2 = CURVE.g().multiply(BigInteger.TWO).normalize();
    ProcessorDetail detail = new ProcessorDetail(MASTER_KEY, PROCESS_ID);

    when(processorDetailSupplier.get()).thenReturn(detail);

    OprfManager.EvaluationResult result1 = manager.evaluate("req-1", point1);
    OprfManager.EvaluationResult result2 = manager.evaluate("req-2", point2);

    assertThat(OctetStringUtils.toHex(result1.evaluatedPoint()))
        .isNotEqualTo(OctetStringUtils.toHex(result2.evaluatedPoint()));
  }
}
