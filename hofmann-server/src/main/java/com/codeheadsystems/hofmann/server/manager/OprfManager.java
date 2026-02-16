package com.codeheadsystems.hofmann.server.manager;

import com.codeheadsystems.hofmann.server.model.ProcessorDetail;
import java.util.function.Supplier;
import javax.inject.Inject;
import javax.inject.Singleton;
import org.bouncycastle.math.ec.ECPoint;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Singleton
public class OprfManager {
  static private final Logger log = LoggerFactory.getLogger(OprfManager.class);

  private final Supplier<ProcessorDetail> processorDetailSupplier;

  @Inject
  public OprfManager(final Supplier<ProcessorDetail> processorDetailSupplier) {
    this.processorDetailSupplier = processorDetailSupplier;
    log.info("OprfManager({})", processorDetailSupplier);
  }

  public EvaluationResult evaluate(String requestId, ECPoint blindedPoint) {
    ProcessorDetail processorDetail = processorDetailSupplier.get();
    log.info("evaluate(requestId+{}, processorIdentifier={})", requestId, processorDetail.processorIdentifier());
    ECPoint result = blindedPoint.multiply(processorDetail.masterKey()).normalize();
    return new EvaluationResult(processorDetail.processorIdentifier(), requestId, result);
  }

  public record EvaluationResult(String processIdentifier, String requestId, ECPoint evaluatedPoint) {
  }

}
