package com.codeheadsystems.hofmann.server.manager;

import com.codeheadsystems.oprf.model.ServerProcessorDetail;
import java.util.function.Supplier;
import javax.inject.Inject;
import javax.inject.Singleton;
import org.bouncycastle.math.ec.ECPoint;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Singleton
public class OprfManager {
  static private final Logger log = LoggerFactory.getLogger(OprfManager.class);

  private final Supplier<ServerProcessorDetail> processorDetailSupplier;

  @Inject
  public OprfManager(final Supplier<ServerProcessorDetail> processorDetailSupplier) {
    this.processorDetailSupplier = processorDetailSupplier;
    log.info("OprfManager({})", processorDetailSupplier);
  }

  public EvaluationResult evaluate(String requestId, ECPoint blindedPoint) {
    ServerProcessorDetail serverProcessorDetail = processorDetailSupplier.get();
    log.info("evaluate(requestId+{}, processorIdentifier={})", requestId, serverProcessorDetail.processorIdentifier());
    ECPoint result = blindedPoint.multiply(serverProcessorDetail.masterKey()).normalize();
    return new EvaluationResult(serverProcessorDetail.processorIdentifier(), requestId, result);
  }

  public record EvaluationResult(String processIdentifier, String requestId, ECPoint evaluatedPoint) {
  }

}
