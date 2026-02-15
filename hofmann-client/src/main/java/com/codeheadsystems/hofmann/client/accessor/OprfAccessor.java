package com.codeheadsystems.hofmann.client.accessor;

import com.codeheadsystems.hofmann.client.config.OprfConfig;
import com.codeheadsystems.hofmann.client.model.ServerIdentifier;
import com.codeheadsystems.hofmann.model.OprfResponse;
import com.codeheadsystems.oprf.curve.Curve;
import com.codeheadsystems.oprf.curve.OctetStringUtils;
import javax.inject.Inject;
import javax.inject.Singleton;
import org.bouncycastle.math.ec.ECPoint;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Singleton
public class OprfAccessor {
  private static final Logger log = LoggerFactory.getLogger(OprfAccessor.class);

  private final Curve curve;

  @Inject
  public OprfAccessor(final OprfConfig oprfConfig) {
    log.info("OprfAccessor({})", oprfConfig);
    this.curve = oprfConfig.curve();
  }

  public Response handleRequest(final ServerIdentifier serverIdentifier,
                                final String requestId,
                                final ECPoint blindedPoint) {
    log.trace("handleRequest(requestId={}, serverIdentifier={})", serverIdentifier, requestId);
    String blindedPointHex = OctetStringUtils.toHex(blindedPoint);

    final OprfResponse response = null; // TODO: call server with blindedPointHex and get response back.

    ECPoint evaluatedPoint = OctetStringUtils.toEcPoint(curve, response.hexCodedEcPoint());
    return new Response(evaluatedPoint, response.processIdentifier());
  }

  public record Response(ECPoint evaluatedPoint, String processIdentifier) {
  }
}
