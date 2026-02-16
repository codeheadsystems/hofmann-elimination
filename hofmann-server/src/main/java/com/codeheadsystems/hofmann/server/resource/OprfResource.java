package com.codeheadsystems.hofmann.server.resource;

import com.codeheadsystems.hofmann.model.OprfRequest;
import com.codeheadsystems.hofmann.model.OprfResponse;
import com.codeheadsystems.hofmann.server.manager.OprfManager;
import com.codeheadsystems.oprf.curve.Curve;
import com.codeheadsystems.oprf.curve.OctetStringUtils;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import javax.inject.Inject;
import javax.inject.Singleton;
import org.bouncycastle.math.ec.ECPoint;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Singleton
@Path("/oprf")
public class OprfResource {
  private static final Logger log = LoggerFactory.getLogger(OprfResource.class);

  private final OprfManager oprfManager;
  private final Curve curve;

  @Inject
  public OprfResource(final OprfManager oprfManager, final Curve curve) {
    log.info("OprfResource({})", oprfManager);
    this.oprfManager = oprfManager;
    this.curve = curve;
  }

  @POST
  @Consumes(MediaType.APPLICATION_JSON)
  @Produces(MediaType.APPLICATION_JSON)
  public OprfResponse evaluate(final OprfRequest request) {
    log.trace("evaluate(requestId={})", request.requestId());
    final ECPoint blindedPoint = OctetStringUtils.toEcPoint(curve, request.hexCodedEcPoint());
    final OprfManager.EvaluationResult result = oprfManager.evaluate(request.requestId(), blindedPoint);
    return new OprfResponse(OctetStringUtils.toHex(result.evaluatedPoint()), result.processIdentifier());
  }
}
