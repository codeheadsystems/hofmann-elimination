package com.codeheadsystems.hofmann.server.resource;

import com.codeheadsystems.hofmann.model.oprf.OprfRequest;
import com.codeheadsystems.hofmann.model.oprf.OprfResponse;
import com.codeheadsystems.rfc.oprf.manager.OprfServerManager;
import com.codeheadsystems.rfc.oprf.model.EvaluatedResponse;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.WebApplicationException;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import javax.inject.Inject;
import javax.inject.Singleton;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * The type Oprf resource.
 */
@Singleton
@Path("/oprf")
public class OprfResource {
  private static final Logger log = LoggerFactory.getLogger(OprfResource.class);

  private final OprfServerManager oprfServerManager;

  /**
   * Instantiates a new Oprf resource.
   *
   * @param oprfServerManager the oprf server manager
   */
  @Inject
  public OprfResource(final OprfServerManager oprfServerManager) {
    this.oprfServerManager = oprfServerManager;
    log.info("OprfResource({})", oprfServerManager);
  }

  /**
   * Evaluate oprf response.
   *
   * @param request the request
   * @return the oprf response
   */
  @POST
  @Consumes(MediaType.APPLICATION_JSON)
  @Produces(MediaType.APPLICATION_JSON)
  public OprfResponse evaluate(final OprfRequest request) {
    log.trace("evaluate(requestId={})", request.requestId());
    // Validate inputs before passing to crypto layer to return 400 instead of 500 for bad input
    if (request.ecPoint() == null || request.ecPoint().isBlank()) {
      throw new WebApplicationException("Missing required field: ecPoint", Response.Status.BAD_REQUEST);
    }
    if (request.requestId() == null || request.requestId().isBlank()) {
      throw new WebApplicationException("Missing required field: requestId", Response.Status.BAD_REQUEST);
    }
    try {
      final EvaluatedResponse evaluatedResponse = oprfServerManager.process(request.blindedRequest());
      return new OprfResponse(evaluatedResponse);
    } catch (IllegalArgumentException e) {
      throw new WebApplicationException("Invalid EC point data", Response.Status.BAD_REQUEST);
    }
  }
}
