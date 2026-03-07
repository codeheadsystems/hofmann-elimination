package com.codeheadsystems.hofmann.server.resource;

import com.codeheadsystems.hofmann.model.oprf.OprfClientConfigResponse;
import com.codeheadsystems.hofmann.model.oprf.OprfRequest;
import com.codeheadsystems.hofmann.model.oprf.OprfResponse;
import com.codeheadsystems.hofmann.server.ratelimit.RateLimitExceededException;
import com.codeheadsystems.hofmann.server.ratelimit.RateLimiter;
import com.codeheadsystems.rfc.oprf.manager.OprfServerManager;
import com.codeheadsystems.rfc.oprf.model.EvaluatedResponse;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.WebApplicationException;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.core.Context;
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
  private final OprfClientConfigResponse clientConfig;
  private final RateLimiter rateLimiter;

  /**
   * Instantiates a new Oprf resource.
   *
   * @param oprfServerManager the oprf server manager
   * @param clientConfig      the client config response to expose via GET /oprf/config
   * @param rateLimiter       rate limiter for the OPRF evaluate endpoint (keyed by client IP)
   */
  @Inject
  public OprfResource(final OprfServerManager oprfServerManager,
                      final OprfClientConfigResponse clientConfig,
                      final RateLimiter rateLimiter) {
    this.oprfServerManager = oprfServerManager;
    this.clientConfig = clientConfig;
    this.rateLimiter = rateLimiter;
    log.info("OprfResource({})", oprfServerManager);
  }

  /**
   * Returns the OPRF configuration that clients need to self-configure.
   *
   * @return the oprf client config response
   */
  @GET
  @Path("/config")
  @Produces(MediaType.APPLICATION_JSON)
  public OprfClientConfigResponse getConfig() {
    log.trace("getConfig()");
    return clientConfig;
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
  public OprfResponse evaluate(final OprfRequest request, @Context ContainerRequestContext ctx) {
    log.trace("evaluate(requestId={})", request.requestId());
    String clientIp = extractClientIp(ctx);
    if (!rateLimiter.tryConsume(clientIp)) {
      throw new WebApplicationException(Response.status(429)
          .header("Retry-After", "60").entity("Rate limit exceeded").build());
    }
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

  private static String extractClientIp(ContainerRequestContext ctx) {
    String forwarded = ctx.getHeaderString("X-Forwarded-For");
    if (forwarded != null && !forwarded.isBlank()) {
      return forwarded.split(",")[0].trim();
    }
    // Fallback — may not be the true client IP behind a proxy
    return "unknown";
  }
}
