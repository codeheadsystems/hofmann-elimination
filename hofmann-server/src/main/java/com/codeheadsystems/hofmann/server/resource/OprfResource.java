package com.codeheadsystems.hofmann.server.resource;

import com.codeheadsystems.hofmann.model.oprf.OprfClientConfigResponse;
import com.codeheadsystems.hofmann.model.oprf.OprfRequest;
import com.codeheadsystems.hofmann.model.oprf.OprfResponse;
import com.codeheadsystems.hofmann.server.ratelimit.RateLimitExceededException;
import com.codeheadsystems.hofmann.server.ratelimit.ClientIpResolver;
import com.codeheadsystems.hofmann.server.ratelimit.RateLimiter;
import com.codeheadsystems.rfc.oprf.manager.OprfServerManager;
import com.codeheadsystems.rfc.oprf.model.EvaluatedResponse;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.WebApplicationException;
import jakarta.servlet.http.HttpServletRequest;
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

  /** Generous upper bound on the hex-encoded EC point (a P-521 uncompressed point is ~267 chars). */
  private static final int MAX_EC_POINT_HEX_LENGTH = 4096;
  /** Generous upper bound on the client-supplied request id. */
  private static final int MAX_REQUEST_ID_LENGTH = 512;

  private final OprfServerManager oprfServerManager;
  private final OprfClientConfigResponse clientConfig;
  private final RateLimiter rateLimiter;
  private final boolean trustForwardedHeaders;


  /**
   * Instantiates a new Oprf resource that does not trust forwarded headers
   * (rate limiting is keyed by the real socket peer address).
   *
   * @param oprfServerManager the oprf server manager
   * @param clientConfig      the client config response to expose via GET /oprf/config
   * @param rateLimiter       rate limiter for the OPRF evaluate endpoint (keyed by client IP)
   */
  public OprfResource(final OprfServerManager oprfServerManager,
                      final OprfClientConfigResponse clientConfig,
                      final RateLimiter rateLimiter) {
    this(oprfServerManager, clientConfig, rateLimiter, false);
  }

  /**
   * Instantiates a new Oprf resource.
   *
   * @param oprfServerManager     the oprf server manager
   * @param clientConfig          the client config response to expose via GET /oprf/config
   * @param rateLimiter           rate limiter for the OPRF evaluate endpoint (keyed by client IP)
   * @param trustForwardedHeaders when true, derive the client IP from the {@code X-Forwarded-For}
   *                              header (only safe behind a trusted proxy that overwrites it);
   *                              when false (default), use the real socket peer address and ignore
   *                              the spoofable header
   */
  @Inject
  public OprfResource(final OprfServerManager oprfServerManager,
                      final OprfClientConfigResponse clientConfig,
                      final RateLimiter rateLimiter,
                      final boolean trustForwardedHeaders) {
    this.oprfServerManager = oprfServerManager;
    this.clientConfig = clientConfig;
    this.rateLimiter = rateLimiter;
    this.trustForwardedHeaders = trustForwardedHeaders;
    log.info("OprfResource({}, trustForwardedHeaders={})", oprfServerManager, trustForwardedHeaders);
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
  public OprfResponse evaluate(final OprfRequest request,
                               @Context ContainerRequestContext ctx,
                               @Context HttpServletRequest httpRequest) {
    log.trace("evaluate(requestId={})", request.requestId());
    String clientIp = extractClientIp(ctx, httpRequest);
    if (!rateLimiter.tryConsume(clientIp)) {
      throw new WebApplicationException(Response.status(429)
          .header("Retry-After", "60").entity("Rate limit exceeded").build());
    }
    // Validate inputs before passing to crypto layer to return 400 instead of 500 for bad input
    if (request.ecPoint() == null || request.ecPoint().isBlank()) {
      throw new WebApplicationException("Missing required field: ecPoint", Response.Status.BAD_REQUEST);
    }
    if (request.ecPoint().length() > MAX_EC_POINT_HEX_LENGTH) {
      throw new WebApplicationException("Field too large: ecPoint", Response.Status.BAD_REQUEST);
    }
    if (request.requestId() == null || request.requestId().isBlank()) {
      throw new WebApplicationException("Missing required field: requestId", Response.Status.BAD_REQUEST);
    }
    if (request.requestId().length() > MAX_REQUEST_ID_LENGTH) {
      throw new WebApplicationException("Field too large: requestId", Response.Status.BAD_REQUEST);
    }
    try {
      final EvaluatedResponse evaluatedResponse = oprfServerManager.process(request.blindedRequest());
      return new OprfResponse(evaluatedResponse);
    } catch (IllegalArgumentException e) {
      throw new WebApplicationException("Invalid EC point data", Response.Status.BAD_REQUEST);
    }
  }

  /**
   * Resolves the rate-limit key for this request.
   *
   * <p>The request is threaded in as a method parameter rather than injected into a field:
   * {@code @Context} field injection into this singleton resource silently yields null, which
   * collapses every caller onto one key and turns a per-origin limiter into a single global
   * bucket — capping the whole deployment rather than each client.
   *
   * <p>Delegates to {@link ClientIpResolver} so the OPRF and OPAQUE endpoints cannot drift apart
   * on whether to believe {@code X-Forwarded-For}.
   */
  private String extractClientIp(ContainerRequestContext ctx, HttpServletRequest httpRequest) {
    return ClientIpResolver.resolve(
        ctx == null ? null : ctx.getHeaderString("X-Forwarded-For"),
        httpRequest == null ? null : httpRequest.getRemoteAddr(),
        trustForwardedHeaders);
  }
}
