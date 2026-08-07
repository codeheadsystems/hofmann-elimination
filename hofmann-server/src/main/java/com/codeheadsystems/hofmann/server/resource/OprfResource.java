package com.codeheadsystems.hofmann.server.resource;

import com.codeheadsystems.hofmann.model.oprf.OprfClientConfigResponse;
import com.codeheadsystems.hofmann.model.oprf.OprfRequest;
import com.codeheadsystems.hofmann.model.oprf.OprfResponse;
import com.codeheadsystems.hofmann.model.oprf.PoprfRequest;
import com.codeheadsystems.hofmann.model.oprf.PoprfResponse;
import com.codeheadsystems.hofmann.model.oprf.VoprfRequest;
import com.codeheadsystems.hofmann.model.oprf.VoprfResponse;
import com.codeheadsystems.hofmann.server.ratelimit.RateLimitExceededException;
import com.codeheadsystems.hofmann.server.ratelimit.ClientIpResolver;
import com.codeheadsystems.hofmann.server.ratelimit.RateLimiter;
import com.codeheadsystems.rfc.oprf.manager.OprfServerManager;
import com.codeheadsystems.rfc.oprf.manager.PoprfServerManager;
import com.codeheadsystems.rfc.oprf.manager.VoprfServerManager;
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
  private final VoprfServerManager voprfServerManager;
  private final PoprfServerManager poprfServerManager;


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
    this(oprfServerManager, clientConfig, rateLimiter, trustForwardedHeaders, null, null);
  }

  /**
   * Instantiates a new Oprf resource with the verifiable modes enabled.
   *
   * <p>The verifiable managers are nullable, and null is the supported way to run without them:
   * a deployment configured for base mode has no VOPRF or POPRF key, so the endpoints answer 404
   * rather than 500. They are separate managers because RFC 9497 puts the mode byte in every
   * domain-separation tag — one suite cannot serve two modes, and {@code assertMode} refuses to
   * let it try.
   *
   * @param oprfServerManager     the base-mode oprf server manager
   * @param clientConfig          the client config response to expose via GET /oprf/config
   * @param rateLimiter           rate limiter for the OPRF endpoints (keyed by client IP)
   * @param trustForwardedHeaders whether to derive the client IP from {@code X-Forwarded-For}
   * @param voprfServerManager    the VOPRF (mode 0x01) manager, or null if not configured
   * @param poprfServerManager    the POPRF (mode 0x02) manager, or null if not configured
   */
  public OprfResource(final OprfServerManager oprfServerManager,
                      final OprfClientConfigResponse clientConfig,
                      final RateLimiter rateLimiter,
                      final boolean trustForwardedHeaders,
                      final VoprfServerManager voprfServerManager,
                      final PoprfServerManager poprfServerManager) {
    this.oprfServerManager = oprfServerManager;
    this.clientConfig = clientConfig;
    this.rateLimiter = rateLimiter;
    this.trustForwardedHeaders = trustForwardedHeaders;
    this.voprfServerManager = voprfServerManager;
    this.poprfServerManager = poprfServerManager;
    log.info("OprfResource({}, trustForwardedHeaders={}, voprf={}, poprf={})",
        oprfServerManager, trustForwardedHeaders,
        voprfServerManager != null, poprfServerManager != null);
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
   * Evaluates a batch of blinded elements under the VOPRF key and returns a DLEQ proof
   * (RFC 9497 mode 0x01).
   *
   * @param request     the batched blinded request
   * @param ctx         the container request context
   * @param httpRequest the servlet request, used to key the rate limiter
   * @return the evaluated elements and the proof
   */
  @POST
  @Path("/verifiable")
  @Consumes(MediaType.APPLICATION_JSON)
  @Produces(MediaType.APPLICATION_JSON)
  public VoprfResponse evaluateVerifiable(final VoprfRequest request,
                                          @Context ContainerRequestContext ctx,
                                          @Context HttpServletRequest httpRequest) {
    log.trace("evaluateVerifiable()");
    requireMode(voprfServerManager, "VOPRF");
    enforceRateLimit(ctx, httpRequest);
    try {
      return new VoprfResponse(voprfServerManager.process(request.blindedRequest()));
    } catch (IllegalArgumentException e) {
      // Covers a malformed batch, an element that is not a valid group encoding, and a batch over
      // the configured cap. All are the caller's fault and none should distinguish itself: the
      // element-level failures in particular must not tell an attacker which element was bad.
      log.debug("verifiable evaluate bad request: {}", e.getMessage());
      throw new WebApplicationException("Invalid request", Response.Status.BAD_REQUEST);
    } catch (SecurityException e) {
      log.debug("verifiable evaluate rejected element: {}", e.getMessage());
      throw new WebApplicationException("Invalid request", Response.Status.BAD_REQUEST);
    }
  }

  /**
   * Evaluates a batch of blinded elements under a key tweaked by the public input, and returns a
   * DLEQ proof (RFC 9497 mode 0x02).
   *
   * @param request     the batched partially-blinded request
   * @param ctx         the container request context
   * @param httpRequest the servlet request, used to key the rate limiter
   * @return the evaluated elements and the proof
   */
  @POST
  @Path("/partially-oblivious")
  @Consumes(MediaType.APPLICATION_JSON)
  @Produces(MediaType.APPLICATION_JSON)
  public PoprfResponse evaluatePartiallyOblivious(final PoprfRequest request,
                                                  @Context ContainerRequestContext ctx,
                                                  @Context HttpServletRequest httpRequest) {
    log.trace("evaluatePartiallyOblivious()");
    requireMode(poprfServerManager, "POPRF");
    enforceRateLimit(ctx, httpRequest);
    try {
      return new PoprfResponse(poprfServerManager.process(request.blindedRequest()));
    } catch (IllegalArgumentException e) {
      log.debug("poprf evaluate bad request: {}", e.getMessage());
      throw new WebApplicationException("Invalid request", Response.Status.BAD_REQUEST);
    } catch (SecurityException e) {
      log.debug("poprf evaluate rejected element: {}", e.getMessage());
      throw new WebApplicationException("Invalid request", Response.Status.BAD_REQUEST);
    }
  }

  /**
   * 404s a verifiable endpoint on a deployment that has no key for that mode.
   *
   * <p>Not 501: the resource is mounted, but this deployment does not offer the mode, and 404 is
   * what a client probing for capability should see. It also means enabling the mode later is
   * purely additive from the client's point of view.
   */
  private void requireMode(final Object manager, final String mode) {
    if (manager == null) {
      log.debug("{} endpoint called but no {} manager is configured", mode, mode);
      throw new WebApplicationException(mode + " is not enabled on this server",
          Response.Status.NOT_FOUND);
    }
  }

  private void enforceRateLimit(final ContainerRequestContext ctx,
                                final HttpServletRequest httpRequest) {
    // Same limiter and the same key as base mode. A batch costs more than a single evaluation, so
    // if anything this under-charges — the batch cap and the transport size bound are what keep
    // that bounded, not the limiter.
    if (!rateLimiter.tryConsume(extractClientIp(ctx, httpRequest))) {
      throw new WebApplicationException(Response.status(429)
          .header("Retry-After", "60").entity("Rate limit exceeded").build());
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
