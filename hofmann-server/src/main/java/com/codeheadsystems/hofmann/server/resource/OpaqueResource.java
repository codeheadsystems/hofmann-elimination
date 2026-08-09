package com.codeheadsystems.hofmann.server.resource;

import com.codeheadsystems.hofmann.model.opaque.AuthFinishRequest;
import com.codeheadsystems.hofmann.model.opaque.AuthFinishResponse;
import com.codeheadsystems.hofmann.model.opaque.AuthStartRequest;
import com.codeheadsystems.hofmann.model.opaque.AuthStartResponse;
import com.codeheadsystems.hofmann.model.opaque.OpaqueClientConfigResponse;
import com.codeheadsystems.hofmann.model.opaque.RecoveryStartRequest;
import com.codeheadsystems.hofmann.model.opaque.RecoveryVerifyRequest;
import com.codeheadsystems.hofmann.model.opaque.RecoveryVerifyResponse;
import com.codeheadsystems.hofmann.model.opaque.RegistrationDeleteRequest;
import com.codeheadsystems.hofmann.model.opaque.RegistrationFinishRequest;
import com.codeheadsystems.hofmann.model.opaque.RegistrationStartRequest;
import com.codeheadsystems.hofmann.model.opaque.RegistrationStartResponse;
import com.codeheadsystems.hofmann.server.manager.HofmannOpaqueServerManager;
import com.codeheadsystems.hofmann.server.ratelimit.ClientIpResolver;
import com.codeheadsystems.hofmann.server.ratelimit.RateLimitExceededException;
import com.codeheadsystems.hofmann.server.ratelimit.RateLimiter;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.DELETE;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.HeaderParam;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.WebApplicationException;
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * JAX-RS adapter for the OPAQUE-3DH protocol.
 * <p>
 * Delegates all business logic to {@link HofmannOpaqueServerManager} and translates its
 * exception contract into JAX-RS HTTP responses:
 * <ul>
 *   <li>{@link IllegalArgumentException}      → 400 Bad Request</li>
 *   <li>{@link SecurityException}             → 401 Unauthorized</li>
 *   <li>{@link UnsupportedOperationException} → 404 Not Found</li>
 *   <li>{@link RateLimitExceededException}    → 429 Too Many Requests</li>
 *   <li>{@link IllegalStateException}         → 503 Service Unavailable</li>
 * </ul>
 *
 * <p>This list must stay in step with the one on {@link HofmannOpaqueServerManager}, which is the
 * authority. It fell two rows behind — this class caught and mapped both missing types, but said
 * it did not, and the manager's javadoc warns that an adapter written against an incomplete list
 * returns 500 under load for a condition that should be a 429. A third adapter is written from
 * this list, so a gap here reproduces the bug rather than merely describing it.
 */
@Path("/opaque")
@Produces(MediaType.APPLICATION_JSON)
@Consumes(MediaType.APPLICATION_JSON)
public class OpaqueResource {

  private static final Logger log = LoggerFactory.getLogger(OpaqueResource.class);

  private final HofmannOpaqueServerManager manager;
  private final OpaqueClientConfigResponse clientConfig;
  private final RateLimiter ipRateLimiter;
  private final boolean trustForwardedHeaders;

  /**
   * Instantiates a new Opaque resource with no origin-based rate limiting.
   *
   * @param manager      the manager
   * @param clientConfig the client config response to expose via GET /opaque/config
   */
  public OpaqueResource(HofmannOpaqueServerManager manager,
                        OpaqueClientConfigResponse clientConfig) {
    this(manager, clientConfig, null, false);
  }

  /**
   * Instantiates a new Opaque resource with an origin-keyed rate limiter.
   *
   * @param manager               the manager
   * @param clientConfig          the client config response to expose via GET /opaque/config
   * @param ipRateLimiter         limiter keyed by request origin, or null to disable
   * @param trustForwardedHeaders whether to believe X-Forwarded-For (only behind a trusted proxy)
   */
  public OpaqueResource(HofmannOpaqueServerManager manager,
                        OpaqueClientConfigResponse clientConfig,
                        RateLimiter ipRateLimiter,
                        boolean trustForwardedHeaders) {
    this.manager = manager;
    this.clientConfig = clientConfig;
    this.ipRateLimiter = ipRateLimiter;
    this.trustForwardedHeaders = trustForwardedHeaders;
  }

  /**
   * Bounds how fast a single origin can reach the unauthenticated OPAQUE endpoints.
   * <p>
   * The manager's limiters are keyed by credential identifier, which bounds attempts against one
   * account but nothing else: every distinct identifier gets a fresh bucket, so an attacker who
   * varies it is unthrottled. That is what lets a flood exhaust the limiter's bucket map and the
   * pending-session store, and denying on either exhausts service for everyone. The manager is
   * framework-agnostic and never sees the request, so this dimension can only be added here.
   * <p>
   * Applied to the unauthenticated entry points only. The authenticated ones already require a
   * JWT whose subject must match, which bounds them by account.
   */
  private void enforceOriginLimit(final HttpServletRequest httpRequest) {
    if (ipRateLimiter == null) {
      return;
    }
    // The request MUST arrive as a method parameter. @Context field injection into this
    // singleton resource silently yields null, which collapses every caller onto the single
    // "unknown" key — turning a per-origin limiter into one global bucket that any single
    // client can drain to deny the whole deployment. That is strictly worse than no limiter,
    // so the request is threaded explicitly rather than injected.
    String origin = ClientIpResolver.resolve(
        httpRequest == null ? null : httpRequest.getHeader("X-Forwarded-For"),
        httpRequest == null ? null : httpRequest.getRemoteAddr(),
        trustForwardedHeaders);
    if (!ipRateLimiter.tryConsume(origin)) {
      throw new WebApplicationException(Response.status(429)
          .header("Retry-After", "60").entity("Rate limit exceeded").build());
    }
  }

  /**
   * Returns the OPAQUE configuration that clients need to self-configure.
   *
   * @return the opaque client config response
   */
  @GET
  @Path("/config")
  public OpaqueClientConfigResponse getConfig() {
    log.trace("getConfig()");
    return clientConfig;
  }

  /**
   * Registration start registration start response.
   *
   * @param req         the registration start request
   * @param authHeader  optional Authorization header (recovery token for re-registration)
   * @param httpRequest the injected servlet request; used only to resolve the origin rate-limit
   *                    key. Tolerates null, which keys every caller alike — see
   *                    {@code enforceOriginLimit} for why it is a parameter and not a field
   * @return the registration start response
   */
  @POST
  @Path("/registration/start")
  public RegistrationStartResponse registrationStart(RegistrationStartRequest req,
                                                     @HeaderParam(HttpHeaders.AUTHORIZATION) String authHeader,
                                                     @Context HttpServletRequest httpRequest) {
    log.trace("registrationStart()");
    enforceOriginLimit(httpRequest);
    try {
      return manager.registrationStart(req, extractBearerToken(authHeader));
    } catch (RateLimitExceededException e) {
      throw new WebApplicationException(Response.status(429)
          .header("Retry-After", "60").entity("Rate limit exceeded").build());
    } catch (SecurityException e) {
      log.debug("registrationStart auth failed: {}", e.getMessage());
      throw new WebApplicationException(Response.Status.UNAUTHORIZED);
    } catch (IllegalArgumentException e) {
      log.debug("registrationStart bad request: {}", e.getMessage());
      throw new WebApplicationException("Invalid request", Response.Status.BAD_REQUEST);
    }
  }

  /**
   * Registration finish response.
   *
   * @param req         the registration finish request
   * @param authHeader  optional Authorization header (recovery token for re-registration)
   * @param httpRequest the injected servlet request; used only to resolve the origin rate-limit
   *                    key. Tolerates null, which keys every caller alike — see
   *                    {@code enforceOriginLimit} for why it is a parameter and not a field
   * @return the response
   */
  @POST
  @Path("/registration/finish")
  public Response registrationFinish(RegistrationFinishRequest req,
                                     @HeaderParam(HttpHeaders.AUTHORIZATION) String authHeader,
                                     @Context HttpServletRequest httpRequest) {
    log.trace("registrationFinish()");
    enforceOriginLimit(httpRequest);
    try {
      manager.registrationFinish(req, extractBearerToken(authHeader));
      return Response.noContent().build();
    } catch (RateLimitExceededException e) {
      throw new WebApplicationException(Response.status(429)
          .header("Retry-After", "60").entity("Rate limit exceeded").build());
    } catch (SecurityException e) {
      log.debug("registrationFinish auth failed: {}", e.getMessage());
      throw new WebApplicationException(Response.Status.UNAUTHORIZED);
    } catch (IllegalArgumentException e) {
      log.debug("registrationFinish bad request: {}", e.getMessage());
      throw new WebApplicationException("Invalid request", Response.Status.BAD_REQUEST);
    }
  }

  /**
   * Registration delete response.
   *
   * @param req        the req
   * @param authHeader the auth header
   * @return the response
   */
  @DELETE
  @Path("/registration")
  public Response registrationDelete(RegistrationDeleteRequest req,
                                     @HeaderParam(HttpHeaders.AUTHORIZATION) String authHeader) {
    log.trace("registrationDelete()");
    try {
      manager.registrationDelete(req, extractBearerToken(authHeader));
      return Response.noContent().build();
    } catch (SecurityException e) {
      log.debug("registrationDelete auth failed: {}", e.getMessage());
      throw new WebApplicationException(Response.Status.UNAUTHORIZED);
    } catch (IllegalArgumentException e) {
      log.debug("registrationDelete bad request: {}", e.getMessage());
      throw new WebApplicationException("Invalid request", Response.Status.BAD_REQUEST);
    }
  }

  private static String extractBearerToken(String authHeader) {
    if (authHeader != null && authHeader.startsWith("Bearer ")) {
      return authHeader.substring(7);
    }
    return null;
  }

  /**
   * Change password start registration start response.
   *
   * @param req        the req
   * @param authHeader the auth header
   * @return the registration start response
   */
  @POST
  @Path("/password/start")
  public RegistrationStartResponse changePasswordStart(RegistrationStartRequest req,
                                                       @HeaderParam(HttpHeaders.AUTHORIZATION) String authHeader) {
    log.trace("changePasswordStart()");
    try {
      return manager.changePasswordStart(req, extractBearerToken(authHeader));
    } catch (RateLimitExceededException e) {
      throw new WebApplicationException(Response.status(429)
          .header("Retry-After", "60").entity("Rate limit exceeded").build());
    } catch (SecurityException e) {
      log.debug("changePasswordStart auth failed: {}", e.getMessage());
      throw new WebApplicationException(Response.Status.UNAUTHORIZED);
    } catch (IllegalArgumentException e) {
      log.debug("changePasswordStart bad request: {}", e.getMessage());
      throw new WebApplicationException("Invalid request", Response.Status.BAD_REQUEST);
    }
  }

  /**
   * Change password finish response.
   *
   * @param req        the req
   * @param authHeader the auth header
   * @return the response
   */
  @POST
  @Path("/password/finish")
  public Response changePasswordFinish(RegistrationFinishRequest req,
                                       @HeaderParam(HttpHeaders.AUTHORIZATION) String authHeader) {
    log.trace("changePasswordFinish()");
    try {
      manager.changePasswordFinish(req, extractBearerToken(authHeader));
      return Response.noContent().build();
    } catch (SecurityException e) {
      log.debug("changePasswordFinish auth failed: {}", e.getMessage());
      throw new WebApplicationException(Response.Status.UNAUTHORIZED);
    } catch (IllegalArgumentException e) {
      log.debug("changePasswordFinish bad request: {}", e.getMessage());
      throw new WebApplicationException("Invalid request", Response.Status.BAD_REQUEST);
    }
  }

  /**
   * Recovery start — sends an out-of-band challenge.
   *
   * @param req         the recovery start request
   * @param httpRequest the injected servlet request; used only to resolve the origin rate-limit
   *                    key. Tolerates null, which keys every caller alike — see
   *                    {@code enforceOriginLimit} for why it is a parameter and not a field
   * @return 202 Accepted
   */
  @POST
  @Path("/recovery/start")
  public Response recoveryStart(RecoveryStartRequest req,
                                @Context HttpServletRequest httpRequest) {
    log.trace("recoveryStart()");
    enforceOriginLimit(httpRequest);
    try {
      manager.recoveryStart(req);
      return Response.accepted().build();
    } catch (UnsupportedOperationException e) {
      throw new WebApplicationException(Response.Status.NOT_FOUND);
    } catch (RateLimitExceededException e) {
      throw new WebApplicationException(Response.status(429)
          .header("Retry-After", "60").entity("Rate limit exceeded").build());
    } catch (IllegalArgumentException e) {
      log.debug("recoveryStart bad request: {}", e.getMessage());
      throw new WebApplicationException("Invalid request", Response.Status.BAD_REQUEST);
    }
  }

  /**
   * Recovery verify — verifies the challenge response and returns a recovery token.
   *
   * @param req         the recovery verify request
   * @param httpRequest the injected servlet request; used only to resolve the origin rate-limit
   *                    key. Tolerates null, which keys every caller alike — see
   *                    {@code enforceOriginLimit} for why it is a parameter and not a field
   * @return the recovery verify response containing the recovery token
   */
  @POST
  @Path("/recovery/verify")
  public RecoveryVerifyResponse recoveryVerify(RecoveryVerifyRequest req,
                                               @Context HttpServletRequest httpRequest) {
    log.trace("recoveryVerify()");
    enforceOriginLimit(httpRequest);
    try {
      return manager.recoveryVerify(req);
    } catch (UnsupportedOperationException e) {
      throw new WebApplicationException(Response.Status.NOT_FOUND);
    } catch (SecurityException e) {
      log.debug("recoveryVerify failed: {}", e.getMessage());
      throw new WebApplicationException(Response.Status.UNAUTHORIZED);
    } catch (IllegalArgumentException e) {
      log.debug("recoveryVerify bad request: {}", e.getMessage());
      throw new WebApplicationException("Invalid request", Response.Status.BAD_REQUEST);
    }
  }

  /**
   * Auth start auth start response.
   *
   * @param req         the auth start request
   * @param httpRequest the injected servlet request; used only to resolve the origin rate-limit
   *                    key. Tolerates null, which keys every caller alike — see
   *                    {@code enforceOriginLimit} for why it is a parameter and not a field
   * @return the auth start response
   */
  @POST
  @Path("/auth/start")
  public AuthStartResponse authStart(AuthStartRequest req,
                                     @Context HttpServletRequest httpRequest) {
    log.trace("authStart()");
    enforceOriginLimit(httpRequest);
    try {
      return manager.authStart(req);
    } catch (RateLimitExceededException e) {
      throw new WebApplicationException(Response.status(429)
          .header("Retry-After", "60").entity("Rate limit exceeded").build());
    } catch (SecurityException e) {
      // Group-element validation (deserializePoint / decodeRistretto255) signals malformed
      // input with SecurityException, so without this catch a malformed blindedElement or
      // clientAkePublicKey returns 500 on an unauthenticated endpoint. Mapped to 400 rather
      // than 401 because nothing has been authenticated at this stage — the input is simply
      // not a well-formed group element. Both the registered and unknown-credential paths
      // reach this identically, so it does not distinguish the two.
      log.debug("authStart invalid group element: {}", e.getMessage());
      throw new WebApplicationException("Invalid request", Response.Status.BAD_REQUEST);
    } catch (IllegalArgumentException e) {
      log.debug("authStart bad request: {}", e.getMessage());
      throw new WebApplicationException("Invalid request", Response.Status.BAD_REQUEST);
    } catch (IllegalStateException e) {
      log.debug("authStart unavailable: {}", e.getMessage());
      throw new WebApplicationException("Service unavailable", Response.Status.SERVICE_UNAVAILABLE);
    }
  }

  /**
   * Auth finish auth finish response.
   *
   * @param req         the auth finish request
   * @param httpRequest the injected servlet request; used only to resolve the origin rate-limit
   *                    key. Tolerates null, which keys every caller alike — see
   *                    {@code enforceOriginLimit} for why it is a parameter and not a field
   * @return the auth finish response
   */
  @POST
  @Path("/auth/finish")
  public AuthFinishResponse authFinish(AuthFinishRequest req,
                                       @Context HttpServletRequest httpRequest) {
    log.trace("authFinish()");
    enforceOriginLimit(httpRequest);
    try {
      return manager.authFinish(req);
    } catch (SecurityException e) {
      log.debug("authFinish failed: {}", e.getMessage());
      throw new WebApplicationException(Response.Status.UNAUTHORIZED);
    } catch (IllegalArgumentException e) {
      log.debug("authFinish bad request: {}", e.getMessage());
      throw new WebApplicationException("Invalid request", Response.Status.BAD_REQUEST);
    } catch (IllegalStateException e) {
      // The session store is now capacity-bounded, so issuing a token can be refused — which
      // happens here, after a handshake the client completed correctly. That is a 503 (the
      // server is out of room, try again), not a 500, and matches how authStart already answers
      // the pending-session store hitting its own cap.
      log.debug("authFinish unavailable: {}", e.getMessage());
      throw new WebApplicationException("Service unavailable", Response.Status.SERVICE_UNAVAILABLE);
    }
  }
}
