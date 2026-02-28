package com.codeheadsystems.hofmann.server.resource;

import com.codeheadsystems.hofmann.model.opaque.AuthFinishRequest;
import com.codeheadsystems.hofmann.model.opaque.AuthFinishResponse;
import com.codeheadsystems.hofmann.model.opaque.AuthStartRequest;
import com.codeheadsystems.hofmann.model.opaque.AuthStartResponse;
import com.codeheadsystems.hofmann.model.opaque.OpaqueClientConfigResponse;
import com.codeheadsystems.hofmann.model.opaque.RegistrationDeleteRequest;
import com.codeheadsystems.hofmann.model.opaque.RegistrationFinishRequest;
import com.codeheadsystems.hofmann.model.opaque.RegistrationStartRequest;
import com.codeheadsystems.hofmann.model.opaque.RegistrationStartResponse;
import com.codeheadsystems.hofmann.server.manager.HofmannOpaqueServerManager;
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
 *   <li>{@link IllegalArgumentException} → 400 Bad Request</li>
 *   <li>{@link SecurityException}        → 401 Unauthorized</li>
 *   <li>{@link IllegalStateException}    → 503 Service Unavailable</li>
 * </ul>
 */
@Path("/opaque")
@Produces(MediaType.APPLICATION_JSON)
@Consumes(MediaType.APPLICATION_JSON)
public class OpaqueResource {

  private static final Logger log = LoggerFactory.getLogger(OpaqueResource.class);

  private final HofmannOpaqueServerManager manager;
  private final OpaqueClientConfigResponse clientConfig;

  /**
   * Instantiates a new Opaque resource.
   *
   * @param manager      the manager
   * @param clientConfig the client config response to expose via GET /opaque/config
   */
  public OpaqueResource(HofmannOpaqueServerManager manager,
                        OpaqueClientConfigResponse clientConfig) {
    this.manager = manager;
    this.clientConfig = clientConfig;
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
   * @param req the req
   * @return the registration start response
   */
  @POST
  @Path("/registration/start")
  public RegistrationStartResponse registrationStart(RegistrationStartRequest req) {
    log.trace("registrationStart()");
    try {
      return manager.registrationStart(req);
    } catch (IllegalArgumentException e) {
      log.debug("registrationStart bad request: {}", e.getMessage());
      throw new WebApplicationException("Invalid request", Response.Status.BAD_REQUEST);
    }
  }

  /**
   * Registration finish response.
   *
   * @param req the req
   * @return the response
   */
  @POST
  @Path("/registration/finish")
  public Response registrationFinish(RegistrationFinishRequest req) {
    log.trace("registrationFinish()");
    try {
      manager.registrationFinish(req);
      return Response.noContent().build();
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
   * Auth start auth start response.
   *
   * @param req the req
   * @return the auth start response
   */
  @POST
  @Path("/auth/start")
  public AuthStartResponse authStart(AuthStartRequest req) {
    log.trace("authStart()");
    try {
      return manager.authStart(req);
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
   * @param req the req
   * @return the auth finish response
   */
  @POST
  @Path("/auth/finish")
  public AuthFinishResponse authFinish(AuthFinishRequest req) {
    log.trace("authFinish()");
    try {
      return manager.authFinish(req);
    } catch (SecurityException e) {
      log.debug("authFinish failed: {}", e.getMessage());
      throw new WebApplicationException(Response.Status.UNAUTHORIZED);
    } catch (IllegalArgumentException e) {
      log.debug("authFinish bad request: {}", e.getMessage());
      throw new WebApplicationException("Invalid request", Response.Status.BAD_REQUEST);
    }
  }
}
