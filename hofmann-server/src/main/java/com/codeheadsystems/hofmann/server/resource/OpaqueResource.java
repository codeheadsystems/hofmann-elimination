package com.codeheadsystems.hofmann.server.resource;

import com.codeheadsystems.hofmann.model.opaque.AuthFinishRequest;
import com.codeheadsystems.hofmann.model.opaque.AuthFinishResponse;
import com.codeheadsystems.hofmann.model.opaque.AuthStartRequest;
import com.codeheadsystems.hofmann.model.opaque.AuthStartResponse;
import com.codeheadsystems.hofmann.model.opaque.RegistrationDeleteRequest;
import com.codeheadsystems.hofmann.model.opaque.RegistrationFinishRequest;
import com.codeheadsystems.hofmann.model.opaque.RegistrationStartRequest;
import com.codeheadsystems.hofmann.model.opaque.RegistrationStartResponse;
import com.codeheadsystems.hofmann.server.manager.HofmannOpaqueServerManager;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.DELETE;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.WebApplicationException;
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

  public OpaqueResource(HofmannOpaqueServerManager manager) {
    this.manager = manager;
  }

  @POST
  @Path("/registration/start")
  public RegistrationStartResponse registrationStart(RegistrationStartRequest req) {
    log.trace("registrationStart()");
    try {
      return manager.registrationStart(req);
    } catch (IllegalArgumentException e) {
      throw new WebApplicationException(e.getMessage(), Response.Status.BAD_REQUEST);
    }
  }

  @POST
  @Path("/registration/finish")
  public Response registrationFinish(RegistrationFinishRequest req) {
    log.trace("registrationFinish()");
    try {
      manager.registrationFinish(req);
      return Response.noContent().build();
    } catch (IllegalArgumentException e) {
      throw new WebApplicationException(e.getMessage(), Response.Status.BAD_REQUEST);
    }
  }

  @DELETE
  @Path("/registration")
  public Response registrationDelete(RegistrationDeleteRequest req) {
    log.trace("registrationDelete()");
    try {
      manager.registrationDelete(req);
      return Response.noContent().build();
    } catch (IllegalArgumentException e) {
      throw new WebApplicationException(e.getMessage(), Response.Status.BAD_REQUEST);
    }
  }

  @POST
  @Path("/auth/start")
  public AuthStartResponse authStart(AuthStartRequest req) {
    log.trace("authStart()");
    try {
      return manager.authStart(req);
    } catch (IllegalArgumentException e) {
      throw new WebApplicationException(e.getMessage(), Response.Status.BAD_REQUEST);
    } catch (IllegalStateException e) {
      throw new WebApplicationException(e.getMessage(), Response.Status.SERVICE_UNAVAILABLE);
    }
  }

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
      throw new WebApplicationException(e.getMessage(), Response.Status.BAD_REQUEST);
    }
  }
}
