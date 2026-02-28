package com.codeheadsystems.hofmann.springboot.controller;

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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

/**
 * Spring Boot adapter for the OPAQUE-3DH protocol.
 * <p>
 * Delegates all business logic to {@link HofmannOpaqueServerManager} and translates its
 * exception contract into Spring HTTP responses:
 * <ul>
 *   <li>{@link IllegalArgumentException} → 400 Bad Request</li>
 *   <li>{@link SecurityException}        → 401 Unauthorized</li>
 *   <li>{@link IllegalStateException}    → 503 Service Unavailable</li>
 * </ul>
 */
@RestController
@RequestMapping("/opaque")
public class OpaqueController {

  private static final Logger log = LoggerFactory.getLogger(OpaqueController.class);

  private final HofmannOpaqueServerManager manager;
  private final OpaqueClientConfigResponse clientConfig;

  /**
   * Instantiates a new Opaque controller.
   *
   * @param manager      the manager
   * @param clientConfig the client config response to expose via GET /opaque/config
   */
  public OpaqueController(HofmannOpaqueServerManager manager,
                          OpaqueClientConfigResponse clientConfig) {
    this.manager = manager;
    this.clientConfig = clientConfig;
  }

  /**
   * Returns the OPAQUE configuration that clients need to self-configure.
   *
   * @return the opaque client config response
   */
  @GetMapping("/config")
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
  @PostMapping("/registration/start")
  public RegistrationStartResponse registrationStart(@RequestBody RegistrationStartRequest req) {
    log.trace("registrationStart()");
    try {
      return manager.registrationStart(req);
    } catch (IllegalArgumentException e) {
      log.debug("registrationStart bad request: {}", e.getMessage());
      throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid request");
    }
  }

  /**
   * Registration finish response entity.
   *
   * @param req the req
   * @return the response entity
   */
  @PostMapping("/registration/finish")
  public ResponseEntity<Void> registrationFinish(@RequestBody RegistrationFinishRequest req) {
    log.trace("registrationFinish()");
    try {
      manager.registrationFinish(req);
      return ResponseEntity.noContent().build();
    } catch (IllegalArgumentException e) {
      log.debug("registrationFinish bad request: {}", e.getMessage());
      throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid request");
    }
  }

  /**
   * Registration delete response entity.
   *
   * @param req        the req
   * @param authHeader the auth header
   * @return the response entity
   */
  @DeleteMapping("/registration")
  public ResponseEntity<Void> registrationDelete(
      @RequestBody RegistrationDeleteRequest req,
      @RequestHeader(value = "Authorization", required = false) String authHeader) {
    log.trace("registrationDelete()");
    try {
      manager.registrationDelete(req, extractBearerToken(authHeader));
      return ResponseEntity.noContent().build();
    } catch (SecurityException e) {
      log.debug("registrationDelete auth failed: {}", e.getMessage());
      throw new ResponseStatusException(HttpStatus.UNAUTHORIZED);
    } catch (IllegalArgumentException e) {
      log.debug("registrationDelete bad request: {}", e.getMessage());
      throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid request");
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
  @PostMapping("/auth/start")
  public AuthStartResponse authStart(@RequestBody AuthStartRequest req) {
    log.trace("authStart()");
    try {
      return manager.authStart(req);
    } catch (IllegalArgumentException e) {
      log.debug("authStart bad request: {}", e.getMessage());
      throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid request");
    } catch (IllegalStateException e) {
      log.debug("authStart unavailable: {}", e.getMessage());
      throw new ResponseStatusException(HttpStatus.SERVICE_UNAVAILABLE, "Service unavailable");
    }
  }

  /**
   * Auth finish auth finish response.
   *
   * @param req the req
   * @return the auth finish response
   */
  @PostMapping("/auth/finish")
  public AuthFinishResponse authFinish(@RequestBody AuthFinishRequest req) {
    log.trace("authFinish()");
    try {
      return manager.authFinish(req);
    } catch (SecurityException e) {
      log.debug("authFinish failed: {}", e.getMessage());
      throw new ResponseStatusException(HttpStatus.UNAUTHORIZED);
    } catch (IllegalArgumentException e) {
      log.debug("authFinish bad request: {}", e.getMessage());
      throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid request");
    }
  }
}
