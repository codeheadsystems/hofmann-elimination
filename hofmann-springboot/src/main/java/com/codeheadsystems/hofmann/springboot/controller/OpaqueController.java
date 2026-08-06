package com.codeheadsystems.hofmann.springboot.controller;

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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
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
  private final RateLimiter originRateLimiter;
  private final boolean trustForwardedHeaders;

  /**
   * Instantiates a new Opaque controller.
   *
   * @param manager      the manager
   * @param clientConfig the client config response to expose via GET /opaque/config
   */
  public OpaqueController(HofmannOpaqueServerManager manager,
                          OpaqueClientConfigResponse clientConfig,
                          @Qualifier("opaqueOriginRateLimiter") RateLimiter originRateLimiter,
                          @Value("${hofmann.trust-forwarded-headers:false}")
                          boolean trustForwardedHeaders) {
    this.manager = manager;
    this.clientConfig = clientConfig;
    this.originRateLimiter = originRateLimiter;
    this.trustForwardedHeaders = trustForwardedHeaders;
  }

  /**
   * Bounds how fast a single origin can reach the unauthenticated OPAQUE endpoints.
   * <p>
   * The manager's limiters key on the credential identifier, which bounds attempts against one
   * account but nothing else: every distinct identifier gets a fresh bucket, so an attacker who
   * varies it is unthrottled. That is what lets a flood exhaust the limiter's bucket map and the
   * pending-session store, and denying on either takes service away from everyone. The manager is
   * framework-agnostic and never sees the request, so this dimension can only be added here.
   */
  private void enforceOriginLimit(HttpServletRequest httpRequest) {
    if (originRateLimiter == null) {
      return;
    }
    String origin = ClientIpResolver.resolve(
        httpRequest == null ? null : httpRequest.getHeader("X-Forwarded-For"),
        httpRequest == null ? null : httpRequest.getRemoteAddr(),
        trustForwardedHeaders);
    if (!originRateLimiter.tryConsume(origin)) {
      throw new ResponseStatusException(HttpStatus.TOO_MANY_REQUESTS, "Rate limit exceeded");
    }
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
   * @param req        the req
   * @param authHeader optional Authorization header (recovery token for re-registration)
   * @return the registration start response
   */
  @PostMapping("/registration/start")
  public RegistrationStartResponse registrationStart(
      @RequestBody RegistrationStartRequest req,
      @RequestHeader(value = "Authorization", required = false) String authHeader,
      HttpServletRequest httpRequest) {
    log.trace("registrationStart()");
    enforceOriginLimit(httpRequest);
    try {
      return manager.registrationStart(req, extractBearerToken(authHeader));
    } catch (RateLimitExceededException e) {
      throw new ResponseStatusException(HttpStatus.TOO_MANY_REQUESTS, "Rate limit exceeded");
    } catch (SecurityException e) {
      log.debug("registrationStart auth failed: {}", e.getMessage());
      throw new ResponseStatusException(HttpStatus.UNAUTHORIZED);
    } catch (IllegalArgumentException e) {
      log.debug("registrationStart bad request: {}", e.getMessage());
      throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid request");
    }
  }

  /**
   * Registration finish response entity.
   *
   * @param req        the req
   * @param authHeader optional Authorization header (recovery token for re-registration)
   * @return the response entity
   */
  @PostMapping("/registration/finish")
  public ResponseEntity<Void> registrationFinish(
      @RequestBody RegistrationFinishRequest req,
      @RequestHeader(value = "Authorization", required = false) String authHeader,
      HttpServletRequest httpRequest) {
    log.trace("registrationFinish()");
    enforceOriginLimit(httpRequest);
    try {
      manager.registrationFinish(req, extractBearerToken(authHeader));
      return ResponseEntity.noContent().build();
    } catch (RateLimitExceededException e) {
      throw new ResponseStatusException(HttpStatus.TOO_MANY_REQUESTS, "Rate limit exceeded");
    } catch (SecurityException e) {
      log.debug("registrationFinish auth failed: {}", e.getMessage());
      throw new ResponseStatusException(HttpStatus.UNAUTHORIZED);
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
   * Change password start registration start response.
   *
   * @param req        the req
   * @param authHeader the auth header
   * @return the registration start response
   */
  @PostMapping("/password/start")
  public RegistrationStartResponse changePasswordStart(
      @RequestBody RegistrationStartRequest req,
      @RequestHeader(value = "Authorization", required = false) String authHeader) {
    log.trace("changePasswordStart()");
    try {
      return manager.changePasswordStart(req, extractBearerToken(authHeader));
    } catch (RateLimitExceededException e) {
      throw new ResponseStatusException(HttpStatus.TOO_MANY_REQUESTS, "Rate limit exceeded");
    } catch (SecurityException e) {
      log.debug("changePasswordStart auth failed: {}", e.getMessage());
      throw new ResponseStatusException(HttpStatus.UNAUTHORIZED);
    } catch (IllegalArgumentException e) {
      log.debug("changePasswordStart bad request: {}", e.getMessage());
      throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid request");
    }
  }

  /**
   * Change password finish response entity.
   *
   * @param req        the req
   * @param authHeader the auth header
   * @return the response entity
   */
  @PostMapping("/password/finish")
  public ResponseEntity<Void> changePasswordFinish(
      @RequestBody RegistrationFinishRequest req,
      @RequestHeader(value = "Authorization", required = false) String authHeader) {
    log.trace("changePasswordFinish()");
    try {
      manager.changePasswordFinish(req, extractBearerToken(authHeader));
      return ResponseEntity.noContent().build();
    } catch (SecurityException e) {
      log.debug("changePasswordFinish auth failed: {}", e.getMessage());
      throw new ResponseStatusException(HttpStatus.UNAUTHORIZED);
    } catch (IllegalArgumentException e) {
      log.debug("changePasswordFinish bad request: {}", e.getMessage());
      throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid request");
    }
  }

  /**
   * Recovery start — sends an out-of-band challenge.
   *
   * @param req the recovery start request
   * @return 202 Accepted
   */
  @PostMapping("/recovery/start")
  public ResponseEntity<Void> recoveryStart(@RequestBody RecoveryStartRequest req,
                                            HttpServletRequest httpRequest) {
    log.trace("recoveryStart()");
    enforceOriginLimit(httpRequest);
    try {
      manager.recoveryStart(req);
      return ResponseEntity.accepted().build();
    } catch (UnsupportedOperationException e) {
      throw new ResponseStatusException(HttpStatus.NOT_FOUND);
    } catch (RateLimitExceededException e) {
      throw new ResponseStatusException(HttpStatus.TOO_MANY_REQUESTS, "Rate limit exceeded");
    } catch (IllegalArgumentException e) {
      log.debug("recoveryStart bad request: {}", e.getMessage());
      throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid request");
    }
  }

  /**
   * Recovery verify — verifies the challenge response and returns a recovery token.
   *
   * @param req the recovery verify request
   * @return the recovery verify response containing the recovery token
   */
  @PostMapping("/recovery/verify")
  public RecoveryVerifyResponse recoveryVerify(@RequestBody RecoveryVerifyRequest req,
                                               HttpServletRequest httpRequest) {
    log.trace("recoveryVerify()");
    enforceOriginLimit(httpRequest);
    try {
      return manager.recoveryVerify(req);
    } catch (UnsupportedOperationException e) {
      throw new ResponseStatusException(HttpStatus.NOT_FOUND);
    } catch (SecurityException e) {
      log.debug("recoveryVerify failed: {}", e.getMessage());
      throw new ResponseStatusException(HttpStatus.UNAUTHORIZED);
    } catch (IllegalArgumentException e) {
      log.debug("recoveryVerify bad request: {}", e.getMessage());
      throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid request");
    }
  }

  /**
   * Auth start auth start response.
   *
   * @param req the req
   * @return the auth start response
   */
  @PostMapping("/auth/start")
  public AuthStartResponse authStart(@RequestBody AuthStartRequest req,
                                     HttpServletRequest httpRequest) {
    log.trace("authStart()");
    enforceOriginLimit(httpRequest);
    try {
      return manager.authStart(req);
    } catch (RateLimitExceededException e) {
      throw new ResponseStatusException(HttpStatus.TOO_MANY_REQUESTS, "Rate limit exceeded");
    } catch (SecurityException e) {
      // Group-element validation (deserializePoint / decodeRistretto255) signals malformed
      // input with SecurityException, so without this catch a malformed blindedElement or
      // clientAkePublicKey returns 500 on an unauthenticated endpoint. Mapped to 400 rather
      // than 401 because nothing has been authenticated at this stage — the input is simply
      // not a well-formed group element. Both the registered and unknown-credential paths
      // reach this identically, so it does not distinguish the two.
      log.debug("authStart invalid group element: {}", e.getMessage());
      throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid request");
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
  public AuthFinishResponse authFinish(@RequestBody AuthFinishRequest req,
                                       HttpServletRequest httpRequest) {
    log.trace("authFinish()");
    enforceOriginLimit(httpRequest);
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
