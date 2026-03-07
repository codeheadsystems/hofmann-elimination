package com.codeheadsystems.hofmann.springboot.controller;

import com.codeheadsystems.hofmann.model.oprf.OprfClientConfigResponse;
import com.codeheadsystems.hofmann.model.oprf.OprfRequest;
import com.codeheadsystems.hofmann.model.oprf.OprfResponse;
import com.codeheadsystems.hofmann.server.ratelimit.RateLimiter;
import com.codeheadsystems.rfc.oprf.manager.OprfServerManager;
import org.springframework.beans.factory.annotation.Qualifier;
import com.codeheadsystems.rfc.oprf.model.BlindedRequest;
import com.codeheadsystems.rfc.oprf.model.EvaluatedResponse;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

/**
 * The type Oprf controller.
 */
@RestController
@RequestMapping("/oprf")
public class OprfController {

  private final OprfServerManager oprfServerManager;
  private final OprfClientConfigResponse clientConfig;
  private final RateLimiter rateLimiter;

  /**
   * Instantiates a new Oprf controller.
   *
   * @param oprfServerManager the oprf server manager
   * @param clientConfig      the client config response to expose via GET /oprf/config
   * @param rateLimiter       rate limiter for the OPRF evaluate endpoint (keyed by client IP)
   */
  public OprfController(OprfServerManager oprfServerManager,
                        OprfClientConfigResponse clientConfig,
                        @Qualifier("oprfRateLimiter") RateLimiter rateLimiter) {
    this.oprfServerManager = oprfServerManager;
    this.clientConfig = clientConfig;
    this.rateLimiter = rateLimiter;
  }

  /**
   * Returns the OPRF configuration that clients need to self-configure.
   *
   * @return the oprf client config response
   */
  @GetMapping("/config")
  public OprfClientConfigResponse getConfig() {
    return clientConfig;
  }

  /**
   * Evaluate oprf response.
   *
   * @param request the request
   * @return the oprf response
   */
  @PostMapping
  public OprfResponse evaluate(@RequestBody OprfRequest request, HttpServletRequest httpRequest) {
    String clientIp = extractClientIp(httpRequest);
    if (!rateLimiter.tryConsume(clientIp)) {
      throw new ResponseStatusException(HttpStatus.TOO_MANY_REQUESTS, "Rate limit exceeded");
    }
    if (request.ecPoint() == null || request.ecPoint().isBlank()) {
      throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Missing required field: ecPoint");
    }
    if (request.requestId() == null || request.requestId().isBlank()) {
      throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Missing required field: requestId");
    }
    try {
      BlindedRequest blindedRequest = request.blindedRequest();
      EvaluatedResponse evaluatedResponse = oprfServerManager.process(blindedRequest);
      return new OprfResponse(evaluatedResponse);
    } catch (IllegalArgumentException e) {
      throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid EC point data");
    }
  }

  private static String extractClientIp(HttpServletRequest request) {
    String forwarded = request.getHeader("X-Forwarded-For");
    if (forwarded != null && !forwarded.isBlank()) {
      return forwarded.split(",")[0].trim();
    }
    return request.getRemoteAddr();
  }
}
