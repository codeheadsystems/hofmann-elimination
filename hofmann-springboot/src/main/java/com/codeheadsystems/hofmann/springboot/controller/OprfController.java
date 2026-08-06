package com.codeheadsystems.hofmann.springboot.controller;

import com.codeheadsystems.hofmann.model.oprf.OprfClientConfigResponse;
import com.codeheadsystems.hofmann.model.oprf.OprfRequest;
import com.codeheadsystems.hofmann.model.oprf.OprfResponse;
import com.codeheadsystems.hofmann.server.ratelimit.ClientIpResolver;
import com.codeheadsystems.hofmann.server.ratelimit.RateLimiter;
import com.codeheadsystems.rfc.oprf.manager.OprfServerManager;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
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

  /** Generous upper bound on the hex-encoded EC point (a P-521 uncompressed point is ~267 chars). */
  private static final int MAX_EC_POINT_HEX_LENGTH = 4096;
  /** Generous upper bound on the client-supplied request id. */
  private static final int MAX_REQUEST_ID_LENGTH = 512;

  private final OprfServerManager oprfServerManager;
  private final OprfClientConfigResponse clientConfig;
  private final RateLimiter rateLimiter;
  private final boolean trustForwardedHeaders;

  /**
   * Instantiates a new Oprf controller.
   *
   * @param oprfServerManager     the oprf server manager
   * @param clientConfig          the client config response to expose via GET /oprf/config
   * @param rateLimiter           rate limiter for the OPRF evaluate endpoint (keyed by client IP)
   * @param trustForwardedHeaders when true ({@code hofmann.trust-forwarded-headers}), derive the
   *                              client IP from {@code X-Forwarded-For} (only safe behind a trusted
   *                              proxy that overwrites it); when false (default), use the real
   *                              socket peer address and ignore the spoofable header
   */
  public OprfController(OprfServerManager oprfServerManager,
                        OprfClientConfigResponse clientConfig,
                        @Qualifier("oprfRateLimiter") RateLimiter rateLimiter,
                        @Value("${hofmann.trust-forwarded-headers:false}") boolean trustForwardedHeaders) {
    this.oprfServerManager = oprfServerManager;
    this.clientConfig = clientConfig;
    this.rateLimiter = rateLimiter;
    this.trustForwardedHeaders = trustForwardedHeaders;
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
   * @param request     the request
   * @param httpRequest the http request
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
    if (request.ecPoint().length() > MAX_EC_POINT_HEX_LENGTH) {
      throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Field too large: ecPoint");
    }
    if (request.requestId() == null || request.requestId().isBlank()) {
      throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Missing required field: requestId");
    }
    if (request.requestId().length() > MAX_REQUEST_ID_LENGTH) {
      throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Field too large: requestId");
    }
    try {
      BlindedRequest blindedRequest = request.blindedRequest();
      EvaluatedResponse evaluatedResponse = oprfServerManager.process(blindedRequest);
      return new OprfResponse(evaluatedResponse);
    } catch (IllegalArgumentException e) {
      throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid EC point data");
    }
  }

  /**
   * Resolves the rate-limit key for this request.
   *
   * <p>Delegates to {@link ClientIpResolver} so the OPRF and OPAQUE endpoints, in both
   * frameworks, cannot drift apart on whether to believe {@code X-Forwarded-For} — the one
   * decision that determines whether an origin-keyed limiter is worth anything.
   */
  private String extractClientIp(HttpServletRequest request) {
    return ClientIpResolver.resolve(
        request == null ? null : request.getHeader("X-Forwarded-For"),
        request == null ? null : request.getRemoteAddr(),
        trustForwardedHeaders);
  }
}
