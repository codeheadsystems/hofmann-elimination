package com.codeheadsystems.hofmann.springboot.controller;

import com.codeheadsystems.hofmann.model.oprf.OprfClientConfigResponse;
import com.codeheadsystems.hofmann.model.oprf.OprfRequest;
import com.codeheadsystems.hofmann.model.oprf.OprfResponse;
import com.codeheadsystems.hofmann.model.oprf.PoprfRequest;
import com.codeheadsystems.hofmann.model.oprf.PoprfResponse;
import com.codeheadsystems.hofmann.model.oprf.VoprfRequest;
import com.codeheadsystems.hofmann.model.oprf.VoprfResponse;
import com.codeheadsystems.hofmann.server.ratelimit.ClientIpResolver;
import com.codeheadsystems.hofmann.server.ratelimit.RateLimiter;
import com.codeheadsystems.hofmann.springboot.config.HofmannProperties;
import com.codeheadsystems.rfc.oprf.manager.OprfServerManager;
import com.codeheadsystems.rfc.oprf.manager.PoprfServerManager;
import com.codeheadsystems.rfc.oprf.manager.VoprfServerManager;
import org.springframework.beans.factory.annotation.Autowired;
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
  private final VoprfServerManager voprfServerManager;
  private final PoprfServerManager poprfServerManager;

  /**
   * Instantiates a new Oprf controller.
   *
   * @param oprfServerManager     the oprf server manager
   * @param clientConfig          the client config response to expose via GET /oprf/config
   * @param rateLimiter           rate limiter for the OPRF evaluate endpoint (keyed by client IP)
   * @param props                 the Hofmann properties; supplies
   *                              {@code hofmann.trust-forwarded-headers}, which when true derives
   *                              the client IP from {@code X-Forwarded-For} — only safe behind a
   *                              trusted proxy that overwrites it. False by default, using the
   *                              real socket peer address and ignoring the spoofable header
   */
  public OprfController(OprfServerManager oprfServerManager,
                        OprfClientConfigResponse clientConfig,
                        @Qualifier("oprfRateLimiter") RateLimiter rateLimiter,
                        HofmannProperties props,
                        @Autowired(required = false) VoprfServerManager voprfServerManager,
                        @Autowired(required = false) PoprfServerManager poprfServerManager) {
    this.oprfServerManager = oprfServerManager;
    this.clientConfig = clientConfig;
    this.rateLimiter = rateLimiter;
    // One source. This used to be an @Value reading the same key, which agreed with
    // HofmannProperties only as long as the value arrived as a property — a consumer
    // overriding the properties bean programmatically would have set a field the
    // controller never read, and silently kept the spoofable-header default.
    this.trustForwardedHeaders = props.isTrustForwardedHeaders();
    // required = false so a base-mode deployment, which has no VOPRF or POPRF key configured,
    // starts normally and answers those endpoints with 404 rather than failing to wire up.
    this.voprfServerManager = voprfServerManager;
    this.poprfServerManager = poprfServerManager;
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
   * Evaluates a batch of blinded elements under the VOPRF key and returns a DLEQ proof
   * (RFC 9497 mode 0x01).
   *
   * @param request     the batched blinded request
   * @param httpRequest the servlet request, used to key the rate limiter
   * @return the evaluated elements and the proof
   */
  @PostMapping("/verifiable")
  public VoprfResponse evaluateVerifiable(@RequestBody VoprfRequest request,
                                          HttpServletRequest httpRequest) {
    requireMode(voprfServerManager, "VOPRF");
    enforceRateLimit(httpRequest);
    try {
      return new VoprfResponse(voprfServerManager.process(request.blindedRequest()));
    } catch (IllegalArgumentException | SecurityException e) {
      // One status and one message for a malformed batch, an element that is not a valid group
      // encoding, and a batch over the configured cap; the two exception types depend on the suite
      // rather than on the fault. Timing still separates them — see the note on the Dropwizard
      // resource — but the batch is attacker-authored, so that reveals nothing they did not send.
      throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid request");
    }
  }

  /**
   * Evaluates a batch of blinded elements under a key tweaked by the public input, and returns a
   * DLEQ proof (RFC 9497 mode 0x02).
   *
   * @param request     the batched partially-blinded request
   * @param httpRequest the servlet request, used to key the rate limiter
   * @return the evaluated elements and the proof
   */
  @PostMapping("/partially-oblivious")
  public PoprfResponse evaluatePartiallyOblivious(@RequestBody PoprfRequest request,
                                                  HttpServletRequest httpRequest) {
    requireMode(poprfServerManager, "POPRF");
    enforceRateLimit(httpRequest);
    try {
      return new PoprfResponse(poprfServerManager.process(request.blindedRequest()));
    } catch (IllegalArgumentException | SecurityException e) {
      throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid request");
    }
  }

  /**
   * 404s a verifiable endpoint on a deployment that has no key for that mode.
   *
   * <p>Not 501: the controller is mapped, but this deployment does not offer the mode, and 404 is
   * what a client probing for capability should see. Enabling the mode later is then purely
   * additive from the client's point of view.
   */
  private void requireMode(Object manager, String mode) {
    if (manager == null) {
      throw new ResponseStatusException(HttpStatus.NOT_FOUND,
          mode + " is not enabled on this server");
    }
  }

  private void enforceRateLimit(HttpServletRequest httpRequest) {
    // Same limiter and key as base mode. A batch costs more than a single evaluation, so if
    // anything this under-charges; the batch cap and the transport size bound are what bound it.
    if (!rateLimiter.tryConsume(extractClientIp(httpRequest))) {
      throw new ResponseStatusException(HttpStatus.TOO_MANY_REQUESTS, "Rate limit exceeded");
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
