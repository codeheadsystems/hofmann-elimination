package com.codeheadsystems.hofmann.springboot.controller;

import com.codeheadsystems.hofmann.model.oprf.OprfClientConfigResponse;
import com.codeheadsystems.hofmann.model.oprf.OprfRequest;
import com.codeheadsystems.hofmann.model.oprf.OprfResponse;
import com.codeheadsystems.rfc.oprf.manager.OprfServerManager;
import com.codeheadsystems.rfc.oprf.model.BlindedRequest;
import com.codeheadsystems.rfc.oprf.model.EvaluatedResponse;
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

  /**
   * Instantiates a new Oprf controller.
   *
   * @param oprfServerManager the oprf server manager
   * @param clientConfig      the client config response to expose via GET /oprf/config
   */
  public OprfController(OprfServerManager oprfServerManager,
                        OprfClientConfigResponse clientConfig) {
    this.oprfServerManager = oprfServerManager;
    this.clientConfig = clientConfig;
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
  public OprfResponse evaluate(@RequestBody OprfRequest request) {
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
}
