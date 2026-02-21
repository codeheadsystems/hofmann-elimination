package com.codeheadsystems.hofmann.springboot.controller;

import com.codeheadsystems.hofmann.model.oprf.OprfRequest;
import com.codeheadsystems.hofmann.model.oprf.OprfResponse;
import com.codeheadsystems.oprf.manager.OprfServerManager;
import com.codeheadsystems.oprf.model.BlindedRequest;
import com.codeheadsystems.oprf.model.EvaluatedResponse;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

@RestController
@RequestMapping("/oprf")
public class OprfController {

  private final OprfServerManager oprfServerManager;

  public OprfController(OprfServerManager oprfServerManager) {
    this.oprfServerManager = oprfServerManager;
  }

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
