package com.codeheadsystems.hofmann.springboot.controller;

import com.codeheadsystems.hofmann.model.oprf.OprfRequest;
import com.codeheadsystems.hofmann.model.oprf.OprfResponse;
import com.codeheadsystems.hofmann.server.manager.OprfManager;
import com.codeheadsystems.ellipticcurve.rfc9380.WeierstrassGroupSpecImpl;
import org.bouncycastle.math.ec.ECPoint;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

@RestController
@RequestMapping("/oprf")
public class OprfController {

  private final OprfManager oprfManager;
  private final WeierstrassGroupSpecImpl groupSpec;

  public OprfController(OprfManager oprfManager, WeierstrassGroupSpecImpl groupSpec) {
    this.oprfManager = oprfManager;
    this.groupSpec = groupSpec;
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
      ECPoint blindedPoint = groupSpec.toEcPoint(request.ecPoint());
      OprfManager.EvaluationResult result = oprfManager.evaluate(request.requestId(), blindedPoint);
      return new OprfResponse(groupSpec.toHex(result.evaluatedPoint()), result.processIdentifier());
    } catch (IllegalArgumentException e) {
      throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid EC point data");
    }
  }
}
