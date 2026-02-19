package com.codeheadsystems.hofmann.springboot.controller;

import com.codeheadsystems.hofmann.model.oprf.OprfRequest;
import com.codeheadsystems.hofmann.model.oprf.OprfResponse;
import com.codeheadsystems.hofmann.server.manager.OprfManager;
import com.codeheadsystems.ellipticcurve.curve.Curve;
import com.codeheadsystems.ellipticcurve.curve.OctetStringUtils;
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
  private final Curve curve;

  public OprfController(OprfManager oprfManager, Curve curve) {
    this.oprfManager = oprfManager;
    this.curve = curve;
  }

  @PostMapping
  public OprfResponse evaluate(@RequestBody OprfRequest request) {
    if (request.hexCodedEcPoint() == null || request.hexCodedEcPoint().isBlank()) {
      throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Missing required field: ecPoint");
    }
    if (request.requestId() == null || request.requestId().isBlank()) {
      throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Missing required field: requestId");
    }
    try {
      ECPoint blindedPoint = OctetStringUtils.toEcPoint(curve, request.hexCodedEcPoint());
      OprfManager.EvaluationResult result = oprfManager.evaluate(request.requestId(), blindedPoint);
      return new OprfResponse(OctetStringUtils.toHex(result.evaluatedPoint()), result.processIdentifier());
    } catch (IllegalArgumentException e) {
      throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid EC point data");
    }
  }
}
