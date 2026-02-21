package com.codeheadsystems.hofmann.model.oprf;

import com.codeheadsystems.oprf.model.EvaluatedResponse;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Server's OPRF response: { ecPoint, processIdentifier }.
 *
 * @param ecPoint           A hex-encoded elliptic curve point returned by the server after applying the server process.
 * @param processIdentifier A identifier for the deterministic process used. Provided so the final value can be traced back to the server secret that generated it, Resulting values are unique to the processIdentifier.
 */
public record OprfResponse(@JsonProperty("ecPoint") String ecPoint,
                           @JsonProperty("processIdentifier") String processIdentifier) {

  public OprfResponse(EvaluatedResponse evaluatedResponse) {
    this(evaluatedResponse.evaluatedPoint(), evaluatedResponse.processIdentifier());
  }

  public EvaluatedResponse evaluatedResponse() {
    return new EvaluatedResponse(ecPoint(), processIdentifier());
  }

}
