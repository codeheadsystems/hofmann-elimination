package com.codeheadsystems.rfc.oprf.model;

import java.util.List;

/**
 * The server-to-client message in POPRF mode.
 * <p>
 * Carries neither the server's public key nor its tweaked key. The client derives the tweaked key
 * itself from the public key it already trusts and the {@code info} it chose; accepting the
 * server's version would let the server pick the standard it is judged by, and every response
 * would verify.
 *
 * @param evaluatedPoints   the hex-encoded evaluated elements, aligned with the request
 * @param proof             the hex-encoded DLEQ proof covering the whole batch
 * @param processIdentifier identifies which server key was used
 */
public record PartiallyEvaluatedResponse(List<String> evaluatedPoints,
                                         String proof,
                                         String processIdentifier) {

  /**
   * Rejects an empty response.
   */
  public PartiallyEvaluatedResponse {
    if (evaluatedPoints == null || evaluatedPoints.isEmpty()) {
      throw new IllegalArgumentException("Response must carry at least one evaluated element");
    }
    if (proof == null || proof.isBlank()) {
      throw new IllegalArgumentException("Response must carry a proof");
    }
    evaluatedPoints = List.copyOf(evaluatedPoints);
  }
}
