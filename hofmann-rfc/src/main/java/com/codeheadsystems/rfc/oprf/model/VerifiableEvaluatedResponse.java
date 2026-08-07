package com.codeheadsystems.rfc.oprf.model;

import java.util.List;

/**
 * The server-to-client message in the verifiable modes.
 * <p>
 * Deliberately does <em>not</em> carry the server's public key. The client must grade a proof
 * against a key it obtained and authenticated out of band; a key travelling alongside the proof it
 * authenticates would let a server choose the standard it is judged by, and every response would
 * verify. The {@code processIdentifier} names which key was used so the client can select from its
 * own configured set — which is safe only if every key in that set is independently authenticated.
 *
 * @param evaluatedPoints   the hex-encoded evaluated elements, aligned with the request
 * @param proof             the hex-encoded DLEQ proof covering the whole batch
 * @param processIdentifier identifies which server key was used
 */
public record VerifiableEvaluatedResponse(List<String> evaluatedPoints,
                                          String proof,
                                          String processIdentifier) {

  /**
   * Rejects an empty response.
   */
  public VerifiableEvaluatedResponse {
    if (evaluatedPoints == null || evaluatedPoints.isEmpty()) {
      throw new IllegalArgumentException("Response must carry at least one evaluated element");
    }
    if (proof == null || proof.isBlank()) {
      throw new IllegalArgumentException("Response must carry a proof");
    }
    evaluatedPoints = List.copyOf(evaluatedPoints);
  }
}
