package com.codeheadsystems.hofmann.model.oprf;

import com.codeheadsystems.rfc.oprf.model.PartiallyEvaluatedResponse;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.List;

/**
 * Server's POPRF response (RFC 9497 mode 0x02): the evaluated elements and one DLEQ proof.
 *
 * <p>The proof is graded against the <em>tweaked</em> key the client derives from the public input
 * it asked for, not against the server's raw public key. That is what binds the response to this
 * particular {@code info}: a server evaluating under a different public input produces a proof
 * against a different tweaked key, and verification fails.
 *
 * @param evaluatedElements hex-encoded evaluated elements, aligned with the request
 * @param proof             hex-encoded DLEQ proof over the whole batch
 * @param processIdentifier identifies the server key the proof is graded against
 */
public record PoprfResponse(@JsonProperty("evaluatedElements") List<String> evaluatedElements,
                            @JsonProperty("proof") String proof,
                            @JsonProperty("processIdentifier") String processIdentifier) {

  /**
   * Instantiates a new POPRF response from the protocol model.
   *
   * @param response the partially evaluated response
   */
  public PoprfResponse(PartiallyEvaluatedResponse response) {
    this(response.evaluatedPoints(), response.proof(), response.processIdentifier());
  }

  /**
   * Returns the protocol model.
   *
   * @return the partially evaluated response
   */
  public PartiallyEvaluatedResponse evaluatedResponse() {
    return new PartiallyEvaluatedResponse(evaluatedElements, proof, processIdentifier);
  }
}
