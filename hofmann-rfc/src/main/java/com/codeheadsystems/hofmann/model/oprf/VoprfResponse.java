package com.codeheadsystems.hofmann.model.oprf;

import com.codeheadsystems.rfc.oprf.model.VerifiableEvaluatedResponse;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.List;

/**
 * Server's VOPRF response (RFC 9497 mode 0x01): the evaluated elements and one DLEQ proof.
 *
 * <p>The proof covers the whole batch and is what makes the mode verifiable — without checking it
 * the client has a base-mode OPRF with extra bytes. {@code processIdentifier} names the key the
 * proof is against, so a client that pins a public key can tell it is talking to the key it
 * expects rather than merely to a self-consistent server.
 *
 * @param evaluatedElements hex-encoded evaluated elements, aligned with the request
 * @param proof             hex-encoded DLEQ proof over the whole batch
 * @param processIdentifier identifies the server key the proof is graded against
 */
public record VoprfResponse(@JsonProperty("evaluatedElements") List<String> evaluatedElements,
                            @JsonProperty("proof") String proof,
                            @JsonProperty("processIdentifier") String processIdentifier) {

  /**
   * Instantiates a new VOPRF response from the protocol model.
   *
   * @param response the verifiable evaluated response
   */
  public VoprfResponse(VerifiableEvaluatedResponse response) {
    this(response.evaluatedPoints(), response.proof(), response.processIdentifier());
  }

  /**
   * Returns the protocol model.
   *
   * @return the verifiable evaluated response
   */
  public VerifiableEvaluatedResponse evaluatedResponse() {
    return new VerifiableEvaluatedResponse(evaluatedElements, proof, processIdentifier);
  }
}
