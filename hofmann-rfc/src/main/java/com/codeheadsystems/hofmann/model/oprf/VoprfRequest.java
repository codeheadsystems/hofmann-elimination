package com.codeheadsystems.hofmann.model.oprf;

import com.codeheadsystems.rfc.oprf.model.VerifiableBlindedRequest;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.List;

/**
 * Client's VOPRF request (RFC 9497 mode 0x01): a batch of blinded elements and a request id.
 *
 * <p>A batch rather than a single element because one DLEQ proof covers the whole batch: the
 * server proves once that every evaluation used the same committed key. Sending elements one at a
 * time would cost a proof per element and prove strictly less.
 *
 * @param blindedElements hex-encoded blinded elements, in order
 * @param requestId       correlates the request with its response
 */
public record VoprfRequest(@JsonProperty("blindedElements") List<String> blindedElements,
                           @JsonProperty("requestId") String requestId) {

  /**
   * Instantiates a new VOPRF request from the protocol model.
   *
   * @param request the verifiable blinded request
   */
  public VoprfRequest(VerifiableBlindedRequest request) {
    this(request.blindedPoints(), request.requestId());
  }

  /**
   * Returns the validated protocol model.
   *
   * <p>Validation lives here rather than in the resource so both adapters get it, and so the
   * element-count check runs before the batch reaches the crypto layer. The batch cap itself is
   * enforced by the manager, which owns the configured value; this only rejects what is
   * structurally unusable.
   *
   * @return the verifiable blinded request
   * @throws IllegalArgumentException if the batch or the request id is missing or malformed
   */
  public VerifiableBlindedRequest blindedRequest() {
    OprfWireFields.requireBatch(blindedElements, "blindedElements");
    OprfWireFields.requireRequestId(requestId);
    return new VerifiableBlindedRequest(List.copyOf(blindedElements), requestId);
  }
}
