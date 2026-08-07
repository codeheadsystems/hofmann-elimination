package com.codeheadsystems.hofmann.model.oprf;

import com.codeheadsystems.rfc.oprf.model.PartiallyBlindedRequest;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.List;

/**
 * Client's POPRF request (RFC 9497 mode 0x02): a batch of blinded elements, the public input, and
 * a request id.
 *
 * <p>{@code info} is agreed by both parties and separates evaluations: the server evaluates under
 * a key tweaked by it, so the same input under a different public input yields an unrelated
 * output. It is public — it travels in the clear and is covered by the proof — which is what
 * distinguishes POPRF from simply concatenating it onto the private input.
 *
 * @param blindedElements hex-encoded blinded elements, in order
 * @param info            hex-encoded public input; empty string for none
 * @param requestId       correlates the request with its response
 */
public record PoprfRequest(@JsonProperty("blindedElements") List<String> blindedElements,
                           @JsonProperty("info") String info,
                           @JsonProperty("requestId") String requestId) {

  /**
   * Instantiates a new POPRF request from the protocol model.
   *
   * @param request the partially blinded request
   */
  public PoprfRequest(PartiallyBlindedRequest request) {
    this(request.blindedPoints(), request.info(), request.requestId());
  }

  /**
   * Returns the validated protocol model.
   *
   * @return the partially blinded request
   * @throws IllegalArgumentException if the batch, public input, or request id is malformed
   */
  public PartiallyBlindedRequest blindedRequest() {
    OprfWireFields.requireBatch(blindedElements, "blindedElements");
    OprfWireFields.requireInfo(info);
    OprfWireFields.requireRequestId(requestId);
    return new PartiallyBlindedRequest(List.copyOf(blindedElements), info, requestId);
  }
}
