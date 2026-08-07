package com.codeheadsystems.rfc.oprf.model;

import java.util.List;

/**
 * The client-to-server message in the verifiable modes: one or more hex-encoded blinded elements.
 *
 * @param blindedPoints the hex-encoded blinded elements, in request order
 * @param requestId     correlates the request with its response
 */
public record VerifiableBlindedRequest(List<String> blindedPoints, String requestId) {

  /**
   * Rejects an empty request.
   */
  public VerifiableBlindedRequest {
    if (blindedPoints == null || blindedPoints.isEmpty()) {
      throw new IllegalArgumentException("Request must carry at least one blinded element");
    }
    blindedPoints = List.copyOf(blindedPoints);
  }
}
