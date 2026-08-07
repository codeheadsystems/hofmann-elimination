package com.codeheadsystems.rfc.oprf.model;

import java.util.List;

/**
 * The client-to-server message in POPRF mode.
 * <p>
 * The public input travels in the clear, which is what "partially oblivious" means: the server
 * learns {@code info} and nothing about the inputs. Callers should not put anything
 * confidentiality-sensitive in it.
 *
 * @param blindedPoints the hex-encoded blinded elements, in request order
 * @param info          the hex-encoded public input
 * @param requestId     correlates the request with its response
 */
public record PartiallyBlindedRequest(List<String> blindedPoints, String info, String requestId) {

  /**
   * Rejects an empty request.
   */
  public PartiallyBlindedRequest {
    if (blindedPoints == null || blindedPoints.isEmpty()) {
      throw new IllegalArgumentException("Request must carry at least one blinded element");
    }
    if (info == null) {
      throw new IllegalArgumentException("Public input is required; use an empty string for none");
    }
    blindedPoints = List.copyOf(blindedPoints);
  }
}
