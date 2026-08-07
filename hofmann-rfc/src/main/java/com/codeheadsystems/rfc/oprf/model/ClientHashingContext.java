package com.codeheadsystems.rfc.oprf.model;

import java.math.BigInteger;

/**
 * Client-side context for hashing: { requestId, blindingFactor, input }.
 *
 * @param requestId      a unique identifier for the request, used to correlate with the server's response
 * @param blindingFactor the random blinding factor used in the OPRF protocol, which should be kept secret and is used to blind the input before sending it to the server
 * @param input          the original input data that the client wants to hash using the OPRF protocol, which will be blinded and sent to the server for processing
 */
public record ClientHashingContext(String requestId, BigInteger blindingFactor, byte[] input) {

  /**
   * Redacts the blinding factor and the input.
   *
   * <p>Same shape as {@link ServerProcessorDetail}: the generated {@code toString} would print
   * {@code blindingFactor} as its full decimal value. Disclosing a blind lets an observer unblind
   * the corresponding evaluated element and recover the OPRF output for that input — and on the
   * OPAQUE path that output is what the envelope keys derive from. {@code input} is redacted too
   * because it is the client's plaintext OPRF input.
   */
  @Override
  public String toString() {
    return "ClientHashingContext[requestId=" + requestId
        + ", blindingFactor=<redacted>, input=<redacted>]";
  }
}
