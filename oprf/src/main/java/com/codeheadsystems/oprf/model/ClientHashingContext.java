package com.codeheadsystems.oprf.model;

import java.math.BigInteger;

/**
 * Client-side context for hashing: { requestId, blindingFactor, input }.
 * @param requestId a unique identifier for the request, used to correlate with the server's response
 * @param blindingFactor the random blinding factor used in the OPRF protocol, which should be kept secret and is used to blind the input before sending it to the server
 * @param input the original input data that the client wants to hash using the OPRF protocol, which will be blinded and sent to the server for processing
 */
public record ClientHashingContext(String requestId, BigInteger blindingFactor, byte[] input) {
}
