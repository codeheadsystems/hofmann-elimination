package com.codeheadsystems.oprf.model;

/**
 * The response from the server after processing an elimination request.
 *
 * @param hexCodedEcPoint   The hex-encoded elliptic curve point returned by the server after applying the server process.
 * @param processIdentifier A identifier for the deterministic process used. Provided so the final value can be traced back to the server process that generated it, Resulting values are unique to the processIdentifier.
 */
public record EliminationResponse(String hexCodedEcPoint, String processIdentifier) {
}
