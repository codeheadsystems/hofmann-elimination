package com.codeheadsystems.rfc.oprf.model;

/**
 * Result of a hash operation, including the hash and an identifier for the process that generated it.
 * <p>
 * <strong>The identifier is not authenticated.</strong> In the verifiable modes the hash itself is
 * trustworthy — it is only produced after a proof has been checked against the public key the
 * client was configured with — but the accompanying label is whatever the server attached, and a
 * misbehaving server can put any value there on a correctly-evaluated result. Treat it as a
 * routing hint. In particular, do not persist results keyed by it in a way that would let a server
 * mislabel which key produced a stored value.
 *
 * @param hash              The resulting hash as a byte array.
 * @param processIdentifier Server-supplied label for the processor that generated this hash, normally
 *                          identifying which key was used. Unauthenticated; see above.
 */
public record HashResult(byte[] hash, String processIdentifier) {
}
