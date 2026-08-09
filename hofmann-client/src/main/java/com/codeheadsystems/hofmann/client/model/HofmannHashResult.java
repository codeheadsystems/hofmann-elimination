package com.codeheadsystems.hofmann.client.model;

/**
 * The outcome of one client-side OPRF round trip, pairing the hash with enough context to say
 * which server and which request produced it.
 *
 * @param serverIdentifier  the server that evaluated this request, as passed to
 *                          {@code performHash}
 * @param processIdentifier server-supplied label for the processor that generated the hash,
 *                          normally identifying which key was used. <strong>Unauthenticated</strong>
 *                          — a misbehaving server can attach any value to a correctly evaluated
 *                          result, so treat it as a routing hint only. See
 *                          {@link com.codeheadsystems.rfc.oprf.model.HashResult}
 * @param requestId         the client-generated id of the hashing context behind this result,
 *                          useful for correlating logs across the round trip
 * @param hash              the RFC 9497 OPRF output. Held by reference, not copied: callers who
 *                          treat the hash as a secret are responsible for clearing it
 */
public record HofmannHashResult(ServerIdentifier serverIdentifier, String processIdentifier, String requestId,
                                byte[] hash) {

}
