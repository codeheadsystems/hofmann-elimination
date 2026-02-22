package com.codeheadsystems.hofmann.client.model;

/**
 * The type Hofmann hash result.
 */
public record HofmannHashResult(ServerIdentifier serverIdentifier, String processIdentifier, String requestId,
                                byte[] hash) {

}
