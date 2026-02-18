package com.codeheadsystems.hofmann.model.opaque;

import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Wire model for the server's final response after a successful OPAQUE authentication
 * (RFC 9807 §5.2 — session key export).
 * <p>
 * Once the server has verified the client MAC from KE3, both parties have completed mutual
 * authentication and independently computed the same session key.  The server returns the
 * session key here so the client can verify that its locally derived key matches the server's
 * — confirming a successful handshake.
 * <p>
 * In production systems the session key would typically be used to establish a secure channel
 * (e.g. as a TLS pre-shared key or to derive application-level tokens) rather than being
 * sent back over the wire.  Returning it here is appropriate for library integration tests
 * and for scenarios where the server needs to share the derived key with a downstream system.
 * <p>
 * Used by: {@code POST /opaque/auth/finish} response
 *
 * @param sessionKeyBase64 base64-encoded shared session key derived from the 3DH handshake;
 *                         both client and server compute the same value independently
 */
public record AuthFinishResponse(
    @JsonProperty("sessionKey") String sessionKeyBase64) {
}
