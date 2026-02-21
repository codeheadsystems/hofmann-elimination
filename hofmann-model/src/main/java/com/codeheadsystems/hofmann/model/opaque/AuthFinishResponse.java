package com.codeheadsystems.hofmann.model.opaque;

import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Wire model for the server's final response after a successful OPAQUE authentication
 * (RFC 9807 §5.2 — session key export).
 * <p>
 * Contains both the session key (for verifying the 3DH handshake matched) and a JWT
 * bearer token for authenticating subsequent API requests.
 * <p>
 * Used by: {@code POST /opaque/auth/finish} response
 *
 * @param sessionKeyBase64 base64-encoded shared session key derived from the 3DH handshake
 * @param token            signed JWT bearer token for authenticating subsequent requests
 */
public record AuthFinishResponse(
    @JsonProperty("sessionKey") String sessionKeyBase64,
    @JsonProperty("token") String token) {
}
