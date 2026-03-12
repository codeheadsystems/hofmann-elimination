package com.codeheadsystems.hofmann.model.opaque;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Wire model for the server's final response after a successful OPAQUE authentication
 * (RFC 9807 §5.2 — session key export).
 * <p>
 * Contains both the session key (for verifying the 3DH handshake matched) and a JWT
 * bearer token for authenticating subsequent API requests.
 * <p>
 * When {@code keyRotationRequired} is {@code true}, the client should immediately
 * re-register via the change-password flow (using the same password) to migrate the
 * credential to the server's current key version. This field is omitted from the JSON
 * response when {@code null} or {@code false} for backward compatibility.
 * <p>
 * Used by: {@code POST /opaque/auth/finish} response
 *
 * @param sessionKeyBase64    base64-encoded shared session key derived from the 3DH handshake
 * @param token               signed JWT bearer token for authenticating subsequent requests
 * @param keyRotationRequired {@code true} when the credential was authenticated with an older
 *                            server key version and should be re-registered; {@code null} otherwise
 */
public record AuthFinishResponse(
    @JsonProperty("sessionKey") String sessionKeyBase64,
    @JsonProperty("token") String token,
    @JsonInclude(JsonInclude.Include.NON_NULL)
    @JsonProperty("keyRotationRequired") Boolean keyRotationRequired) {

  /**
   * Backward-compatible constructor (no key rotation flag).
   *
   * @param sessionKeyBase64 base64-encoded shared session key
   * @param token            signed JWT bearer token
   */
  public AuthFinishResponse(String sessionKeyBase64, String token) {
    this(sessionKeyBase64, token, null);
  }
}
