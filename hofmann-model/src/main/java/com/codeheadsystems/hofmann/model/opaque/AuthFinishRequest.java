package com.codeheadsystems.hofmann.model.opaque;

import com.codeheadsystems.opaque.model.KE3;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.Base64;

/**
 * Wire model for KE3 — the final message the client sends during OPAQUE authentication
 * (RFC 9807 §5.2 — AKE message 3).
 * <p>
 * After the client verifies the server MAC from KE2, it computes its own MAC over the
 * full AKE transcript (preamble + server MAC) and sends it here.  The server verifies
 * this MAC to complete mutual authentication.
 * <p>
 * If the client MAC is correct, both parties have now authenticated each other and
 * independently derived the same session key.  If the password was wrong, either the
 * client will fail to verify the server MAC (and not send KE3 at all), or if a bogus
 * KE3 is sent, the server will reject it with a 401.
 * <p>
 * The session token echoes the value from {@link AuthStartResponse} so the server can
 * retrieve the pending {@code ServerAuthState} it stored between KE1 and KE3.
 * <p>
 * Used by: {@code POST /opaque/auth/finish}
 *
 * @param sessionToken    the session token returned in {@link AuthStartResponse}; used
 *                        server-side to look up the pending AKE state for this handshake
 * @param clientMacBase64 base64-encoded client MAC authenticating the full AKE transcript;
 *                        computed as {@code HMAC(Km3, SHA256(preamble || serverMac))}
 */
public record AuthFinishRequest(
    @JsonProperty("sessionToken") String sessionToken,
    @JsonProperty("clientMac") String clientMacBase64) {

  private static final Base64.Encoder B64 = Base64.getEncoder();
  private static final Base64.Decoder B64D = Base64.getDecoder();

  public AuthFinishRequest(String sessionToken, KE3 ke3) {
    this(sessionToken, B64.encodeToString(ke3.clientMac()));
  }

  public KE3 ke3() {
    if (clientMacBase64 == null || clientMacBase64.isBlank()) {
      throw new IllegalArgumentException("Missing required field: clientMac");
    }
    try {
      return new KE3(B64D.decode(clientMacBase64));
    } catch (IllegalArgumentException e) {
      throw new IllegalArgumentException("Invalid base64 in field: clientMac", e);
    }
  }
}
