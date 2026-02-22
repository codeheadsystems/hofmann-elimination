package com.codeheadsystems.hofmann.model.opaque;

import com.codeheadsystems.rfc.opaque.model.RegistrationResponse;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.Base64;

/**
 * Server's response to OPAQUE registration phase 1 (RFC 9807 §5.1 — RegistrationResponse).
 * <p>
 * After the server evaluates the OPRF on the client's blinded element, it returns two things:
 * <ol>
 *   <li>The <em>evaluated element</em> — the OPRF output the client will use to derive its
 *       randomized password ({@code randomized_pwd}). Because the element was blinded before
 *       sending, the server never learns the plaintext password.</li>
 *   <li>The <em>server long-term public key</em> — sent here so the client can bind it into
 *       the envelope and verify the server's identity during authentication.  This is the same
 *       key pair the server uses for the AKE (authenticated key exchange) in phase 3.</li>
 * </ol>
 * Both fields are base64-encoded because they are raw byte arrays (compressed SEC1 EC points).
 * <p>
 * Used by: {@code POST /opaque/registration/start} response
 *
 * @param evaluatedElementBase64 base64-encoded OPRF-evaluated element (compressed SEC1 EC point)
 * @param serverPublicKeyBase64  base64-encoded server long-term public key (compressed SEC1 EC point,                               first byte 0x02 or 0x03)
 */
public record RegistrationStartResponse(
    @JsonProperty("evaluatedElement") String evaluatedElementBase64,
    @JsonProperty("serverPublicKey") String serverPublicKeyBase64) {

  private static final Base64.Encoder B64 = Base64.getEncoder();
  private static final Base64.Decoder B64D = Base64.getDecoder();

  /**
   * Instantiates a new Registration start response.
   *
   * @param response the response
   */
  public RegistrationStartResponse(RegistrationResponse response) {
    this(B64.encodeToString(response.evaluatedElement()),
        B64.encodeToString(response.serverPublicKey()));
  }

  private static byte[] decode(String value, String fieldName) {
    if (value == null || value.isBlank()) {
      throw new IllegalArgumentException("Missing required field: " + fieldName);
    }
    try {
      return B64D.decode(value);
    } catch (IllegalArgumentException e) {
      throw new IllegalArgumentException("Invalid base64 in field: " + fieldName, e);
    }
  }

  /**
   * Registration response registration response.
   *
   * @return the registration response
   */
  public RegistrationResponse registrationResponse() {
    return new RegistrationResponse(
        decode(evaluatedElementBase64, "evaluatedElement"),
        decode(serverPublicKeyBase64, "serverPublicKey"));
  }
}
