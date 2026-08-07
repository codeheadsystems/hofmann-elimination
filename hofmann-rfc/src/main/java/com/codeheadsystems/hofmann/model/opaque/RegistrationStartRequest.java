package com.codeheadsystems.hofmann.model.opaque;

import com.codeheadsystems.rfc.opaque.model.RegistrationRequest;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.Base64;

/**
 * Wire model for the first message the client sends during OPAQUE registration
 * (RFC 9807 §5.1 — RegistrationRequest).
 * <p>
 * The client blinds its password using a random scalar, hashes the result onto
 * the curve, and sends the blinded element to the server. The server evaluates
 * the OPRF without ever seeing the plaintext password. Both the credential
 * identifier and the blinded element are base64-encoded because they are raw
 * byte arrays that are not human-readable.
 * <p>
 * Used by: {@code POST /opaque/registration/start}
 *
 * @param credentialIdentifierBase64 base64-encoded credential identifier (e.g. username or email)                                   that the server uses to look up or create the registration record
 * @param blindedElementBase64       base64-encoded blinded OPRF input element (compressed SEC1 EC point)
 */
public record RegistrationStartRequest(
    @JsonProperty("credentialIdentifier") String credentialIdentifierBase64,
    @JsonProperty("blindedElement") String blindedElementBase64) {

  private static final Base64.Encoder B64 = Base64.getEncoder();

  /**
   * Instantiates a new Registration start request.
   *
   * @param credentialIdentifier the credential identifier
   * @param request              the request
   */
  public RegistrationStartRequest(byte[] credentialIdentifier, RegistrationRequest request) {
    this(B64.encodeToString(credentialIdentifier),
        B64.encodeToString(request.blindedElement()));
  }

  private static byte[] decode(String value, String fieldName) {
    return WireFields.decode(value, fieldName);
  }

  /**
   * Credential identifier byte [ ].
   *
   * @return the byte [ ]
   */
  public byte[] credentialIdentifier() {
    return decode(credentialIdentifierBase64, "credentialIdentifier");
  }

  /**
   * Returns the credential identifier in its canonical base64 spelling.
   *
   * <p>Overrides the generated accessor so that downstream consumers — the session index,
   * the JWT subject, and every rate-limiter bucket key — see one spelling per identifier.
   * See {@link CredentialIdentifiers} for why the raw client string cannot be used directly.
   *
   * @return the canonical base64 credential identifier
   */
  public String credentialIdentifierBase64() {
    return CredentialIdentifiers.canonicalize(credentialIdentifierBase64);
  }

  /**
   * Registration request registration request.
   *
   * @return the registration request
   */
  public RegistrationRequest registrationRequest() {
    return new RegistrationRequest(decode(blindedElementBase64, "blindedElement"));
  }
}
