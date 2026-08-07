package com.codeheadsystems.hofmann.model.opaque;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.Base64;

/**
 * Wire model for a credential deletion request.
 * <p>
 * Removes a previously registered OPAQUE credential from the server's store.  This is not
 * part of the core RFC 9807 protocol but is a necessary lifecycle operation for any
 * production deployment (account deletion, re-registration, administrative cleanup, etc.).
 * <p>
 * The credential identifier is base64-encoded because it is a raw byte array that may not
 * be valid UTF-8 in all deployments (though in practice it is often an email or username).
 * <p>
 * Used by: {@code DELETE /opaque/registration}
 *
 * @param credentialIdentifierBase64 base64-encoded credential identifier whose registration                                   record should be permanently removed from the server store
 */
public record RegistrationDeleteRequest(
    @JsonProperty("credentialIdentifier") String credentialIdentifierBase64) {

  private static final Base64.Encoder B64 = Base64.getEncoder();

  /**
   * Instantiates a new Registration delete request.
   *
   * @param credentialIdentifier the credential identifier
   */
  public RegistrationDeleteRequest(byte[] credentialIdentifier) {
    this(B64.encodeToString(credentialIdentifier));
  }

  /**
   * Credential identifier byte [ ].
   *
   * @return the byte [ ]
   */
  public byte[] credentialIdentifier() {
    return WireFields.decode(credentialIdentifierBase64, "credentialIdentifier");
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
}
