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
  private static final Base64.Decoder B64D = Base64.getDecoder();

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
    if (credentialIdentifierBase64 == null || credentialIdentifierBase64.isBlank()) {
      throw new IllegalArgumentException("Missing required field: credentialIdentifier");
    }
    try {
      return B64D.decode(credentialIdentifierBase64);
    } catch (IllegalArgumentException e) {
      throw new IllegalArgumentException("Invalid base64 in field: credentialIdentifier", e);
    }
  }
}
