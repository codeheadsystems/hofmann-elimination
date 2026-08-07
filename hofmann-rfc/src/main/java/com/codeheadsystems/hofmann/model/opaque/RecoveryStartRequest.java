package com.codeheadsystems.hofmann.model.opaque;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.Base64;

/**
 * Wire model for an account recovery start request.
 * <p>
 * Initiates the out-of-band identity verification challenge for account recovery.
 * The server's {@code RecoveryChallenger} implementation determines what challenge
 * is sent (e.g. email code, SMS OTP, TOTP prompt).
 * <p>
 * Used by: {@code POST /opaque/recovery/start}
 *
 * @param credentialIdentifierBase64 base64-encoded credential identifier of the account to recover
 */
public record RecoveryStartRequest(
    @JsonProperty("credentialIdentifier") String credentialIdentifierBase64) {

  private static final Base64.Encoder B64 = Base64.getEncoder();

  /**
   * Instantiates a new Recovery start request from raw credential identifier bytes.
   *
   * @param credentialIdentifier the credential identifier
   */
  public RecoveryStartRequest(byte[] credentialIdentifier) {
    this(B64.encodeToString(credentialIdentifier));
  }

  /**
   * Returns the decoded credential identifier bytes.
   *
   * @return the credential identifier
   * @throws IllegalArgumentException if the field is missing, blank, or invalid base64
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
