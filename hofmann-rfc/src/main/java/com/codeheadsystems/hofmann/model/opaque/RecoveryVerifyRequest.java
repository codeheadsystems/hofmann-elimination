package com.codeheadsystems.hofmann.model.opaque;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.Base64;

/**
 * Wire model for an account recovery verification request.
 * <p>
 * Submits the user's response to the out-of-band challenge sent by
 * {@code POST /opaque/recovery/start}. On success, a single-use recovery
 * token is returned that authorizes re-registration.
 * <p>
 * Used by: {@code POST /opaque/recovery/verify}
 *
 * @param credentialIdentifierBase64 base64-encoded credential identifier
 * @param challengeResponse          the user's response to the challenge (e.g. "482901")
 */
public record RecoveryVerifyRequest(
    @JsonProperty("credentialIdentifier") String credentialIdentifierBase64,
    @JsonProperty("challengeResponse") String challengeResponse) {

  private static final Base64.Encoder B64 = Base64.getEncoder();
  private static final Base64.Decoder B64D = Base64.getDecoder();

  /**
   * Instantiates a new Recovery verify request from raw credential identifier bytes.
   *
   * @param credentialIdentifier the credential identifier
   * @param challengeResponse    the user's challenge response
   */
  public RecoveryVerifyRequest(byte[] credentialIdentifier, String challengeResponse) {
    this(B64.encodeToString(credentialIdentifier), challengeResponse);
  }

  /**
   * Returns the decoded credential identifier bytes.
   *
   * @return the credential identifier
   * @throws IllegalArgumentException if the field is missing, blank, or invalid base64
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
   * Returns the challenge response, validated as non-null and non-blank.
   *
   * @return the challenge response string
   * @throws IllegalArgumentException if the field is missing or blank
   */
  public String validatedChallengeResponse() {
    if (challengeResponse == null || challengeResponse.isBlank()) {
      throw new IllegalArgumentException("Missing required field: challengeResponse");
    }
    return challengeResponse;
  }
}
