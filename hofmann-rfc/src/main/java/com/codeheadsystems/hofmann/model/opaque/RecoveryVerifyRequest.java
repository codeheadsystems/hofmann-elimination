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

  /**
   * Returns the challenge response, validated as non-null, non-blank, and within the field cap.
   *
   * <p>This <em>overrides</em> the generated record accessor rather than sitting beside it as a
   * separately-named "validated" variant. The variant left the generated {@code challengeResponse()}
   * public and returning the raw string, so the validation was opt-in: correct only for as long as
   * every caller remembered to reach for the longer name. Overriding the accessor means there is
   * no uncapped spelling left to reach for — the same shape as
   * {@link #credentialIdentifierBase64()} here and {@code AuthFinishRequest.sessionToken()}.
   *
   * <p>The value is not base64, so it never passed through the decode helper and carried no bound
   * at all; it is still an unauthenticated client-supplied string handed straight to a
   * {@code RecoveryChallenger} implementation.
   *
   * @return the challenge response string
   * @throws IllegalArgumentException if the field is missing, blank, or over the field cap
   */
  @Override
  public String challengeResponse() {
    if (challengeResponse == null || challengeResponse.isBlank()) {
      throw new IllegalArgumentException("Missing required field: challengeResponse");
    }
    WireFields.checkLength(challengeResponse, "challengeResponse");
    return challengeResponse;
  }

  /**
   * Returns the validated challenge response.
   *
   * @return the challenge response string
   * @throws IllegalArgumentException if the field is missing, blank, or over the field cap
   * @deprecated the validation now lives on {@link #challengeResponse()} itself, so this name no
   *     longer distinguishes anything. Use {@code challengeResponse()}.
   */
  @Deprecated(since = "3.2.0", forRemoval = true)
  public String validatedChallengeResponse() {
    return challengeResponse();
  }
}
