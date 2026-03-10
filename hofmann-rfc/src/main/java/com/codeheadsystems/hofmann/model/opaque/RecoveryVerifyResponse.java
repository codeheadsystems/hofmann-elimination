package com.codeheadsystems.hofmann.model.opaque;

import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Wire model for an account recovery verification response.
 * <p>
 * Contains a single-use recovery token that authorizes re-registration.
 * The client should use this token as {@code Authorization: Bearer <recoveryToken>}
 * in the subsequent {@code POST /opaque/registration/start} and
 * {@code POST /opaque/registration/finish} calls.
 * <p>
 * Returned by: {@code POST /opaque/recovery/verify}
 *
 * @param recoveryToken single-use recovery token authorizing re-registration
 */
public record RecoveryVerifyResponse(
    @JsonProperty("recoveryToken") String recoveryToken) {
}
