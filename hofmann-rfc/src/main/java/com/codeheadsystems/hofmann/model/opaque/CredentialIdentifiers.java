package com.codeheadsystems.hofmann.model.opaque;

import java.util.Base64;

/**
 * Canonicalization for base64-encoded credential identifiers.
 *
 * <p>The server carries a credential identity in two forms: the decoded bytes, which key the
 * {@code CredentialStore}, and the base64 string, which keys the session store, the JWT
 * {@code sub} claim, and every rate-limiter bucket. {@link Base64.Decoder} is non-canonical —
 * it ignores both the padding and the unused trailing bits of the final character — so a
 * single identifier has multiple accepted string spellings that all decode to the same bytes:
 *
 * <pre>
 *   YWxpY2U=  YWxpY2U  YWxpY2V  YWxpY2V=  YWxpY2W=  YWxpY2X=   -&gt; all decode to "alice"
 * </pre>
 *
 * <p>The alias count depends on the identifier's length: {@code len % 3 == 0} has no aliases,
 * {@code len % 3 == 2} has 8, and {@code len % 3 == 1} has 32.
 *
 * <p>Left unnormalized, the two forms disagree and two things break. Session revocation is
 * keyed on the string, so a session opened under one spelling survives a password change or
 * account deletion performed under another — the record is replaced but the token is not
 * revoked. And each spelling gets its own rate-limiter bucket while resolving to the same
 * account, multiplying the online-guessing budget by up to 32x against the one control that
 * stands between a deployment and an online dictionary attack.
 *
 * <p>Normalizing at the DTO boundary means every downstream consumer — session index, JWT
 * subject, rate-limit key, log line — sees one spelling per identifier.
 */
final class CredentialIdentifiers {

  private static final Base64.Encoder ENCODER = Base64.getEncoder();
  private static final Base64.Decoder DECODER = Base64.getDecoder();

  /**
   * Matches {@code MAX_ENCODED_FIELD_LENGTH} in the request models. Kept in sync deliberately:
   * this is a pre-decode bound, not a replacement for the models' own per-field validation.
   */
  private static final int MAX_ENCODED_LENGTH = 4096;

  private CredentialIdentifiers() {
  }

  /**
   * Returns the canonical base64 spelling of a credential identifier: padded, with the unused
   * trailing bits of the final character cleared.
   *
   * <p>Null and blank values are returned unchanged so that the existing per-field validation
   * continues to produce its own "Missing required field" message rather than being pre-empted
   * here.
   *
   * @param value the client-supplied base64 string
   * @return the canonical encoding of the same bytes
   * @throws IllegalArgumentException if the value is not valid base64
   */
  static String canonicalize(final String value) {
    if (value == null || value.isBlank()) {
      return value;
    }
    // Bound the work before decoding. The per-field cap lives in each model's decode(), which
    // runs later, so without this an oversized identifier would be fully decoded and re-encoded
    // (~2.3x its length in allocation) only to be rejected a moment afterwards.
    if (value.length() > MAX_ENCODED_LENGTH) {
      throw new IllegalArgumentException("Field too large: credentialIdentifier");
    }
    try {
      return ENCODER.encodeToString(DECODER.decode(value));
    } catch (IllegalArgumentException e) {
      throw new IllegalArgumentException("Invalid base64 in field: credentialIdentifier", e);
    }
  }
}
