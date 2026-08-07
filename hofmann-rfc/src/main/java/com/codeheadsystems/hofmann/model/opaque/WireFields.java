package com.codeheadsystems.hofmann.model.opaque;

import java.util.Base64;

/**
 * Shared base64 field decoding for the OPAQUE wire models.
 *
 * <p>Every model in this package decodes attacker-supplied base64 into byte arrays, and each one
 * had written that out itself. {@code RegistrationStartRequest} and {@code AuthStartRequest} also
 * enforced a length cap and named the risk in a comment; the other five request models copied the
 * decode helper <em>without</em> the check. The gap mattered most at {@code registrationFinish},
 * which is unauthenticated and whose output is written to durable storage.
 *
 * <p>Collecting it here means the cap cannot be present on some paths and absent on others, and
 * that {@link CredentialIdentifiers}, which needs the same bound before it canonicalizes, reads
 * the value rather than restating it.
 */
final class WireFields {

  /**
   * Upper bound on the encoded length of any single field. The largest legitimate value is a
   * base64-encoded P-521 point (~180 chars); credential identifiers are application-defined.
   * This cap blocks unbounded allocation from attacker-supplied fields.
   *
   * <p><strong>Scope limit:</strong> 4096 is generous for a credential identifier, which is
   * retained as a map key across four rate limiters and the session index. It is deliberately not
   * tightened here — identifiers are application-defined, and a lower bound would reject
   * deployments that are working today. A deployment that knows its own identifier shape should
   * bound it further at its own trust boundary.
   */
  static final int MAX_ENCODED_FIELD_LENGTH = 4096;

  private static final Base64.Decoder DECODER = Base64.getDecoder();

  private WireFields() {
  }

  /**
   * Decodes a required base64 field, rejecting missing, oversized, and malformed values.
   *
   * <p>Order matters: the length check precedes the decode so an oversized field is refused
   * before it is expanded into a byte array.
   *
   * @param value     the client-supplied base64 string
   * @param fieldName the field name, used only in the exception message
   * @return the decoded bytes
   * @throws IllegalArgumentException if the field is missing, over the cap, or not valid base64
   */
  static byte[] decode(final String value, final String fieldName) {
    if (value == null || value.isBlank()) {
      throw new IllegalArgumentException("Missing required field: " + fieldName);
    }
    checkLength(value, fieldName);
    try {
      return DECODER.decode(value);
    } catch (IllegalArgumentException e) {
      throw new IllegalArgumentException("Invalid base64 in field: " + fieldName, e);
    }
  }

  /**
   * Enforces the field-length cap without decoding, for callers that validate a string field or
   * need the bound applied before some other work.
   *
   * @param value     the client-supplied string
   * @param fieldName the field name, used only in the exception message
   * @throws IllegalArgumentException if the value is over the cap
   */
  static void checkLength(final String value, final String fieldName) {
    if (value != null && value.length() > MAX_ENCODED_FIELD_LENGTH) {
      throw new IllegalArgumentException("Field too large: " + fieldName);
    }
  }
}
