package com.codeheadsystems.hofmann.model.oprf;

import java.util.List;

/**
 * Shared field validation for the OPRF wire models.
 *
 * <p>The same shape as {@code WireFields} in the OPAQUE model package, and for the same reason:
 * the base-mode endpoint grew its bounds inline in the resource, so the checks lived in one
 * adapter and not the other. Putting them on the model means both adapters get them and neither
 * can drift.
 *
 * <p>These bound what is structurally unusable. They are not the batch cap — that belongs to the
 * manager, which owns the configured value — nor the transport size bound, which is
 * {@link VerifiableOprfLimits} and is applied before the body is parsed at all.
 */
final class OprfWireFields {

  /**
   * Upper bound on a hex-encoded element. A compressed P-521 point is 134 characters; this leaves
   * room without admitting an allocation attack, and a wrong-length element is rejected precisely
   * by {@code validateElement} downstream.
   */
  static final int MAX_ELEMENT_HEX_LENGTH = 512;

  /** Upper bound on the client-supplied request id. */
  static final int MAX_REQUEST_ID_LENGTH = 512;

  /**
   * Upper bound on the hex-encoded POPRF public input.
   *
   * <p>{@code info} is application-defined and is hashed into the key tweak, so it has no
   * protocol-imposed size. It is bounded here because it is attacker-supplied on an
   * unauthenticated endpoint and reaching the hash means allocating it first.
   */
  static final int MAX_INFO_HEX_LENGTH = 4096;

  /**
   * Hard ceiling on the element count accepted from the wire, independent of the configured batch
   * cap.
   *
   * <p>Matches {@code VoprfServerManager.ABSOLUTE_MAX_BATCH_SIZE}. A deployment can configure a
   * smaller cap and the manager will enforce it; this stops a list far beyond any legal
   * configuration being walked and copied before the manager gets to say so.
   */
  static final int ABSOLUTE_MAX_BATCH = 1024;

  private OprfWireFields() {
  }

  static void requireBatch(final List<String> elements, final String fieldName) {
    if (elements == null || elements.isEmpty()) {
      throw new IllegalArgumentException("Missing required field: " + fieldName);
    }
    if (elements.size() > ABSOLUTE_MAX_BATCH) {
      throw new IllegalArgumentException(
          "Batch of " + elements.size() + " exceeds the absolute maximum of " + ABSOLUTE_MAX_BATCH);
    }
    for (int i = 0; i < elements.size(); i++) {
      String element = elements.get(i);
      if (element == null || element.isBlank()) {
        throw new IllegalArgumentException("Missing element at index " + i + " of " + fieldName);
      }
      if (element.length() > MAX_ELEMENT_HEX_LENGTH) {
        throw new IllegalArgumentException("Element too large at index " + i + " of " + fieldName);
      }
    }
  }

  static void requireRequestId(final String requestId) {
    if (requestId == null || requestId.isBlank()) {
      throw new IllegalArgumentException("Missing required field: requestId");
    }
    if (requestId.length() > MAX_REQUEST_ID_LENGTH) {
      throw new IllegalArgumentException("Field too large: requestId");
    }
  }

  /**
   * Validates the POPRF public input. Null is rejected rather than defaulted: an absent {@code
   * info} and an empty one are different public inputs producing different outputs, so guessing
   * which the caller meant would silently change the function being evaluated.
   */
  static void requireInfo(final String info) {
    if (info == null) {
      throw new IllegalArgumentException(
          "Missing required field: info (use an empty string for no public input)");
    }
    if (info.length() > MAX_INFO_HEX_LENGTH) {
      throw new IllegalArgumentException("Field too large: info");
    }
  }
}
