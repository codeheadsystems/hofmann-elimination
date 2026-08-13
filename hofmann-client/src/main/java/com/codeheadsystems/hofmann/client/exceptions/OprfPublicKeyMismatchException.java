package com.codeheadsystems.hofmann.client.exceptions;

/**
 * The server advertises a different public key than the one this client pinned.
 *
 * <p>Extends {@link SecurityException} rather than {@code OprfAccessorException} deliberately. The
 * other accessor exceptions mean a request failed; this one means the peer is not who was pinned,
 * which is the same class of statement {@code VoprfClientManager} makes when a proof does not
 * verify, and it should not be swallowed by a {@code catch (OprfAccessorException)} written to
 * handle transport trouble.
 *
 * <p>It does not, on its own, prove an attack. The likelier cause is a server that rotated its key
 * without the pinned copies being updated. What it does prove is that continuing would fail, and
 * failing here says why — where failing later says only that a proof did not verify.
 */
public class OprfPublicKeyMismatchException extends SecurityException {

  /**
   * Instantiates a new public-key mismatch exception.
   *
   * @param message the message
   */
  public OprfPublicKeyMismatchException(final String message) {
    super(message);
  }
}
