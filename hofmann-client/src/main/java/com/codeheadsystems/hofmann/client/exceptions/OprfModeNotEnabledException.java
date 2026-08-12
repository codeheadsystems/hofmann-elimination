package com.codeheadsystems.hofmann.client.exceptions;

/**
 * The server does not offer the requested verifiable mode.
 *
 * <p>Raised from two places that mean the same thing: an HTTP 404 from
 * {@code /oprf/verifiable} or {@code /oprf/partially-oblivious}, which is how the server
 * advertises that it has no key for that mode, and a {@code GET /oprf/config} whose mode list is
 * present but does not name the mode, which lets the client fail before spending a round trip.
 * One type for both, so a caller has one thing to catch.
 *
 * <p>Not 501 and not an error on the server's part: the mode being off is a deployment choice, and
 * turning it on later is purely additive from the client's point of view.
 */
public class OprfModeNotEnabledException extends OprfAccessorException {

  /**
   * Instantiates a new mode-not-enabled exception.
   *
   * @param message the message
   */
  public OprfModeNotEnabledException(final String message) {
    super(message, null);
  }
}
