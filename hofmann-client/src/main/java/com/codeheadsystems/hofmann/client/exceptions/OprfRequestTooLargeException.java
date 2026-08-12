package com.codeheadsystems.hofmann.client.exceptions;

/**
 * The request body exceeded the server's size bound (HTTP 413).
 *
 * <p>For the verifiable modes the bound is derived from the batch cap, so reaching it in practice
 * means the batch was too large. The client checks the batch size locally first — against the
 * server-advertised cap when there is one — so this is the backstop for a server whose bound is
 * tighter than what it advertises, or for a client that never fetched the config.
 */
public class OprfRequestTooLargeException extends OprfAccessorException {

  /**
   * Instantiates a new request-too-large exception.
   *
   * @param message the message
   */
  public OprfRequestTooLargeException(final String message) {
    super(message, null);
  }
}
