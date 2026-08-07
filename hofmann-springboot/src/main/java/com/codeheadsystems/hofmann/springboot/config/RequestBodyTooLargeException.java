package com.codeheadsystems.hofmann.springboot.config;

import java.io.IOException;

/**
 * Signals that a request body exceeded the configured limit while it was being read.
 *
 * <p>An {@link IOException} because that is what {@code ServletInputStream.read} is allowed to
 * throw, and a distinct type so it can be told apart from a genuine I/O failure. The distinction
 * decides a status code: a client sending too much is a 413, a socket dying mid-read is not.
 *
 * <p>It exists because the bare {@code IOException} it replaces had no handler, so an oversized
 * <em>chunked</em> body — one that declares no {@code Content-Length} and is therefore caught by
 * the stream bound rather than the up-front check — surfaced as a 500. The Dropwizard adapter
 * answered 413 for the same request, so the two integrations disagreed about whose fault it was.
 */
public class RequestBodyTooLargeException extends IOException {

  private static final long serialVersionUID = 1L;

  /**
   * Instantiates a new exception.
   *
   * @param maxBytes the limit that was exceeded
   */
  public RequestBodyTooLargeException(final long maxBytes) {
    super("Request body exceeds maximum allowed size of " + maxBytes + " bytes");
  }
}
