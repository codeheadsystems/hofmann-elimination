package com.codeheadsystems.hofmann.client.exceptions;

import java.time.Duration;

/**
 * The server rate-limited this client (HTTP 429).
 *
 * <p>Carries the {@code Retry-After} the server sent, when it sent one and it parsed. The
 * Dropwizard adapter sets it; the Spring adapter currently does not, so {@link #retryAfter()} is
 * null there. A caller that wants to back off should treat null as "no guidance" rather than as
 * "retry immediately".
 */
public class OprfRateLimitedException extends OprfAccessorException {

  private final transient Duration retryAfter;

  /**
   * Instantiates a new rate-limited exception.
   *
   * @param message    the message
   * @param retryAfter the parsed {@code Retry-After}, or null if absent or unparseable
   */
  public OprfRateLimitedException(final String message, final Duration retryAfter) {
    super(message, null);
    this.retryAfter = retryAfter;
  }

  /**
   * How long the server asked this client to wait, if it said.
   *
   * @return the retry-after duration, or null
   */
  public Duration retryAfter() {
    return retryAfter;
  }
}
