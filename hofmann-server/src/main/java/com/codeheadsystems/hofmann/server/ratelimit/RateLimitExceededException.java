package com.codeheadsystems.hofmann.server.ratelimit;

/**
 * Thrown when a rate limit has been exceeded.
 * Framework adapters should map this to HTTP 429 Too Many Requests.
 */
public class RateLimitExceededException extends RuntimeException {

  /**
   * Instantiates a new Rate limit exceeded exception.
   */
  public RateLimitExceededException() {
    super("Rate limit exceeded");
  }
}
