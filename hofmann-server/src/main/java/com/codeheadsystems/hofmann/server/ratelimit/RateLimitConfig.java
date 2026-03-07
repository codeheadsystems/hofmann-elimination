package com.codeheadsystems.hofmann.server.ratelimit;

/**
 * Configuration for a token-bucket rate limiter.
 *
 * @param maxTokens       maximum burst size (tokens available at any instant)
 * @param refillPerSecond rate at which tokens are replenished
 * @param maxEntries      maximum number of tracked keys (prevents OOM from key enumeration)
 */
public record RateLimitConfig(int maxTokens, double refillPerSecond, int maxEntries) {
}
