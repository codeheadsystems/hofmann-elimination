package com.codeheadsystems.hofmann.server.ratelimit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

class InMemoryRateLimiterTest {

  @Test
  void consumesUpToCapacityThenDenies() {
    InMemoryRateLimiter limiter = new InMemoryRateLimiter(new RateLimitConfig(2, 0.0, 100));
    try {
      assertTrue(limiter.tryConsume("k1"));
      assertTrue(limiter.tryConsume("k1"));
      assertFalse(limiter.tryConsume("k1"));
    } finally {
      limiter.shutdown();
    }
  }

  @Test
  void refillsTokensOverTime() throws InterruptedException {
    InMemoryRateLimiter limiter = new InMemoryRateLimiter(new RateLimitConfig(1, 5.0, 100));
    try {
      assertTrue(limiter.tryConsume("k1"));
      assertFalse(limiter.tryConsume("k1"));

      Thread.sleep(250); // ~1.25 tokens at 5 tokens/sec
      assertTrue(limiter.tryConsume("k1"));
    } finally {
      limiter.shutdown();
    }
  }

  @Test
  void enforcesMaxEntries() {
    InMemoryRateLimiter limiter = new InMemoryRateLimiter(new RateLimitConfig(1, 0.0, 1));
    try {
      assertTrue(limiter.tryConsume("key-a"));
      assertFalse(limiter.tryConsume("key-b"));
      assertEquals(1, limiter.bucketCount());
    } finally {
      limiter.shutdown();
    }
  }

  @Test
  void tracksBucketsPerKeyIndependently() {
    InMemoryRateLimiter limiter = new InMemoryRateLimiter(new RateLimitConfig(1, 0.0, 10));
    try {
      assertTrue(limiter.tryConsume("user-1"));
      assertFalse(limiter.tryConsume("user-1"));

      assertTrue(limiter.tryConsume("user-2"));
      assertFalse(limiter.tryConsume("user-2"));
    } finally {
      limiter.shutdown();
    }
  }
}

