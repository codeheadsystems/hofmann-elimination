package com.codeheadsystems.hofmann.server.ratelimit;

public interface RateLimitConfigSupplier {

  RateLimitConfig authRateLimitConfig();

  RateLimitConfig registrationRateLimitConfig();

  RateLimitConfig oprfRateLimitConfig();

  RateLimitConfig recoveryRateLimitConfig();

  class DefaultRateLimitConfigSupplier implements RateLimitConfigSupplier {

    @Override
    public RateLimitConfig recoveryRateLimitConfig() {
      return new RateLimitConfig(3, 3.0 / 60, 50_000);
    }

    @Override
    public RateLimitConfig authRateLimitConfig() {
      return new RateLimitConfig(10, 10.0 / 60, 50_000);
    }

    @Override
    public RateLimitConfig registrationRateLimitConfig() {
      return new RateLimitConfig(5, 5.0 / 60, 50_000);
    }

    @Override
    public RateLimitConfig oprfRateLimitConfig() {
      return new RateLimitConfig(30, 30.0 / 60, 50_000);
    }

  }

}
