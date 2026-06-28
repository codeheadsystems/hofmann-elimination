package com.codeheadsystems.hofmann.server.ratelimit;

public interface RateLimitConfigSupplier {

  RateLimitConfig authRateLimitConfig();

  RateLimitConfig registrationRateLimitConfig();

  RateLimitConfig oprfRateLimitConfig();

  RateLimitConfig recoveryRateLimitConfig();

  class DefaultRateLimitConfigSupplier implements RateLimitConfigSupplier {

    @Override
    public RateLimitConfig recoveryRateLimitConfig() {
      // A full legitimate recovery draws three tokens from this bucket (recoveryStart +
      // recoveryVerify + registrationFinish); capacity 6 leaves headroom for a couple of
      // mistyped challenge codes while still tightly throttling online code/token guessing.
      return new RateLimitConfig(6, 6.0 / 60, 50_000);
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
