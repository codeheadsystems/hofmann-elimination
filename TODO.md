# Security TODO

Remaining items from the security review (Feb 2026). Items marked DONE have been
addressed; the rest are listed by priority.

## DONE

- [x] **P0: Constant-time MAC comparison** — replaced `Arrays.equals` with
      `MessageDigest.isEqual` in `OpaqueAke`, `OpaqueEnvelope`, and `Server`.
- [x] **P0: EC point validation** — `OpaqueCrypto.deserializePoint` and
      `OctetStringUtils.toEcPoint` now reject identity and off-curve points.
- [x] **P1: Deserialization bounds checks** — `KE2.deserialize` and
      `Envelope.deserialize` validate input length before `System.arraycopy`.
- [x] **P1: Session store DoS protection** — `OpaqueResource.pendingSessions` is
      capped at 10,000 entries with per-entry TTL instead of bulk clear.
- [x] **P1: Base64 decode error handling** — all `B64D.decode` calls wrapped in
      `decodeBase64()` helper returning HTTP 400 for malformed input.
- [x] **Input validation** — null/blank checks on all REST endpoint inputs;
      OPRF resource validates hex EC point input.
- [x] **Unified error messages** — all MAC/envelope failures throw generic
      "Authentication failed" to prevent protocol state leakage.
- [x] **Implement key material cleanup** — `ClientAuthState` and `ClientRegistrationState`
      now implement `AutoCloseable`; `close()` zeros the `password` byte array via
      `Arrays.fill`. `BigInteger` fields (`blind`, `clientAkePrivateKey`) are immutable
      and cannot be zeroed at the Java level.
- [x] **Shut down sessionReaper on app shutdown** — Added `HofmannOpaqueServerManager.shutdown()`
      which calls `sessionReaper.shutdown()`. `HofmannBundle` registers a Dropwizard `Managed`
      lifecycle component that calls it on stop. `HofmannAutoConfiguration` declares the bean
      with `@Bean(destroyMethod = "shutdown")` for Spring Boot.
- [x] **Add request size limits** — Added `maxRequestBodyBytes` field to
      `HofmannConfiguration` (default 65536 bytes / 64 KiB). `HofmannBundle` registers
      a JAX-RS `ContainerRequestFilter` that checks `Content-Length` and returns HTTP 413
      if the header exceeds the configured limit.
- [x] **Constant-time modular inverse** — `OprfCipherSuite.finalize()` now uses
      Fermat inversion `blind.modPow(n-2, n)` instead of `BigInteger.modInverse()`.
- [x] **Subgroup membership checks** — `WeierstrassGroupSpecImpl.deserializePoint()`
      documents the cofactor-1 assumption explicitly. A guarded runtime check (`n·P = O`)
      is included for defense-in-depth should a cofactor>1 curve be added.
- [x] **Protect credential deletion endpoint** — `DELETE /opaque/registration` now
      requires a valid JWT bearer token with subject matching the credential being deleted.
- [x] **Sanitize IAE messages in HTTP 400 responses** — All catch blocks return a generic
      message instead of forwarding `e.getMessage()`. Originals logged at DEBUG.
- [x] **Add status check in `HofmannOprfAccessor`** — Validates HTTP status code
      before deserializing: 401 throws `SecurityException`, other 4xx/5xx throws
      `OprfAccessorException`.
- [x] **Add dependency vulnerability scanning** — OWASP Dependency-Check Gradle plugin,
      fails the build on CVSS >= 7.
- [x] **Make `OpaqueCrypto.randomBytes()` injectable** — `RandomProvider` with injectable
      `SecureRandom` via `OpaqueConfig`.
- [x] **Builder pattern for cipher suites** — `OprfCipherSuite.builder()` provides a
      fluent builder with `withSuite()`, `withRandom()`, `withRandomProvider()`.
- [x] **Add ristretto255-SHA512 cipher suite** — `Ristretto255GroupSpec.java` implements
      `GroupSpec` with pure BigInteger Edwards25519 arithmetic. `RISTRETTO255_SHA512`
      constant in both `OprfCipherSuite` and `OpaqueCipherSuite`. OPRF test vectors pass.
- [x] **Document CSRF disable rationale** — Documented in `SECURITY.md` under
      "CSRF Disabled in HofmannSecurityConfig" with full justification.
- [x] **Document TLS requirement** — Documented in `SECURITY.md` under
      "TLS Required for Production" with threat analysis and deployment patterns
      (reverse proxy, cloud LB, application-level).
- [x] **Document secrets management** — Documented in `USAGE.md` under
      "Injecting secrets from environment variables" with examples for Spring Boot,
      Dropwizard, Docker Compose, and Kubernetes.
- [x] **Constant-time scalar serialization** — Extracted `ByteUtils.scalarToFixedBytes()`
      that always routes through a zero-padded intermediate buffer, eliminating
      data-dependent branching on `BigInteger.toByteArray()` length. Replaced all
      four call sites: `Server.java`, `HofmannBundle.java`,
      `HofmannAutoConfiguration.java`, `WeierstrassGroupSpecImpl.serializeScalar()`.
- [x] **Add HTTP security headers** — Spring Boot: added `.headers()` DSL to
      `HofmannSecurityConfig` configuring `X-Frame-Options: DENY`,
      `X-Content-Type-Options: nosniff`, `Strict-Transport-Security` (1 year,
      includeSubDomains), and `Cache-Control: no-store`. Dropwizard: added
      `SecurityHeadersFilter` (JAX-RS `ContainerResponseFilter`) registered in
      `HofmannBundle.run()` setting the same four headers.
- [x] **Add CORS configuration** — Spring Boot: added explicit `.cors()` DSL to
      `HofmannSecurityConfig` with a `CorsConfigurationSource` bean that blocks all
      cross-origin requests by default (empty allowed-origins list). Override the
      `corsConfigurationSource` bean to permit specific origins. Dropwizard: added
      `CorsFilter` (JAX-RS `ContainerResponseFilter`) registered in `HofmannBundle`,
      configured via `corsAllowedOrigins` in YAML. Both restrict methods to
      GET/POST/DELETE and headers to Content-Type/Authorization.
- [x] **Restrict actuator health endpoint** — Removed `/actuator/health` from the
      `permitAll()` list in `HofmannSecurityConfig`; it now requires authentication
      like all other non-OPAQUE/OPRF endpoints. Removed public key length detail from
      both `OpaqueServerHealthIndicator` (Spring Boot) and `OpaqueServerHealthCheck`
      (Dropwizard) health responses.
- [x] **Zero intermediate key material** — `OpaqueAke.java` now explicitly zeros
      `dh1`, `dh2`, `dh3`, `ikm`, `prk`, `handshakeSecret`, `km2`, `km3`, and
      `expectedServerMac` via `Arrays.fill(..., (byte) 0)` immediately after each
      value is consumed. On authentication failure in `generateKE3`, all remaining
      key material is zeroed before throwing. `BigInteger` scalars remain immutable
      and cannot be zeroed at the Java level.

- [x] **Add rate limiting** — Added `RateLimiter` interface with `InMemoryRateLimiter`
      (token-bucket) default implementation. OPAQUE endpoints rate-limit by credential
      identifier (`/auth/start`: 10 req/min, `/registration/start`: 5 req/min). OPRF
      endpoint rate-limits by client IP (30 req/min). All limits configurable; users can
      override with custom `RateLimiter` implementations (e.g. Redis-backed). Spring Boot:
      `@ConditionalOnMissingBean` beans with `@Qualifier`. Dropwizard: created in
      `HofmannBundle.run()` with managed shutdown lifecycle.

## P1: Important — Security hardening

(All P1 items completed.)

## P2: Recommended — Defense in depth

(All P2 items completed.)

## P3: Good to have

- [ ] **Production KSF enforcement** — The identity KSF is correctly flagged for
      test use only. Consider adding a runtime check that rejects identity KSF
      in non-test configurations to prevent accidental production deployment.
