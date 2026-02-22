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
      Files: `opaque/model/ClientAuthState.java`, `ClientRegistrationState.java`
- [x] **Shut down sessionReaper on app shutdown** — Added `HofmannOpaqueServerManager.shutdown()`
      which calls `sessionReaper.shutdown()`. `HofmannBundle` registers a Dropwizard `Managed`
      lifecycle component that calls it on stop. `HofmannAutoConfiguration` declares the bean
      with `@Bean(destroyMethod = "shutdown")` for Spring Boot.
      Files: `hofmann-server/manager/HofmannOpaqueServerManager.java`,
             `hofmann-dropwizard/HofmannBundle.java`,
             `hofmann-springboot/config/HofmannAutoConfiguration.java`
- [x] **Add request size limits** — Added `maxRequestBodyBytes` field to
      `HofmannConfiguration` (default 65536 bytes / 64 KiB). `HofmannBundle` registers
      a JAX-RS `ContainerRequestFilter` that checks `Content-Length` and returns HTTP 413
      if the header exceeds the configured limit.
      Files: `hofmann-dropwizard/HofmannConfiguration.java`, `HofmannBundle.java`
- [x] **Constant-time modular inverse** — `OprfCipherSuite.finalize()` now uses
      Fermat inversion `blind.modPow(n-2, n)` instead of `BigInteger.modInverse()`.
      `modPow` with a fixed-length exponent (n-2 has the same bit-length as n) is
      significantly more constant-time than the Extended Euclidean Algorithm.
- [x] **Subgroup membership checks** — `WeierstrassGroupSpecImpl.deserializePoint()`
      now documents the cofactor-1 assumption explicitly. For P-256/P-384/P-521/secp256k1
      (h=1) every non-identity on-curve point is automatically in the prime-order subgroup.
      A guarded runtime check (`n·P = O`) is included for defense-in-depth should a
      cofactor>1 curve be added in the future.
- [x] **Protect credential deletion endpoint** — `DELETE /opaque/registration` now
      requires a valid JWT bearer token. `HofmannOpaqueServerManager.registrationDelete()`
      verifies the token via `JwtManager` and validates that the JWT subject matches
      the credential being deleted. Both `OpaqueResource` (JAX-RS) and `OpaqueController`
      (Spring) extract the `Authorization` header and pass the bearer token to the manager.
      The client-side `HofmannOpaqueClientManager.deleteRegistration()` and
      `HofmannOpaqueAccessor.registrationDelete()` now require a `bearerToken` parameter.
      Files: `hofmann-server/manager/HofmannOpaqueServerManager.java`,
             `hofmann-server/resource/OpaqueResource.java`,
             `hofmann-springboot/controller/OpaqueController.java`,
             `hofmann-client/accessor/HofmannOpaqueAccessor.java`,
             `hofmann-client/manager/HofmannOpaqueClientManager.java`
- [x] **Sanitize IAE messages in HTTP 400 responses** — All `IllegalArgumentException`
      catch blocks in `OpaqueResource` and `OpaqueController` now return a generic
      "Invalid request" message instead of forwarding `e.getMessage()`. The original
      message is logged at DEBUG level for diagnostics. `IllegalStateException` messages
      are also sanitized to "Service unavailable".
      Files: `hofmann-server/resource/OpaqueResource.java`,
             `hofmann-springboot/controller/OpaqueController.java`
- [x] **Add status check in `HofmannOprfAccessor`** — Added `checkStatus()` method
      matching the pattern in `HofmannOpaqueAccessor`. The accessor now validates the
      HTTP status code before deserializing: 401 throws `SecurityException`, other
      4xx/5xx throws `OprfAccessorException`.
      Files: `hofmann-client/accessor/HofmannOprfAccessor.java`
- [x] **Add dependency vulnerability scanning** — Added OWASP Dependency-Check Gradle
      plugin (v12.1.1) to the root `build.gradle.kts`. Configured to scan all subprojects
      and fail the build on CVSS >= 7 (high severity). Run with `./gradlew dependencyCheckAnalyze`.
      Files: `build.gradle.kts`
- [X] P2: **Make `OpaqueCrypto.randomBytes()` injectable** — `OpaqueCrypto.java:19`
      uses a static `SecureRandom` instance. Unlike `OprfCipherSuite.randomScalar()`
      which supports `withRandom()`, the nonce/key generation in `OpaqueCrypto`
      cannot be replaced with an HSM-backed or test-deterministic source.

## P1: Critical

- [ ] **Builder pattern for cipher suites** — `OprfCipherSuite` currently has a single constructor
      with many parameters, which is error-prone and difficult to read. Refactor to
      a builder pattern that allows named parameters and validation. 
      This would improve readability and reduce the risk of parameter ordering mistakes when constructing cipher suites.

## P2: Important
- [ ] **Add ristretto255-SHA512 cipher suite** — RFC 9497 §4.4 defines a ristretto255-SHA512
  OPRF suite that was partially implemented but not completed. See `ristretto255.md` for
  full details, test vectors, known bugs, and a recommended debug approach.

      What is needed:
      - `ElligatorMap.java` in `rfc9380/`: field arithmetic, Elligator map, ristretto255
        encode/decode, point addition/doubling (Edwards25519)
      - `Ristretto255GroupSpec.java` in `rfc9380/`: implements `GroupSpec` using `ElligatorMap`
      - `OprfCipherSuite.RISTRETTO255_SHA512` constant and `buildRistretto255Sha512()` method
      - `Ristretto255Sha512` nested class in `OprfVectorsTest` (vectors in `ristretto255.md`)

      Key issues from the previous attempt (details in `ristretto255.md`):
      - Several constants and sign conventions are tricky; see the notes for correct formulas
      - `encodeRistretto255` was producing wrong output; the encode algorithm is the main
        remaining bug — `sqrtRatioM1` returns `wasSquare=false` for a case where it should
        be true
      - `hashToScalar` must use little-endian byte interpretation (not OS2IP/big-endian)

      The `GroupSpec` interface is already the right extension point; `OprfCipherSuite` needs
      no structural changes beyond adding the constant and builder.

- [ ] **Add TLS enforcement** — No HTTPS configuration exists. Add TLS config
      fields to `HofmannConfiguration` and document that production deployments
      MUST use HTTPS. Consider enforcing `https://` scheme in
      `OpaqueAccessor.baseUri()`. Without TLS, OPRF secrets and authentication
      tokens are transmitted in plaintext.

- [ ] **Add rate limiting** — No rate limiting on any endpoint. Add per-IP or
      per-credential rate limits, especially on `/auth/start` and the OPRF
      endpoint (to limit oracle calls against the server's OPRF key).

- [ ] **Add HTTP security headers** — Neither Dropwizard (`HofmannBundle`) nor
      Spring Boot (`HofmannSecurityConfig`) configures security response headers.
      Missing: `Strict-Transport-Security` (HSTS), `X-Content-Type-Options: nosniff`,
      `X-Frame-Options: DENY`, `Cache-Control: no-store` on auth responses.

      In Spring, add `.headers(h -> h.frameOptions(...).contentTypeOptions(...))`.
      In Dropwizard, register a `ContainerResponseFilter` that sets the headers.

- [ ] **Add CORS configuration** — No explicit CORS policy exists. Spring Security
      defaults to blocking cross-origin requests, but this is implicit and fragile.
      Add an explicit CORS configuration that restricts allowed origins, methods,
      and headers. In Dropwizard, add a `CrossOriginFilter` via the `FilterRegistration`.

- [ ] **Constant-time scalar serialization** — `BigInteger.toByteArray()` returns
      variable-length output (adds a leading zero byte when the high bit is set).
      Code at `OpaqueEnvelope.java:91-98`, `Server.java:57-63`, and
      `HofmannBundle.java:257-263` branches on `clientSkBytes.length > nsk`,
      which is data-dependent and could leak ~1 bit of timing information about
      the scalar value.

      Fix: extract a shared `scalarToFixedBytes(BigInteger, int)` helper that
      always copies `nsk` bytes from a zero-padded buffer without branching.

## P3: Good to have

- [ ] **Secrets manager integration** — `HofmannConfiguration` stores
      `serverKeySeedHex`, `oprfSeedHex`, `oprfMasterKeyHex` in plaintext YAML.
      Add support for environment variable substitution or a secrets manager.

- [ ] **Production KSF enforcement** — The identity KSF is correctly flagged for
      test use only. Consider adding a runtime check that rejects identity KSF
      in non-test configurations to prevent accidental production deployment.

- [ ] **Document CSRF disable rationale** — `HofmannSecurityConfig.java:27`
      disables CSRF globally. This is correct for a stateless JWT API but the
      code has no comment explaining why. Add a comment so future maintainers
      do not mistakenly re-enable CSRF or assume the disable was accidental.

- [ ] **Restrict actuator health endpoint** — `/actuator/health` is listed in
      `HofmannSecurityConfig.java:30` as `permitAll()`. While health checks
      are often public, this endpoint exposes server public key length via
      `OpaqueServerHealthIndicator`. Consider restricting to authenticated
      users or internal IPs, or removing the public key detail.

- [ ] **Zero intermediate key material** — Derived keys in `OpaqueAke.java`
      (`dh1`, `dh2`, `dh3`, `ikm`, `handshakeSecret`, `DerivedKeys` record)
      remain in memory after use. While Java GC makes deterministic zeroing
      difficult, explicitly zeroing byte arrays after they are consumed would
      reduce the window for memory-dump attacks.
