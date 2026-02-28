# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.1.0] - 2026-02-28

### Added

#### `hofmann-typescript` — new npm package

A complete TypeScript/browser client for the Hofmann Elimination server, published separately
to npm as `hofmann-typescript`.

- **RFC 9497 OPRF** (P-256/SHA-256) — `blind()`, `finalize()`, `deriveKeyPair()`, `hashToScalar()`
- **RFC 9807 OPAQUE-3DH** — `OpaqueClient` with `createRegistrationRequest()`, `finalizeRegistration()`,
  `generateKE1()`, `generateKE3()`; deterministic variants for test-vector verification
- **`OpaqueHttpClient`** — full registration, authentication, and deletion flows over HTTP;
  `static async create(baseUrl)` factory auto-fetches `/opaque/config` and applies the
  server's cipher suite, context, and Argon2id parameters automatically
- **`OprfHttpClient`** — wraps `POST /oprf`; `static async create(baseUrl)` fetches
  `/oprf/config` and stores it in `cachedConfig`
- **Argon2id KSF** — `argon2idKsf(memoryKib, iterations, parallelism)` via `hash-wasm`
  (loaded on demand); `identityKsf` for test servers; custom `KSF` interface for any
  async stretching function
- **Interactive demo** — Vite-powered `demo.html` with proxied backend for manual
  testing of OPRF evaluation, OPAQUE registration, authentication, and deletion
- **RFC test suite** — 17 tests against CFRG official vectors for OPRF and OPAQUE-3DH
- **Integration test skeleton** — live-server tests activated via `TEST_SERVER_URL`
  (skipped automatically when the env-var is absent)
- **ESM + UMD dual build** — `dist/hofmann-typescript.js` and
  `dist/hofmann-typescript.umd.cjs`
- **`OpaqueConfigResponseDto`** exported from the package index so callers can type
  the auto-fetched config object

#### Server config endpoints

- `GET /opaque/config` — returns the OPAQUE cipher suite name, context string, and
  Argon2id parameters clients need to self-configure; registered by `HofmannBundle`
  and `HofmannAutoConfiguration`
- `GET /oprf/config` — returns the OPRF cipher suite name; registered alongside the
  existing `POST /oprf` endpoint

#### Java client auto-configuration

- **`HofmannOpaqueClientManager`** — new `@Inject` one-arg constructor
  `(HofmannOpaqueAccessor)` auto-fetches `GET /opaque/config` on first use per
  `ServerIdentifier`, building and caching the `Client` instance; a two-arg constructor
  `(accessor, Map<ServerIdentifier, OpaqueClientConfig>)` accepts per-server overrides
  for CLI tools or offline scenarios where auto-fetch is not suitable
- **`HofmannOprfClientManager`** — same lazy-cache pattern; new `@Inject` one-arg
  constructor auto-fetches `GET /oprf/config`; two-arg override-map constructor for
  CLI/offline use; package-private test constructor accepts a fixed `OprfClientManager`
  to avoid network calls in unit tests
- **`OpaqueClientConfig.fromServerConfig(OpaqueClientConfigResponse)`** — builds the
  correct `OpaqueConfig` from a server config response, selecting `forTesting` when
  `argon2MemoryKib == 0` and `withArgon2id` otherwise
- **`OprfClientConfig.fromServerConfig(OprfClientConfigResponse)`** — builds an
  `OprfCipherSuite` from the server-reported cipher suite name

---

## [1.0.0] - 2026-02-20

First stable release.

### Added

#### Core RFC implementations (`hofmann-rfc`)

- **RFC 9380 — Hash-to-Elliptic-Curves**: `HashToCurve` with Simplified SWU and
  `expand_message_xmd`; supports P-256, P-384, P-521, and secp256k1 (via 3-isogeny)
- **RFC 9497 — OPRF mode 0**: `OprfCipherSuite` with four suites — P-256/SHA-256,
  P-384/SHA-384, P-521/SHA-512, and Ristretto255/SHA-512; `OprfClientManager` and
  `OprfServerManager`; validated against CFRG test vectors
- **RFC 9807 — OPAQUE-3DH**: full registration (3 messages) and authentication (3
  messages including AKE); `OpaqueCipherSuite` wrapping `OprfCipherSuite`; `OpaqueConfig`
  with Argon2id and identity KSF options; `Client` and `Server` classes

#### Server library (`hofmann-server`)

- `HofmannOpaqueServerManager` — framework-agnostic service handling registration,
  authentication, and deletion; exception contract: `IAE → 400`, `SecurityException → 401`,
  `ISE → 503`
- `OpaqueResource` (JAX-RS) and `OprfResource` (JAX-RS) — thin adapters over the manager
- `JwtManager` — HMAC-SHA256 signed JWT issuance and verification
- `CredentialStore` and `SessionStore` interfaces with `InMemoryCredentialStore` and
  `InMemorySessionStore` reference implementations
- Session reaper: TTL-based eviction of stale AKE states (capped at 10,000 pending
  sessions to prevent DoS)

#### Dropwizard integration (`hofmann-dropwizard`)

- `HofmannBundle<C extends HofmannConfiguration>` — wires OPAQUE and OPRF endpoints,
  JWT auth filter, health check, and request-size filter into any Dropwizard application
- `HofmannConfiguration` — YAML configuration with defaults for cipher suite, context,
  server seeds, OPRF master key, Argon2id parameters, JWT secret/TTL/issuer, and request
  size limit
- `withSecureRandom(SecureRandom)` — fluent setter for HSM-backed or custom randomness
- `Supplier<ServerProcessorDetail>` constructor variant for hot OPRF key rotation
- In-memory dev mode (no-arg constructor) with prominent startup warnings

#### Spring Boot integration (`hofmann-springboot`)

- `HofmannAutoConfiguration` — `@ConditionalOnMissingBean` autoconfiguration for all
  server components; every bean is overridable by declaring a replacement `@Bean`
- `OpaqueController` and `OprfController` — Spring MVC adapters
- `application.yml` properties under the `hofmann.*` prefix (camel-case aliases provided)

#### Client library (`hofmann-client`)

- `HofmannOpaqueClientManager` — orchestrates the full OPAQUE registration,
  authentication, and deletion flows; delegates HTTP to `HofmannOpaqueAccessor`
- `HofmannOprfClientManager` — orchestrates the OPRF blind-evaluate-finalize flow;
  delegates HTTP to `HofmannOprfAccessor`
- `HofmannOpaqueAccessor` and `HofmannOprfAccessor` — `java.net.http.HttpClient`-based
  HTTP adapters; `401 → SecurityException`, other errors → typed accessor exceptions
- `OpaqueClientConfig` — `withArgon2id(...)`, `forTesting(...)` factory methods;
  `ServerIdentifier` and `ServerConnectionInfo` models

#### Security hardening

- Constant-time MAC comparison via `MessageDigest.isEqual` (replaces `Arrays.equals`)
- EC point validation on deserialization — identity and off-curve points rejected
- Bounds checks in `KE2.deserialize` and `Envelope.deserialize` before all array copies
- Fermat inversion (`blind.modPow(n-2, n)`) for constant-time scalar inversion in OPRF
  finalization (replaces `BigInteger.modInverse`)
- Subgroup membership check in `WeierstrassGroupSpecImpl.deserializePoint` for
  defense-in-depth against small-subgroup attacks on future cofactor > 1 curves
- Generic error messages on 400/503 responses — original messages logged at DEBUG only
- `ClientAuthState` and `ClientRegistrationState` implement `AutoCloseable`; `close()`
  zeros the password byte array
- Bearer-token protection on `DELETE /opaque/registration`; JWT subject must match the
  credential identifier being deleted
- Request body size filter — HTTP 413 for payloads exceeding `maxRequestBodyBytes` (default 64 KiB)
- OWASP Dependency-Check Gradle plugin configured to fail the build on CVSS ≥ 7
- Injectable `SecureRandom` via `OprfCipherSuite.withRandom(SecureRandom)` and
  `HofmannBundle.withSecureRandom(SecureRandom)`
- Session reaper lifecycle managed via Dropwizard `Managed` and Spring `destroyMethod`

#### Test infrastructure

- RFC 9380 Appendix J test vectors: `P256HashToCurveTest`, `P384HashToCurveTest`,
  `P521HashToCurveTest`
- RFC 9497 Appendix A test vectors: `OprfVectorsTest` (P-256 top-level; P-384, P-521,
  Ristretto255 as `@Nested` classes)
- RFC 9807 test vectors: `OpaqueVectorsTest` (P-256/SHA-256)
- Round-trip tests parameterized over all three Weierstrass cipher suites:
  `RoundTripTest` (OPRF), `OpaqueRoundTripTest` (OPAQUE)
- Dropwizard and Spring Boot integration test suites exercising the full HTTP stack

---

[1.1.0]: https://github.com/codeheadsystems/hofmann-elimination/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/codeheadsystems/hofmann-elimination/releases/tag/v1.0.0
