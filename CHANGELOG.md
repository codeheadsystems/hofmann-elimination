# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

> **Security release, with one substantial feature.** Fixes three critical and nine high-severity
> findings from an August 2026 review, plus six follow-ups found while verifying those fixes. Two
> are exploitable by a malicious or compromised server against its own clients, and one lets a
> session survive the password change meant to revoke it — so upgrading is strongly recommended for
> anyone running OPAQUE or the standalone OPRF in production.
>
> It also adds RFC 9497 VOPRF and POPRF to `hofmann-rfc`. That part is a library addition: base
> mode is unchanged, and no existing caller needs to do anything. See *Added* below.
>
> **This release contains breaking changes and is versioned 3.1.0, not 3.0.1.** Most deployments
> need no code changes; the exceptions are listed under *Breaking changes* below. There is no
> wire-format change and existing registration records remain valid, with one narrow exception
> noted under *Upgrade notes*.

### Added

- **RFC 9497 VOPRF (mode 0x01) and POPRF (mode 0x02)** in `hofmann-rfc`, alongside the existing
  base mode. VOPRF lets a client verify the server evaluated with the key it publicly committed
  to; POPRF adds a public input, agreed by both parties, that separates evaluations. Both are
  available on all four cipher suites and support batching under a single proof. See
  `hofmann-rfc/OPRF.md`.

  Base mode is unchanged and remains the default, so OPAQUE and every existing caller keep
  byte-identical behaviour. This is a library addition only — no HTTP endpoints, TypeScript, or
  Rust support yet.

  Two requirements the verifiable modes place on callers, both of which the protocol cannot
  enforce: the server public key must be **authenticated** out of band, since an attacker able to
  substitute it can run a distinct key per client and still produce verifying proofs (RFC 9497
  §7.3); and one secret must not serve two modes, because the static Diffie-Hellman budget of
  §7.2.3 is per-key and POPRF exposes an inversion oracle where the other modes expose a
  multiplication oracle. `VerifiableProcessorDetail.deriveFromSeed` makes the second
  self-enforcing.

  Conformance is pinned against the RFC's own Appendix A vectors — key derivation for all twelve
  (suite, mode) pairs, the DLEQ proof bytes, and full end-to-end exchanges at batch sizes 1 and 2.

- `allowEphemeralKeys` (Dropwizard) / `hofmann.allow-ephemeral-keys` (Spring Boot), and the
  removal of committed key fallbacks from the demo and testserver configs. See the ninth
  high-severity entry below. `make up` generates throwaway keys into a gitignored `.env`.
- `FixedCapacityRateLimiter`, which pre-allocates its buckets and hashes keys into them, so an
  attacker-controlled key space cannot exhaust it. It backs the origin limiter, now enabled by
  default at 600/min — viable because origins are aggregated to an IPv6 /64 rather than keyed on
  a full address, of which one subscriber line holds 2^64.
- Optional pinning of the OPAQUE `context`: callers may supply the expected value and have the
  server's verified against it rather than adopting whatever arrives. `USAGE.md` specifies the
  context is shared out-of-band, and it is the only deployment-distinguishing value in the
  preamble when identities are absent.

### Fixed

- `Ristretto255GroupSpec.serializeScalar` had no range check, and its little-endian encoder copies
  at most 32 bytes and silently drops the rest — so a scalar at or above 2^256 was truncated into a
  different, valid-looking scalar rather than rejected. Unreachable from any in-tree call path, since no
  `src/main` code calls it and OPAQUE serializes scalars by a different route — and an external
  caller would have to supply its own out-of-range `BigInteger`, which nothing this library
  produces ever is. It would, however, have made the new proof encodings malleable. The Weierstrass implementation has always checked.
- Malformed hex reached callers as `IllegalStateException`, because BouncyCastle's
  `DecoderException` extends it rather than `IllegalArgumentException`. On the server that turned a
  client's bad input into a 5xx under the HTTP adapters' convention, letting any caller manufacture
  500s; on the client it let a server choose which exception type the application saw. Both
  directions are now typed by whose fault the failure is, in all three modes.
- A junk recovery bearer token drained the victim's recovery rate limit at
  `registration/finish`. That path is keyed on the token now, so guesses burn the attacker's own
  budget. `recovery/start` and `recovery/verify` still key on the credential identifier, so a
  targeted lockout of those two remains possible — see known limitations.
- `recoveryVerify`'s constant-time floor held a request thread for 250 ms with no ceiling on
  concurrency, so a few hundred sources — well under one IPv6 /64 — could exhaust the servlet
  pool and take down the whole application, not just recovery. Concurrency is capped, with excess
  refused rather than queued.
- `OpaqueHttpClient`'s constructor defaulted to `identityKsf`, so hand-constructing it silently
  disabled password stretching. It requires an explicit KSF now.

### Security

#### Critical

- **The Java OPRF client accepted the identity element as the server's evaluated element**
  (`hofmann-rfc`). RFC 9497 §2.1 requires `DeserializeElement` to reject the group identity. For
  ristretto255 the identity is the canonical all-zero encoding, so every RFC 9496 decode check
  passed for it; `blindInv · O = O`, and the OPRF output collapsed to a function of the input
  alone — independent of both the blind and the server key. A malicious, breached, or MITM'd
  server returning 32 zero bytes silently turned the OPRF into an unkeyed, unsalted hash, and
  mode `0x00` has no verifiability proof for the client to detect it with. This affected the
  standalone OPRF product as well as OPAQUE. The Rust and TypeScript ports already rejected it;
  Java was the only affected implementation. Also closed a matching hole where a blind congruent
  to zero mod n produced the same collapse from the caller's side, on all four suites.

- **Session revocation was bypassable, so password change and account deletion did not terminate
  an attacker's session** (`hofmann-server`). The credential store keyed on decoded bytes while
  the JWT subject, the session index and every rate-limiter bucket keyed on the raw base64
  string. `Base64.getDecoder()` ignores padding and the unused trailing bits of the final
  character, so one identifier had up to 32 accepted spellings — 1 for `len%3==0`, 8 for
  `len%3==2`, 32 for `len%3==1`. A session opened under one spelling survived a password change
  or deletion performed under another. The same aliasing multiplied every per-account rate limit
  by the same factor, including the gate on recovery-code guessing.

- **Both clients accepted key-stretching parameters from the server** (`hofmann-client`,
  `hofmann-typescript`). In OPAQUE the KSF runs entirely on the client, so these parameters
  decide how expensive an offline dictionary attack is against the record the server stores.
  A server answering `GET /opaque/config` with `argon2MemoryKib: 0` selected the identity KSF and
  the client stored a record derived from an unstretched password — and since the server kept
  serving the same config, authentication continued to work and nothing looked wrong from either
  side. Clients now enforce a floor of 19456 KiB / 2 iterations (the OWASP Argon2id minimum at
  t=2, p=1) and type-check the parameters before comparing them, because a non-numeric value
  yields `NaN` in JavaScript and every comparison with `NaN` is false.

#### High

- **`POST /opaque/registration/finish` was an unauthenticated, unthrottled enumeration oracle.**
  The rate limiter was consumed only on the recovery path, and the endpoint returned 400 for an
  existing credential and 204 for a new one — defeating the enumeration resistance `authStart`
  provides by manufacturing a KE2 for unknown credentials. Both branches now return 204, under a
  rate-limit token consumed before the existence lookup and a 25 ms floor that covers the write
  the not-exists branch performs.
- **Client-uploaded registration records were stored without validation.** No length check
  against Npk/Nh/Nn/Nm, and the client public key was never validated as a group element. A
  poisoned record made `/auth/start` fail for that identifier while an unknown one received a
  fake KE2 — a second enumeration oracle and a permanent per-identifier denial of service.
  Validated on all three write paths, including `changePasswordFinish`.
- **The server OPRF key was accepted from configuration unvalidated.** `oprfMasterKeyHex: "00"`
  on ristretto255 made every evaluation return the identity element while the deployment appeared
  healthy. Keys congruent to zero mod n are now rejected at startup and per request.
- **Scalar multiplication on the NIST curves was not constant-time.** BouncyCastle resolves the
  default multiplier to window-NAF for P-256/384/521, which leaks through the add/double
  sequence, secret-indexed table lookups, and a window size taken from the bit length. Measured
  17–19% timing separation between scalars of equal bit length and different Hamming weight, on
  a path where the attacker chooses the point and can request unlimited evaluations against a
  long-lived key. Replaced with a Montgomery ladder over a fixed-width scalar; the signal is now
  within noise on every axis measured.
- **Rate limiters and the pending-session store denied all new entries when full**, turning a
  cheap flood of attacker-chosen keys into a total outage. Both now reclaim expired entries
  before refusing. Also fixed a keying bug that made the OPAQUE origin limiter and the
  pre-existing OPRF limiter *global* rather than per-client: `@Context` field injection into a
  singleton JAX-RS resource yields null, so every caller shared one bucket.
- **The Spring Boot security chain competed with the host application's.** It was unconditional
  and matched every URL, so a consumer with their own chain hit
  `UnreachableFilterChainException` at startup on Spring Security 6.2+. It is now registered only
  when the application defines no chain of its own.
- **Spring Boot rewrote every error status to 401.** The ERROR dispatch was not permitted, so
  400, 429 and 503 all reached clients as "unauthorized" — a throttled client would re-prompt for
  a password instead of backing off.
- **Key material was generated at startup when unset, behind only a warning.** `jwtSecretHex`,
  `serverKeySeedHex` and `oprfSeedHex` each fell back to a freshly generated value, while
  `oprfMasterKeyHex` and `allowIdentityKsf` failed startup outright — the same class of
  misconfiguration treated two ways. The generated key is random per process, so this was never
  a key-disclosure risk in library code; the failure is availability and consistency, surfacing
  as intermittent authentication failures long after deployment. Where it did bite is deployment:
  the demo and testserver configs shipped working `${VAR:-<committed>}` fallbacks — including a
  real HMAC signing key — and both Dockerfiles copy those files into the published images, so an
  operator running an image without the environment variables set inherited a key that is public
  in git history. Both halves are fixed together, because emptying the defaults alone would have
  traded a known key for a silently random one.
- **The release pipeline ran unpinned third-party actions alongside the signing key.** Both
  release workflows imported the GPG key and wrote the passphrase to disk, then ran actions
  referenced by mutable tags in the same job. All actions are now pinned by commit SHA, signing
  material is scrubbed after publish, and the manual release refuses to publish from a ref that
  is not an ancestor of `main`.

### Breaking changes

- **`OpaqueClientConfig.fromServerConfig(cfg)` and `OpaqueHttpClient.create(url)` now throw**
  against a server offering the identity KSF or parameters below the floor. Warning and
  proceeding was considered and rejected: a warning that the attacker's own payload triggers does
  not stop the client writing an unstretched record. To opt in locally — for a dev server
  deliberately configured with `allowIdentityKsf` — use `fromServerConfig(cfg, true)` in Java or
  `create(url, { allowWeakServerKsf: true })` in TypeScript, or pin an `OpaqueClientConfig`
  through the client manager's overrides map, which does not consult the server at all.
- **The Spring CORS bean is renamed** from `corsConfigurationSource` to
  `hofmannCorsConfigurationSource` and is now `@ConditionalOnMissingBean`. The old name collided
  with any application that declared its own bean of that name — failing startup — and silently
  overrode applications configuring CORS through `WebMvcConfigurer`, because Spring Security
  prefers a bean of that exact name. Override the new name to customise it.
- **`POST /opaque/registration/finish` returns 204 for an already-registered credential**
  instead of 400. The record is still never overwritten; only the signal changed. A client using
  this endpoint to detect existing accounts must stop.
- **JAX-RS resource method signatures changed.** `OpaqueResource`'s six unauthenticated endpoints
  and `OprfResource.evaluate` take an additional `HttpServletRequest` parameter, needed to key
  rate limits by origin. This affects callers invoking the resource classes directly; it is
  transparent to HTTP clients.
- **Spring Boot components are now registered by the autoconfiguration** via `@Import` rather
  than requiring the consumer's component scan to reach
  `com.codeheadsystems.hofmann.springboot`. Applications already scanning that package are
  unaffected — the duplicate definition is discarded.

### Changed

- The origin-keyed rate limiter added for OPAQUE is **disabled by default**. As a blanket default
  it throttled legitimate deployments — one login draws two tokens, so a corporate NAT or mobile
  CGNAT shares one bucket — while an attacker sidesteps it with a few dozen addresses, or one
  IPv6 /64. Enable it by overriding `RateLimitConfigSupplier.originRateLimitConfig()`.
- OPRF keys at or above the group order are normalised rather than rejected. Such a key already
  works, since scalar multiplication reduces modulo the order, and `openssl rand -hex 32` — the
  documented recipe — exceeds ristretto255's order about 94% of the time. Rejecting would have
  broken live deployments whose stored outputs only that key reproduces. A warning is logged.
- Constant-time scalar multiplication costs roughly 2.4x on the primitive: about 0.5 ms extra per
  login on P-256 server-side. On the client the production Argon2id KSF swamps it entirely.

### Upgrade notes

- **JWTs issued before this upgrade under a non-canonical credential identifier will no longer
  match** on delete or change-password until the user re-authenticates. No client in this
  repository ever emits a non-canonical spelling and sessions are in-memory with a 3600 s default
  TTL, so this should not be observable in practice.
- Existing registration records remain valid. There is no wire-format or protocol change, and all
  RFC 9380, RFC 9497 and RFC 9807 vectors pass unchanged, as do the cross-implementation
  (Java/TypeScript ↔ Rust) vectors.
- Deployments that set `oprfMasterKeyHex` to a value congruent to zero modulo the group order
  will now **fail to start**. This is intentional: such a deployment had no effective OPRF key.

### Known limitations

Recorded in `TODO.md` rather than left implied:

- Rate limiting bounds memory, not throughput. The limiter in front of the unauthenticated
  endpoints can no longer be exhausted by varying the key — it pre-allocates its buckets — but an
  attacker sending enough traffic to drain every slot still denies service, as they would against
  any per-key limit.
- **Identifier squatting is bounded but not eliminated.** The origin limiter caps the rate at
  which a single source can claim unregistered identifiers; nothing stops a distributed attacker
  claiming them slowly. Eliminating it requires proof of identifier ownership — email or SMS
  confirmation before a registration is honoured — which belongs to the deployment, not the
  library.
- The OPAQUE `context` is verified against a locally supplied value only when the caller opts in
  by passing one. Requiring it would break every existing caller, so the default still accepts the
  server's value.
- Rate-limit slots are shared: distinct keys can hash to the same bucket and therefore share a
  budget. The per-process seed is folded through the key's characters, so collisions cannot be
  solved for offline, but per-key accounting is approximate rather than exact.
- **An unauthenticated caller can still lock a victim out of account recovery.**
  `recovery/start` and `recovery/verify` bound guessing per account, so a handful of requests
  naming a victim spend that victim's budget. The origin limiter bounds the rate per source and
  the limiter can no longer be exhausted, but a targeted lockout is cheap. Closing it needs
  something an attacker cannot supply on the victim's behalf — proof-of-work, or the email round
  trip that recovery ownership rests on anyway.

## [3.0.0] - 2026-08-04

> **The only breaking change in this release is in the Rust `hofmann-rfc` crate**, whose
> RNG parameter types change with the RustCrypto 0.14 upgrade. The Java artifacts and the
> TypeScript package have no source changes since 2.1.0 — they move to 3.0.0 only to stay
> in lockstep with the crate. Java and TypeScript users can upgrade with no code changes.
>
> No wire-format or protocol change in any implementation. All RFC 9380, RFC 9497 and
> RFC 9807 test vectors pass unchanged, so existing registration records remain valid and
> cross-implementation (Java/TypeScript ↔ Rust) interop is unaffected.

### Changed

#### RustCrypto 0.14 upgrade (`hofmann-rfc` crate — **breaking**)

- Moved the whole RustCrypto dependency set to the 0.14 line: `elliptic-curve`,
  `p256`, `p384`, `p521` and the newly split-out `hash2curve` crate at 0.14, plus
  `sha2` 0.11, `hmac` 0.13, `digest` 0.11 and `rand`/`rand_core` 0.10. Previously the
  curve crates were held at 0.13 because a partial bump puts two incompatible copies
  of `elliptic-curve` in the tree; the `ignore` list in `.github/dependabot.yml` that
  enforced that is now gone.
- **Breaking:** RNG parameters take `rand_core::CryptoRng` (0.10) instead of
  `rand_core::CryptoRngCore` (0.6). This affects `GroupSpec::random_scalar`,
  `OpaqueConfig::random_bytes`, and the `OpaqueClient`/`OpaqueServer` methods that
  accept an RNG. Callers using `rand::thread_rng()` should now use `rand::rng()`.
- Dropped the unused `hkdf` and `generic-array` dependencies. HKDF is implemented
  directly on HMAC in `OpaqueCipherSuite`; the `hkdf` crate was never called.
- `argon2` stays at 0.5 (0.6 is still a release candidate) and is now the only source
  of duplicate crates in the dependency tree, via `blake2` and `password-hash`.
- The crate is now `rustfmt`-clean; `cargo fmt --all --check` passes.

#### Dependency updates (Java)

- `auth0-jwt` 4.5.2 → 4.6.0, `bouncy-castle` 1.84 → 1.85, `jackson` 2.22.0 → 2.22.1,
  `tools-jackson` 3.2.0 → 3.2.1, `junit-jupiter` 6.1.0 → 6.1.2, and the
  `com.gradleup.nmcp.settings` plugin 1.6.0 → 1.6.1, plus a Gradle wrapper bump.

#### Dependency updates (TypeScript)

- Dev-dependency updates only (`vite`, `vitest`, `@types/node`); no runtime dependency
  or source changes.

## [2.1.0] - 2026-06-28

> Backward-compatible hardening and bug-fix release; no breaking API changes to the Java
> artifacts. **Rust note:** the `hofmann-rfc` crate's Argon2id KSF salt is corrected from 32 to
> 16 bytes to match the Java and TypeScript implementations and RFC 9807. A Rust 2.0.0 server
> using Argon2id derived a different `randomized_pwd`, so credentials registered against a Rust
> 2.0.0 server with Argon2id must be re-registered after upgrading — and cross-implementation
> (Java/TypeScript ↔ Rust) OPAQUE interop with Argon2id now works.

### Security

#### OPRF endpoint rate limiting (`hofmann-server`, `hofmann-springboot`, `hofmann-dropwizard`)

- **Spoofable `X-Forwarded-For` rate-limit bypass** — the unauthenticated OPRF endpoint keyed its
  rate limiter on the attacker-controlled left-most `X-Forwarded-For` value (and the Dropwizard
  adapter collapsed every client to the literal `"unknown"` when the header was absent). An
  attacker could rotate the header per request to mint unlimited buckets, or trigger a single
  shared-bucket self-DoS. The client IP is now taken from the real socket peer by default;
  `X-Forwarded-For` is honoured only when the new opt-in `trustForwardedHeaders` /
  `hofmann.trust-forwarded-headers` is enabled, and in that mode the **right-most**
  (proxy-appended) entry is used so an appending proxy cannot be tricked into trusting a spoofed
  value.
- **Unthrottled `recoveryVerify`** — account-recovery challenge verification consumed no rate-limit
  token yet ran an unconditional 250&nbsp;ms latency floor on the request thread, enabling online
  challenge-code brute-forcing and a thread-exhaustion DoS. Every attempt is now throttled by the
  per-credential recovery rate limiter (default capacity raised 3 → 6 to fit a full legitimate
  recovery plus retry headroom), and a throttled attempt returns HTTP 429.
- **Unbounded request bodies (memory-amplification DoS)** — request-body size is now enforced
  regardless of framing. The Dropwizard adapter bounds the entity stream (its previous
  `Content-Length` check was bypassable via chunked transfer encoding), and the Spring Boot adapter
  gained a `BodySizeLimitFilter` (it previously had no body-size limit at all) covering both
  `getInputStream()` and `getReader()`. The OPAQUE/OPRF wire DTOs additionally cap each encoded
  field length.

### Fixed

- **Rust Argon2id salt length** (`hofmann-rfc`) — corrected from 32 to 16 bytes to match the
  Java/TypeScript implementations and RFC 9807, fixing cross-implementation OPAQUE interop when
  Argon2id is enabled (see the release note above).
- **`InMemorySessionStore` memory leak** (`hofmann-server`) — the credential → JTI reverse index is
  now kept in sync when sessions expire lazily, instead of accumulating stale entries unbounded.
- **`InMemoryPendingSessionStore` startup crash on short TTLs** (`hofmann-server`) — the reaper
  period is now guarded so a TTL of 1–3 seconds no longer throws `IllegalArgumentException` at
  construction.

### Changed

- **Dependencies** — Dropwizard 5.0.1 → 5.0.2, Spring Boot 4.0.6 → 4.1.0, Jackson 2.21.4 → 2.22.0,
  tools-jackson 3.1.3 → 3.2.0, Gradle wrapper 9.5.1 → 9.6.0; added `jakarta.servlet-api` (6.1.0,
  `compileOnly`) for socket-peer access in the OPRF resource.
- **New configuration options** — `trustForwardedHeaders` (Dropwizard) /
  `hofmann.trust-forwarded-headers` (Spring; default `false`), and `hofmann.max-request-body-bytes`
  (Spring; default 64&nbsp;KiB, mirroring the existing Dropwizard `maxRequestBodyBytes`).

### Tests

- Added cross-implementation OPAQUE conformance vectors asserting the Java implementation matches
  the independent Rust implementation byte-for-byte for P-384, P-521, and Ristretto255 — the suites
  with no published CFRG known-answer vectors.
- Expanded coverage of security-property branches: enumeration-resistant fake KE2, the
  duplicate-registration takeover guard, single-use pending sessions, rate-limit 429 paths, the
  Spring `BodySizeLimitFilter`, and a Dropwizard integration test proving per-client OPRF
  rate-limit bucket isolation.

---

## [2.0.0] - 2026-06-01

> **Breaking change (Rust + TypeScript only).** The Rust crate (`hofmann-rfc`) and the
> TypeScript package (`@codeheadsystems/hofmann-typescript`) change several public
> signatures to harden against malformed input — see **Changed** for the migration. The
> Java artifacts (`hofmann-*`) have no breaking API changes; the major version bump keeps
> all artifacts on one version line.

### Security

#### Java server (`hofmann-rfc`, `hofmann-server`, `hofmann-springboot`, `hofmann-dropwizard`)

- **Timing side-channel in ristretto255 scalar multiplication** — replaced the variable-time
  right-to-left double-and-add (which branched on each secret-key bit and looped over the
  scalar's bit length) with a constant-time Montgomery ladder. The routine runs server-side
  with the long-term OPRF/OPAQUE key, so the previous leak was remotely exploitable to
  recover that key.
- **Account takeover via registration overwrite** — unauthenticated `registrationFinish` no
  longer overwrites an existing credential (last-write-wins). An attacker who knew a victim's
  credential identifier could previously replace their record. Existing credentials must be
  updated through the authenticated change-password or recovery flow.
- **User enumeration via `recoveryVerify` timing** — `recoveryVerify` now enforces a minimum
  wall-clock time (`RECOVERY_VERIFY_MIN_NANOS`, 250 ms) on both success and failure paths,
  closing the latency oracle that distinguished existing from non-existing accounts.
- **Server-side identity (neutral) element rejection** — the OPRF `blindEvaluate` paths and
  each OPAQUE AKE DH output now reject the all-zero/identity element, matching the existing
  client-side checks (RFC 9497 §3.3.2, RFC 9807).
- **Recovery token no longer logged** — `InMemoryRecoveryTokenStore` no longer writes the raw
  single-use recovery token to the DEBUG log.
- **Recovery-token consumption rate-limited** — `registrationFinish` (where the recovery token
  is consumed) is now throttled by the per-credential recovery rate limiter;
  `RateLimitExceededException` maps to HTTP 429, and a token supplied when recovery is
  unconfigured is treated as invalid instead of throwing.

#### TypeScript client (`@codeheadsystems/hofmann-typescript`)

- **Identity (neutral) element rejection** — `CipherSuite.finalize` rejects an identity OPRF
  evaluated element (RFC 9497 §2.1) and `CipherSuite.dhMultiply` rejects an identity peer DH
  contribution and result (RFC 9807 §6.3), for both the NIST and ristretto255 suites.
  `@noble/curves` already rejects the identity for the NIST suites, but **accepts** the
  all-zero ristretto255 encoding, so a malicious server could previously collapse the OPRF
  output to a fixed, key-independent value (degrading the OPRF to an unsalted hash of the
  input) or strip its contribution from the OPAQUE-3DH transcript.

#### Rust library (`hofmann-rfc`)

- **No panics on malformed/identity elements** — point decoding and `GroupSpec::scalar_multiply`
  now return errors instead of panicking on attacker-controlled bytes (a wrong-length or
  off-curve encoding, or the identity element). The OPRF/OPAQUE server paths feed the
  client-supplied blinded element and AKE public key straight into `scalar_multiply`, so a
  malformed request previously panicked the handling thread — a remote, unauthenticated denial
  of service now that the crate can build a server directly.
- **Bounds-checked credential response** — the OPAQUE client validates the (untrusted)
  `masked_response` length before unmasking and `Envelope::deserialize` rejects short input,
  so a malicious server can no longer panic the client while unmasking/slicing.

### Changed

- **Rust (breaking): point operations return `Result`.** `GroupSpec::scalar_multiply`,
  `OprfCipherSuite::finalize`, `Envelope::deserialize`, and the OPAQUE flow that builds on them
  — `OpaqueServer::create_registration_response` / `generate_ke2` / `generate_fake_ke2` /
  `generate_ke2_deterministic`, `OpaqueClient::finalize_registration[_deterministic]`, and the
  internal `blind_evaluate` / `create_*_response` / `finalize_registration*` /
  `derive_randomized_pwd` helpers — now return `Result<_, &'static str>`. Add `?` or `.unwrap()`
  at call sites. `scalar_multiply_generator`, `scalar_inverse`, `hash_to_group`, and `blind` are
  unchanged (they only ever see internally-derived, trusted inputs).
- **TypeScript (breaking): standalone HKDF helpers take the hash explicitly.** `hkdfExtract`,
  `hkdfExpand`, and `hkdfExpandLabel` (exported from the package index) now take the hash
  function as their first argument instead of hard-coding SHA-256, which silently produced
  incompatible, truncated key material for the P-384/P-521/ristretto255 suites. Prefer the
  suite-aware `CipherSuite.hkdf*` methods. A `HashFn` type is exported.

---

## [1.3.0] - 2026-03-09

### Added

#### Account recovery (`hofmann-server`, `hofmann-springboot`, `hofmann-dropwizard`)

- **`RecoveryChallenger` SPI** — pluggable interface for out-of-band identity verification
  (email codes, SMS OTP, TOTP, admin approval); implementations define `sendChallenge()` and
  `verifyResponse()` with constant-time comparison guidance
- **`RecoveryTokenStore` interface** — single-use, TTL-limited token storage for recovery
  authorization; `InMemoryRecoveryTokenStore` reference implementation with capacity limits
- **Recovery endpoints** — `POST /opaque/recovery/start` (sends challenge),
  `POST /opaque/recovery/verify` (validates response, issues recovery token); recovery token
  authorizes re-registration for the same credential identifier
- **Recovery DTOs** — `RecoveryStartRequest`, `RecoveryVerifyRequest`, `RecoveryVerifyResponse`
  in `hofmann-model`
- Wired into both Spring Boot (`OpaqueController`, `HofmannAutoConfiguration`) and Dropwizard
  (`OpaqueResource`, `HofmannBundle`); recovery is disabled when no `RecoveryChallenger` bean
  is provided

#### Rate limiting (`hofmann-server`)

- **`RateLimiter` interface** — token-bucket rate limiting with `tryConsume(key)` and pluggable
  implementations; default `InMemoryRateLimiter` suitable for single-node deployments
- **`RateLimitConfig`** — configurable `maxTokens`, `refillPerSecond`, and `maxEntries`
  (prevents OOM from key enumeration)
- **`RateLimitConfigSupplier`** — allows dynamic reconfiguration of rate limit parameters
- Applied to authentication endpoints by default; overridable via `@Bean` (Spring Boot) or
  `withAuthRateLimiter()` (Dropwizard)

#### `PendingSessionStore` interface (`hofmann-server`)

- Extracted pending OPAQUE session storage into a dedicated `PendingSessionStore` interface
  with `InMemoryPendingSessionStore` reference implementation; enables distributed session
  storage (e.g. Redis-backed) for multi-node clusters where authStart and authFinish may
  hit different nodes

#### Rust implementation (`hofmann-rust`)

- **New crate `hofmann-rfc`** — Rust library implementing RFC 9380, RFC 9497, and RFC 9807
- Supports P-256/SHA-256, P-384/SHA-384, P-521/SHA-512, and Ristretto255/SHA-512 cipher suites
- Uses RustCrypto ecosystem: `p256`, `p384`, `p521`, `sha2`, `hmac`, `hkdf`, `argon2`,
  `curve25519-dalek`, `subtle`, `zeroize`
- Full OPAQUE registration + authentication, fake KE2, Argon2id KSF, deterministic test APIs
- Recovery module with `RecoveryChallenger` trait and `InMemoryTokenStore`
- Test suite: RFC vector tests (hash-to-curve, OPRF, OPAQUE), roundtrip tests across all
  four cipher suites, recovery flow tests

### Security

- **HTTP security headers** — `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`,
  `Strict-Transport-Security` (1 year, includeSubDomains), `Cache-Control: no-store` added
  to all responses in both Dropwizard (`SecurityHeadersFilter`) and Spring Boot
  (`HofmannSecurityConfig`)
- **CORS configuration** — configurable CORS filter added to Dropwizard (`CorsFilter`) and
  Spring Boot; actuator endpoints restricted from external access
- **Constant-time scalar serialization** — removed timing leak in scalar-to-bytes conversion

### Changed

- `JwtManager` moved from `server.auth` to `server.manager` package
- Gradle wrapper bumped from 9.3.1 to 9.4.0

---

## [1.2.1] - 2026-03-08

### Security

- **TS: Constant-time scalar inversion** — Replaced the custom variable-time `modPow()`
  in `suite.ts` with `invert()` from `@noble/curves/abstract/modular`, which provides
  constant-time modular inversion via Fermat's little theorem. Affects OPRF finalize for
  all Weierstrass and ristretto255 suites.
- **TS: Constant-time equality for mismatched lengths** — `constantTimeEqual()` in
  `primitives.ts` no longer early-returns on length mismatch; instead XORs the length
  difference into the accumulator and iterates over `a.length` entries, preventing
  timing-based length leakage.
- **TS: Zero intermediate key material** — `derive3DHKeys()` in `ake.ts` now zeros
  `dh1`, `dh2`, `dh3`, `ikm`, `prk`, and `handshakeSecret` via `.fill(0)` immediately
  after use. `generateKE3()` in `client.ts` zeros `km2` and `km3` after MAC computation,
  including on authentication failure. Matches the Java `OpaqueAke.java` zeroing behavior.
- **Production KSF enforcement** — Added `allowIdentityKsf` property (default `false`)
  to `HofmannProperties` (Spring Boot) and `HofmannConfiguration` (Dropwizard). When
  `argon2MemoryKib=0` without `allowIdentityKsf=true`, startup fails with
  `IllegalStateException`. Prevents accidental production deployment with the identity
  KSF (no key stretching).

### Added

- **`OpaqueAuthenticationError`** — New error class in `hofmann-typescript` thrown for
  HTTP 401 responses from `OpaqueHttpClient._post()` and `deleteRegistration()`. Allows
  callers to distinguish authentication failures from other server errors, matching the
  Java `HofmannOpaqueAccessor` behavior. Exported from the package index.
- **`zeroRegistrationState()` / `zeroAuthState()`** — Utility functions in
  `hofmann-typescript` for zeroing sensitive `Uint8Array` fields in
  `ClientRegistrationState` and `ClientAuthState`. Callers invoke cleanup explicitly
  (matching Java's `AutoCloseable` pattern). Exported from the package index.
- **`IdentityKsfEnforcementTest`** — Unit test verifying that Spring Boot startup rejects
  identity KSF without the opt-in flag, accepts it with the flag, and allows Argon2id
  without the flag.

---

## [1.2.0] - 2026-03-02

### Added

#### Ristretto255/SHA-512 cipher suite

- **Java**: `Ristretto255GroupSpec` — pure Edwards25519 arithmetic (extended coordinates)
  with ristretto255 encode/decode per RFC 9496; `RISTRETTO255_SHA512` constant added to
  `OprfCipherSuite` and `OpaqueCipherSuite`
- **TypeScript**: `RISTRETTO255_SHA512` suite using `@noble/curves/ed25519`
  (`ristretto255_hasher`); `getCipherSuite("RISTRETTO255_SHA512")` factory support
- RFC 9497 test vectors for ristretto255/SHA-512 (`OprfVectorsTest.Ristretto255Sha512`)
- `hashToGroup`: expand_message_xmd to 64 bytes, two 32-byte halves decoded as little-endian
  mod p; `hashToScalar`: 64 bytes decoded as little-endian mod L; scalars serialized as
  32-byte little-endian (unlike Weierstrass big-endian)

#### TypeScript multi-cipher-suite support

- `CipherSuite` interface in `src/oprf/suite.ts` encapsulating all suite-specific operations
- P-384/SHA-384 and P-521/SHA-512 suites (`P384_SHA384`, `P521_SHA512`) alongside existing
  P-256/SHA-256; factory: `getCipherSuite("P384_SHA384")`
- `OpaqueClient(suite?)` and `OprfHttpClient(url, suite?)` accept optional suite parameter
- `OpaqueHttpClient.create(url)` and `OprfHttpClient.create(url)` auto-fetch server config
  and wire the correct cipher suite automatically
- Backward-compatible flat exports default to P-256/SHA-256; existing imports unchanged

#### Integration test module (`hofmann-integration-tests`)

- Cross-cipher-suite tests for OPRF and OPAQUE over P-256/SHA-256, P-384/SHA-384,
  P-521/SHA-512; abstract base class + 3 concrete subclasses per protocol
- Argon2id KSF enabled (1024 KiB, 1 iteration, 1 parallelism) in integration tests
- Cross-client tests: Java server ↔ TypeScript client via `TypeScriptRunner` (ProcessBuilder
  → vitest); driven by `TEST_SERVER_URL` + `TEST_OUTPUT_DIR` env vars; skipped when
  `node_modules/dist` is absent

### Fixed

- **RFC 9807 §4.1.2 — AKE ephemeral key seed size**: `Client.generateKE1()` and
  `OpaqueAke.generateKE2()` were generating AKE key seeds with `Nsk` bytes (32/48/66,
  suite-dependent) instead of the spec-mandated `Nseed = 32 = Nn` (suite-independent).
  Affected P-384 (was 48, now 32) and P-521 (was 66, now 32). P-256 was unaffected
  (Nsk = Nn = 32). Seeds are not transmitted, so no interoperability breakage; existing
  P-256 registrations and sessions are unaffected.
- **RFC 9807 §4.1.2 — envelope PrivateKey seed length**: `OpaqueEnvelope` was deriving the
  client private key seed with `Nsk` bytes instead of `Nseed = 32`. Fixed for P-384 and
  P-521 (breaking change for existing P-384/P-521 OPAQUE registrations; P-256 unaffected).
- **`OpaqueCipherSuite.P521_SHA512`** was incorrectly referencing `CurveHashSuite.P256_SHA256`
  internally; corrected to `CurveHashSuite.P521_SHA512`.
- **`OpaqueClientConfig.fromServerConfig()`** ignored the cipher suite when
  `argon2MemoryKib == 0` (identity KSF path); now correctly forwards the suite name.
- **TypeScript argon2id `hashLength`**: was hardcoded to 32 bytes regardless of suite; now
  parameterized as `suite.Nh` (32/48/64), ensuring correct stretched output length for
  P-384 and P-521.

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

[3.0.0]: https://github.com/codeheadsystems/hofmann-elimination/compare/v2.1.0...v3.0.0
[2.1.0]: https://github.com/codeheadsystems/hofmann-elimination/compare/v2.0.0...v2.1.0
[2.0.0]: https://github.com/codeheadsystems/hofmann-elimination/compare/v1.4.1...v2.0.0
[1.3.0]: https://github.com/codeheadsystems/hofmann-elimination/compare/v1.2.1...v1.3.0
[1.2.1]: https://github.com/codeheadsystems/hofmann-elimination/compare/v1.2.0...v1.2.1
[1.2.0]: https://github.com/codeheadsystems/hofmann-elimination/compare/v1.1.0...v1.2.0
[1.1.0]: https://github.com/codeheadsystems/hofmann-elimination/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/codeheadsystems/hofmann-elimination/releases/tag/v1.0.0
