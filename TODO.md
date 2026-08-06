# Security TODO

Open items from the security review of **August 2026** (six-reviewer fan-out across
`hofmann-rfc`, `hofmann-server`, `hofmann-client`, both framework integrations, and the
Rust/TypeScript ports).

The Feb 2026 DONE list has been removed: each entry was re-verified against the current
tree, and the ones that hold are recorded in "Confirmed sound" at the bottom rather than
carried as checklist noise. **Four entries did not hold and are now open items below,
marked `[was marked DONE]`.** Treat this file as a claim log that must be re-verified, not
as evidence.

Findings marked **[reproduced]** were demonstrated by executing code against the compiled
classes, not by reading alone.

---

## P0: Critical — fix before the next release

- [ ] **Reject the identity element when decoding a ristretto255 point** — [reproduced]
      `Ristretto255GroupSpec.decodeRistretto255()` (`:222-256`) implements every RFC 9496
      §4.3.1 check but not the protocol-layer identity rejection RFC 9497 §2.1 adds on top.
      The all-zero encoding is a *legitimate* ristretto255 encoding, so §4.3.1 conformance
      does not exclude it. `finalize()` (`OprfCipherSuite.java:277`) then computes
      `blindInv · O = O` and the OPRF output collapses to
      `H(len‖input‖len‖0³²‖"Finalize")` — a function of the input alone, independent of the
      blind *and* the server key:

      ```
      RISTRETTO255_SHA512 -> ACCEPTED identity; blind1 == blind2 output; key-independent
      P256_SHA256         -> REJECTED
      ```

      A malicious, breached, or MITM'd server returning 32 zero bytes silently downgrades
      every client to an unkeyed, unsalted hash. Mode `0x00` OPRF has no verifiability
      proof, so the client cannot detect it. Affects **both** the standalone OPRF product
      (`OprfClientManager.hashResult:85-89` passes the server element straight through) and
      OPAQUE (`OpaqueOprf.java:67`, where the envelope MAC degrades it to an auth failure).

      **Fix in `decodeRistretto255`, not in `finalize`.** `decodeRistretto255` has exactly
      one caller — `Ristretto255GroupSpec.scalarMultiply:137` — which is the shared entry
      point for `finalize` *and* all six AKE Diffie-Hellman operations
      (`OpaqueAke.java:154-156`, `:213-215`). One guard covers every path and matches where
      Rust placed it.

      Rust (`elliptic_curve/ristretto255.rs:126-135`) and TypeScript
      (`src/oprf/suite.ts:345-353`) both already reject this, and the TS comment describes
      this exact attack. **Java is the only implementation missing it.** Relatedly,
      `OprfServerManager.java:45-46` justifies its own server-side check with "The client
      already rejects the identity" — that premise is false for the Java client and should
      be corrected in the same change.

- [ ] **Canonicalize the credential identifier at the trust boundary** — [reproduced]
      The server carries **two identities per user**: `InMemoryCredentialStore` keys on the
      *decoded bytes* (`ByteKey`), while the JWT `sub`, `SessionStore`, and every
      rate-limit bucket key on the *raw base64 string* the client sent. Java's
      `Base64.getDecoder()` ignores both padding and the unused trailing bits of the final
      character, so `YWxpY2U=`, `YWxpY2U`, `YWxpY2V`, `YWxpY2V=`, `YWxpY2W=`, `YWxpY2X=`
      all decode to `alice`. Alias count depends on identifier length: `len%3==0` → 1
      (immune), `len%3==2` → 8, `len%3==1` → 32. Roughly two-thirds of a real user base is
      aliasable. Nothing normalizes anywhere.

      Two consequences:
      - **Session revocation is bypassable.** Every account-mutating operation performs a
        bytes-keyed mutation beside a string-keyed revocation
        (`HofmannOpaqueServerManager.java:319-320`, `:360-361`, `:414-417`). A session
        opened under an alias survives password change *and* account deletion until natural
        JWT expiry. This contradicts the Javadoc on both methods and the stated contract in
        `SessionStore.java`.
      - **Rate limits multiply 8–32× per account** — the only control between an OPAQUE
        deployment and online guessing, and it also gates the recovery OTP.

      One re-encode in the DTO accessor closes both. Prefer carrying decoded bytes plus a
      single server-derived string form.

- [ ] **Enforce a client-side floor on key-stretching parameters**
      `OpaqueClientConfig.fromServerConfig()` (`:109-115`) adopts `argon2MemoryKib` /
      `Iterations` / `Parallelism` verbatim from `GET /opaque/config`, and
      `argon2MemoryKib == 0` selects `IdentityKsf`, whose `stretch()` returns the input
      unchanged (`OpaqueConfig.java:207-212`). Reached from the production `@Inject` path
      (`HofmannOpaqueClientManager.java:89`); same in TypeScript (`src/opaque/http.ts:154`).

      Since the KSF runs entirely client-side, a server answering `{"argon2MemoryKib":0}`
      at registration makes the client store a record derived from an **unstretched**
      password — offline attack cost drops from 64 MiB Argon2id to ~1 hash/guess.
      Authentication keeps working afterwards, so nothing looks wrong from either side.
      The quieter variant (8 KiB / 1 iteration) is equally unchecked.

      The server has `allowIdentityKsf` and fails startup without it; the client has no
      counterpart. Add a local floor and require an explicit local opt-in for the identity
      KSF. Also pin `context` out-of-band rather than taking it from the server
      (`http.ts:157` vs `USAGE.md:23`), and reject non-`https` URIs in
      `ServerConnectionInfo`.

---

## P1: High

- [ ] **Rate-limit `POST /opaque/registration/finish` and equalize its response branches**
      [reproduced] The limiter is consumed only inside the recovery branch
      (`HofmannOpaqueServerManager.java:302`); the normal path consumes nothing. The
      endpoint also never checks that a `registrationStart` occurred, so the uploaded
      record can be arbitrary bytes. Existing credential → `IllegalArgumentException` →
      **400**; new credential → **204**. That is a free, unlimited, unauthenticated
      existence oracle which nullifies the fake-KE2 machinery `Server.generateFakeKE2`
      exists to provide. Worse, the 204 branch **stores the prober's record**, so every
      negative probe permanently squats that identifier and the legitimate user can never
      register — a single sweep can pre-register a whole namespace.

- [ ] **Validate uploaded `RegistrationRecord` fields before storing** — [reproduced]
      `RegistrationFinishRequest.registrationRecord()` (`:84-90`) base64-decodes
      `clientPublicKey`, `maskingKey`, `envelopeNonce`, `authTag` and hands them straight
      to `credentialStore.store()`. No length check against Npk/Nh/Nn/Nm, and
      `clientPublicKey` is never round-tripped through point deserialization. A poisoned
      record makes `/auth/start` throw on an XOR length mismatch (`97 vs 35`) → **400**,
      while an unknown identifier returns **200 + fake KE2** — a second enumeration oracle
      and a permanent per-identifier auth DoS. A wrong-length key yields a third
      distinguishable class (401) one step later.

- [ ] **Validate the server OPRF key at supplier construction** — [reproduced]
      `HofmannBundle.java:550` / `HofmannAutoConfiguration.java:470` do
      `new BigInteger(masterKeyHex, 16)` with no nonzero check, no `[1, n-1]` range check,
      and no reduction mod n. `oprfMasterKeyHex: "00"` on ristretto255 makes the server
      return the identity for every request; combined with the P0 above, the deployment
      silently runs with **no OPRF key at all**. On the Weierstrass suites, `k` and `k+n`
      are distinct config values producing identical output under different
      `processorIdentifier`s — a key-rotation footgun — and the raw bit length feeds the
      wNAF window size.

- [ ] **Use a constant-time multiplier for the NIST curves**
      `WeierstrassGroupSpecImpl.scalarMultiply:102` calls BouncyCastle `ECPoint.multiply`,
      which resolves to `WNafL2RMultiplier` for the NIST prime curves — confirmed by
      reflection on the live curve object, with a measured ~12% Hamming-weight signal at
      equal bit length. Every scalar reaching it is secret: the per-credential OPRF key,
      the server long-term and ephemeral AKE keys, the client blind, and the client's
      recovered private key. `P256_SHA256` is `OpaqueConfig.DEFAULT`.

      Server-side `blindEvaluate` is the sharpest target — the attacker chooses the point
      (so per-point wNAF precomputation misses every request, keeping the signal clean) and
      can request unlimited evaluations against a long-lived key. The ristretto path is a
      genuine Montgomery ladder with `cswap` (`Ristretto255GroupSpec.scalarMul:391-403`);
      the hardening never reached the three NIST suites. Note the previous "constant-time"
      work covered `modInverse` and scalar serialization only — `ECPoint.multiply` was
      never addressed. Fix via `curve.configure().setMultiplier(...)`, or document the
      suite choice as having a side-channel consequence.

- [ ] **Stop keying rate limits and DoS-sensitive stores on attacker-chosen values**
      `InMemoryRateLimiter:49-58` denies any non-resident key once `maxEntries` (50,000) is
      reached, and the key is entirely client-supplied. ~200 req/s of random identifiers
      sustains a **total login outage** indefinitely. Separately,
      `InMemoryPendingSessionStore:80-82` throws → **503** at 10,000 entries, and
      `authStart` stores an entry for every request including the fake path, so ~84 req/s
      of unfinished handshakes denies all logins. `recoveryVerify`'s 250 ms constant-time
      floor (`:463-486`) is likewise bounded only per key, so fresh identifiers buy free
      thread-holds and can saturate the servlet pool.

      Deny-on-capacity is the right *security* direction; the defect is the unbounded,
      attacker-controlled key space in front of it. `OprfResource.extractClientIp:134-151`
      already does this correctly (socket peer address by default, `X-Forwarded-For` only
      when explicitly trusted, right-most entry) — adopt that pattern on the OPAQUE
      endpoints, or add an outer IP-keyed limiter.

- [ ] **Scope the Spring Boot security filter chain**
      `HofmannSecurityConfig.securityFilterChain` (`:44-65`) has no `securityMatcher`, no
      `@Order`, and no `@ConditionalOnMissingBean`. It matches **every URL in the host
      application** and globally disables CSRF, forces `STATELESS`, replaces the CORS
      source, and redefines `anyRequest()` as "must present a Hofmann JWT". A consumer with
      their own chain gets a silent first-match-wins collision: either Hofmann swallows
      their entire authorization policy, or theirs swallows Hofmann's and `/opaque/**` +
      `/oprf/**` inherit whatever they configured. No startup error either way. Not caught
      by the repo's tests because `HofmannTestApplication` declares no chain of its own.
      Add `http.securityMatcher("/opaque/**", "/oprf/**")`, an explicit `@Order`, and
      `@ConditionalOnMissingBean`.

- [ ] **Register the Spring components from the auto-configuration**
      `META-INF/spring/...AutoConfiguration.imports` lists only `HofmannAutoConfiguration`,
      which carries no `@Import` or `@ComponentScan`. `OpaqueController`, `OprfController`,
      `HofmannSecurityConfig`, and `OpaqueServerHealthIndicator` load **only** if the
      consumer's component scan reaches `com.codeheadsystems.hofmann.springboot.*`. The
      repo's tests pass because `HofmannTestApplication` sits in exactly that package,
      which masks the gap. A consumer who wires the controllers directly gets the OPAQUE
      endpoints with no `HofmannSecurityConfig` and therefore none of Spring Security's
      header writers — Dropwizard applies those unconditionally. `USAGE.md:222` claims
      autoconfiguration "activates automatically" and never mentions component scanning.

- [ ] **Fail closed on unset JWT secret and OPAQUE seeds — and empty the demo defaults in
      the same change**
      `HofmannBundle.java:411-418` / `:503-510` and `HofmannAutoConfiguration.java:238-247`
      / `:143-147` generate random key material with only a `log.warn` when unset. Being
      precise: this is random *per process*, so there is no hardcoded signing key in the
      library and no token-forgery vulnerability in library code — the failure is
      availability and consistency (nodes disagree, every restart invalidates all
      accounts). The defect is inconsistency: `oprfMasterKeyHex` (`:544-549` / `:463-469`),
      `allowIdentityKsf` (`:481-489` / `:109-117`), and half-configured rotation seed pairs
      (`:447-451` / `:186-190`) all **throw**.

      Where it does bite is deployment: `hofmann-demo/server/config.yml:34,35,40,45` and
      `hofmann-testserver/config/config.yml:34,35,40,45` carry working
      `${VAR:-<committed-value>}` fallbacks for the server key seed, OPRF seed, OPRF master
      key, and JWT secret, and both `Dockerfile`s `COPY` that config at line 37. An
      operator running the published image without the env vars gets a **publicly known
      HMAC signing key**.

      Do both together: emptying the demo defaults alone just trades a known key for a
      silently random one. Add an explicit `allowEphemeralKeys` / `devMode` flag mirroring
      `allowIdentityKsf`.

- [ ] **Harden the release pipeline** — `release.yml:41,105` and
      `manual-release.yml:74,138` run unpinned third-party actions
      (`gradle/actions/setup-gradle@v3`, `softprops/action-gh-release@v2`) in the **same
      job** that imports the GPG private key (`release.yml:61`) and writes
      `signing.gnupg.passphrase` into `~/.gradle/gradle.properties` (`:84-89`). Neither is
      cleaned up. Whoever controls a mutable `v2`/`v3` tag can exfiltrate the code-signing
      key and `CENTRAL_PORTAL_*` and publish signed artifacts under
      `com.codeheadsystems:*`. `gradle.yml:34,153` already pins by commit SHA — apply the
      same practice here. Separately, `manual-release.yml:4` is `workflow_dispatch` with no
      branch restriction and publishes from the dispatch ref, so arbitrary unreviewed code
      can ship to Maven Central; gate on `main` ancestry.

---

## P2: Medium

- [ ] **Fake-KE2 path is measurably slower than the real path** — measured
      `real=743.7µs fake=872.7µs`, a **17.4%** one-directional offset
      (`HofmannOpaqueServerManager.java:544-560` → `Server.java:135-161`).
      `createFakeRecord` runs two extra `hkdfExpand` calls plus a full `deriveAkeKeyPair`
      (hash-to-scalar loop + generator scalar multiplication) *before* the same
      `generateKE2` the real path runs. Satisfies RFC 9807 §10.6's literal construction but
      not its goal. This is the residual enumeration exposure once the free oracles above
      are closed. Cache the fake record outside the timed path, or do equivalent work on
      both branches.

- [ ] **Move the deterministic test-vector APIs off the public production surface**
      `Client.java:103-149`, `Server.java:178-221`, `OprfCipherSuite.withRandom`
      (`:99-100`, `:358-361`), `OpaqueConfig.withRandomConfig` (`:104-106`), and the
      `forTesting()` factories are all public with nothing but a Javadoc "(for testing)"
      between them and a production caller. Failure modes if misused, in severity order:
      server reuse of `(maskingNonce, serverAkeKeySeed, serverNonce)` → **replayable
      authentication without the password**; reuse of `serverAkeKeySeed` alone → **total
      loss of forward secrecy with no functional symptom**; client blind reuse →
      **cross-account password-equality oracle**; client AKE seed reuse → session
      linkability. Silent in every case but the first. Move to a test-support artifact, or
      make package-private with a test-only accessor.

- [ ] **Zero password-equivalent material in the credential/envelope path**
      `OpaqueAke` is meticulous; its siblings are not. `randomizedPwd` — from which the
      envelope keys, masking key, and client long-term private key all derive — is created
      in `OpaqueCredentials.deriveRandomizedPwd` (`:110`) and never zeroed, in either
      `finalizeRegistrationWithNonce` or `recoverCredentials` (`:193-212`, `:224-230`).
      Same for `oprfOutput`, `stretchedOutput`, `maskingKey`, `pad`, `plaintext`,
      `authKey`, and the `deriveAkeKeyPair` seed (`OpaqueEnvelope.java:33-101`). A heap
      dump or swap page yields `randomizedPwd` directly, which is password-equivalent.

- [ ] **`[was marked DONE]` Actually invoke the state zeroization** — a grep across every
      `src/main` tree finds **zero** `try`-with-resources blocks and zero `close()` calls on
      `ClientAuthState` / `ClientRegistrationState`. The library's own client creates the
      state, uses it, and drops it (`HofmannOpaqueClientManager.java:128, 162, 203`). The
      `AutoCloseable` mitigation exists but nothing triggers it, so it is not a mitigation.
      The password `byte[]` is held by reference rather than copied, and `authenticate()`
      deliberately re-uses it afterwards for `changePassword` (`:176`), so zeroing at the
      obvious point needs care. Either wire it up or withdraw the claim from the docs.

- [ ] **Stop retaining the OPAQUE session key server-side as a `String`**
      `HofmannOpaqueServerManager.java:591-593` → `JwtManager.java:87` →
      `SessionData.java:13-17`. `String` cannot be zeroed, the source `byte[]` in
      `ServerAuthState` is never wiped, and `SessionData` is a record so its auto-generated
      `toString()` renders the base64 session key in full. `JwtManager.verify` reads only
      subject and jti — the session key is not needed at all.

- [ ] **`InMemorySessionStore` is unbounded with no reaper** — unlike the pending-session
      and recovery-token stores, entries are evicted only lazily inside `load(jti)`
      (`:38-44`), i.e. only if that exact token is presented again. A client that
      authenticates and discards its token leaves a `SessionData` resident forever. Add the
      capacity guard and background reaper the sibling stores already have.

- [ ] **`CredentialStore` exposes no atomic primitive, so the takeover guard cannot be made
      safe** — the guard at `HofmannOpaqueServerManager.java:321` is a check-then-act, and
      both the recovery path (`:319-332`) and `changePasswordFinish` (`:414-417`)
      `delete()` then `store()`, leaving a window where the credential does not exist. An
      attacker flooding the unthrottled `registration/finish` can land inside it. The
      interface offers only `store`/`load`/`delete` — **no implementer can close this**.
      Add `storeIfAbsent`/compare-and-set, and a transactional boundary for the
      delete-then-store pairs (a failure between them currently leaves the account
      permanently unregistered).

- [ ] **`InMemorySessionStore` revoke/store race** — `store()` (`:26-30`) puts then indexes;
      `revokeByCredentialIdentifier()` (`:69-75`) removes the index then drains it. A
      concurrent `store()` that reads the set before the remove and adds after the drain
      leaves a jti live in `store` but orphaned from the index — surviving that revocation
      and **every future one**. Same end state as the P0 canonicalization bug, reachable
      without the alias trick. Update both maps under one lock keyed on the credential.

- [ ] **Apply the field-length cap to all request models** —
      `RegistrationStartRequest` and `AuthStartRequest` define and enforce
      `MAX_ENCODED_FIELD_LENGTH = 4096`, naming the exact risk in a comment.
      `RegistrationFinishRequest`, `RegistrationDeleteRequest`, `RecoveryStartRequest`,
      `RecoveryVerifyRequest`, and `AuthFinishRequest` copy the decode helper *without* the
      check. `registrationFinish` is the one whose output is written to durable storage,
      and it is unauthenticated and unthrottled. 4096 is itself generous for a value
      retained as a map key across four limiters × 50,000 entries.

- [ ] **Enforce canonical point encodings** — `WeierstrassGroupSpecImpl:136-137` accepts
      uncompressed (`0x04`) and hybrid (`0x06`/`0x07`) SEC1 forms while serialization only
      ever emits compressed, so `DeserializeElement` is not the inverse of
      `SerializeElement` (RFC 9497 §2.1). Confirmed: the same point sent three ways yields
      byte-identical evaluated responses. Not an invalid-curve vector — off-curve points
      *are* rejected — but one group element gains many wire representations, bypassing
      anything that rate-limits, caches, dedups, or audits on the `blindedPoint` string.
      Require `length == elementSize()` and a `0x02`/`0x03` prefix.

- [ ] **Snapshot `supplier.get()` once in `OprfServerManager.process`** (`:50-51`) — it is
      called twice, so under the key rotation that `HofmannAutoConfiguration.java:452-456`
      explicitly documents, a request straddling the swap gets a hash computed with key A
      labelled as key B. That value can never be recomputed or verified — permanent data
      loss for affected accounts.

- [ ] **Range-check `Ristretto255GroupSpec.serializeScalar`** (`:147-150`) —
      `serializeScalar(2^300)` silently truncates to the identity scalar and
      `serializeScalar(-1)` returns garbage. This is the function OPAQUE uses to serialize
      private keys. `WeierstrassGroupSpecImpl.serializeScalar:113-119` validates `[0, n-1]`;
      mirror it.

- [ ] **Dropwizard `/api-docs` is unconditional and outside the filter chain** —
      `HofmannBundle.java:274-277` registers an `AssetServlet` at `/api-docs/*` on every
      consumer's application. Because it is a servlet, the `SecurityHeadersFilter`,
      `CorsFilter`, and size-limit filter registered via `environment.jersey().register()`
      (`:279-281`) do not apply. Swagger UI with no `X-Frame-Options` and no CSP, no opt-out,
      and it collides with a consumer's own `/api-docs` mapping.

- [ ] **`[was marked DONE]` Add dependency vulnerability scanning** — the OWASP
      Dependency-Check plugin is referenced **nowhere**: not in any `*.gradle.kts`, not in
      `buildSrc/src/main/kotlin/*`, not in `gradle/libs.versions.toml`. CI runs
      `gradle/actions/dependency-submission`, which feeds Dependabot alerts — advisory and
      post-hoc, not a build gate. There is also no `cargo audit` in the Rust job and no
      `npm audit` in the TypeScript job.

---

## P3: Low

- [ ] **Records with secret fields auto-generate leaking `toString()`** —
      `ServerProcessorDetail.java:9` holds `BigInteger masterKey`, and `BigInteger` renders
      as its **full decimal value** (unlike `byte[]`, which renders as an identity hash —
      which is why `JwtKeyDetail` and `ByteKey` are safe). One
      `log.info("detail={}", supplier.get())` — the pattern already used at
      `OprfResource.java:81` and `HofmannOprfClientManager.java:75` — writes the long-term
      OPRF master key to the log. It is also `Serializable`. Same shape at
      `ClientHashingContext.java:12` (blinding factor). No call site triggers it today; add
      explicit `toString()` overrides before one does.
- [ ] **Token and PII logging** — `HofmannOpaqueServerManager.java:582` and
      `InMemoryPendingSessionStore.java:85` log the pending session token at DEBUG, which
      contradicts the policy `InMemoryRecoveryTokenStore.java:75-78` spells out for the
      structurally equivalent recovery token. `:318` logs the credential identifier —
      usually an email — at INFO.
- [ ] **`SecurityException` from point validation escapes as HTTP 500** —
      `OpaqueResource.java:265-279` catches `RateLimitExceededException`,
      `IllegalArgumentException`, and `IllegalStateException`, but `deserializePoint`
      throws `SecurityException`. Malformed KE1 → 500 instead of 400. Not an oracle (real
      and fake paths throw identically), just inconsistent. Relatedly, attacker-controlled
      input produces `DecoderException`, `IllegalArgumentException`, *and*
      `SecurityException` across the three deserialization sites — the "sanitize IAE
      messages" work assumed a uniform type that does not exist.
- [ ] **OPRF client API takes the secret as a `String`** —
      `OprfClientManager.java:109` and `HofmannOprfClientManager.java:107` offer no
      `byte[]` overload, so the caller's secret is interned in a non-zeroable `String`. The
      OPAQUE side uses `byte[]` throughout.
- [ ] **JWT hardening** — no minimum secret length (`jwtSecretHex: "00"` yields a 1-byte
      HMAC key), no `aud` claim issued or verified (two deployments sharing the default
      `hofmann` issuer would cross-accept tokens), and `revoke(jti)` is never called from
      any endpoint, so there is no logout — a stolen JWT lives its full 3600 s TTL.
- [ ] **Recovery token is consumed before the identifier is checked** —
      `HofmannOpaqueServerManager.java:313-317` calls `remove(bearerToken)` and only then
      compares `credId`. Anyone who observes a token can invalidate it by replaying it with
      a wrong identifier, forcing the user to restart recovery. Peek, compare, then remove.
- [ ] **Deserialization strictness** — `KE2.deserialize` (`:26`) tests `length <` rather
      than `!=`, so trailing bytes parse and are silently dropped. No production caller
      today. `Server`'s constructor (`:38-46`) validates no key material — no range check
      on the private key, no check that the public key is the matching point. `hkdfExpand`
      (`OpaqueCipherSuite.java:175-190`) has no `len <= 255*Nh` guard.
      `ExpandMessageXmd:139-157` accepts an empty DST, which RFC 9380 §3.1 forbids.
- [ ] **API footguns in the hash-to-curve layer** — `HashToCurve.DEFAULT_DST` (`:28`) is a
      **secp256k1** tag on a class that also serves P-256/384/521;
      `forP521().hashToCurve(msg, DEFAULT_DST)` compiles and runs. `OprfCipherSuite`'s
      `contextString()` / `hashToGroupDst()` / `hashToScalarDst()` / `deriveKeyPairDst()`
      (`:130-159`) return live `byte[]` fields from process-wide statics shared across
      request threads — return `.clone()`.
- [ ] **CORS and header parity** — `CorsFilter.java:30-40` omits `Vary: Origin` on both
      non-matching early returns (only the matching path sets it at `:39`) and sets no
      `Access-Control-Max-Age`; a shared cache can serve one origin's response to another.
      Dropwizard writes HSTS unconditionally including on plaintext, while Spring writes it
      only on requests it considers secure — behind a TLS-terminating proxy, effectively
      never. Neither framework sets `Referrer-Policy` or `Content-Security-Policy`.
- [ ] **Demo and test-server hygiene** — `hofmann-demo/.swp` is tracked by git (vim swap
      file with an editing buffer, username, and hostname; no secrets); add `*.swp` to
      `.gitignore`. `hofmann-testserver/docker-compose.yml:10` publishes the Dropwizard
      **admin connector on `0.0.0.0:8081`** — healthchecks, metrics, thread dumps, admin
      task servlet; bind to `127.0.0.1`. No `USER` directive in any of the three
      Dockerfiles (all run as root). `haproxy.cfg` has no `option forwardfor`, so the
      backend sees the proxy IP for every client and the whole demo shares one OPRF
      rate-limit bucket.
- [ ] **Auto-merge without a test gate** — `auto-wolpert.yml:11-21` and
      `auto-dependabot.yml:11-27` auto-approve and auto-merge with no test gate expressed
      in the workflow; `auto-dependabot.yml:13-17` runs `fetch-metadata` then ignores its
      outputs, so major-version bumps merge unreviewed. Mitigating: both use
      `pull_request`, not `pull_request_target`, so fork PRs get a read-only token.

---

## Documentation

- [ ] **`USAGE.md` config reference is incomplete** — `:49-53` lists only
      `maxRequestBodyBytes` under "Security"; `corsAllowedOrigins`, `allowIdentityKsf`, and
      `trustForwardedHeaders` are absent. The `maxRequestBodyBytes` description still says
      Content-Length-only, understating the (correct, chunked-safe) implementation.
      `:222` claims Spring autoconfiguration "activates automatically" — see P1.
- [ ] **`hofmann.trust-forwarded-headers` bypasses `HofmannProperties`** — read via
      `@Value` at `OprfController.java:52` with no corresponding field. Default is `false`
      (secure), so this is consistency and docs only.
- [ ] **Stale doc pointers** — `OpaqueCrypto.deserializePoint` and
      `OctetStringUtils.toEcPoint` (credited in the old TODO for point validation) do not
      exist; the validation is real but lives in `WeierstrassGroupSpecImpl.deserializePoint`
      and `Ristretto255GroupSpec.decodeRistretto255`. `OPAQUE.md:168` lists an
      `OpaqueCrypto` class that is gone. `HASH_TO_CURVE.md:38` still documents
      `toEcPoint(Curve, String)`.
- [ ] **`SECURITY.md` caveats to add** — (a) the KSF runs client-side *and the client
      currently takes its parameters from the server* (`:88-93` omits the second half);
      (b) `BigInteger` arithmetic is magnitude-dependent, so the Montgomery ladder and
      Fermat inversion are improvements but not constant-time in the strict sense —
      `ByteUtils.scalarToFixedBytes` (`:77-84`) likewise produces fixed-length output but
      its `System.arraycopy` length still varies with the scalar's leading zero bytes;
      (c) the cipher-suite choice has a side-channel consequence today (ristretto255 is
      laddered, the NIST suites are not).

---

## Test coverage gaps

- [ ] **No Java test asserts the identity element is rejected.**
      `Ristretto255GroupSpecTest.java:42-50` asserts the all-zero encoding is *producible*
      (`0·G`, `L·G`); nothing asserts decoding it is refused.
      `WeierstrassGroupSpecImplTest` *does* have `identityPoint_throwsSecurityException` —
      the divergence in the test suites mirrors the divergence in the code. Port the
      TypeScript regression at `test/oprf.test.ts:265-278` (all four suites ×
      {`finalize`, `dhMultiply`}) to Java.
- [ ] **`OprfVectorsTest` exercises ristretto255 through `groupSpec` directly**, never
      through `OprfClientManager` / `OprfServerManager`, so no adversarial server response
      is ever tested.
- [ ] **Cross-implementation vectors are happy-path only** — add an identity-element case,
      and malformed/error-path cases per curve.
- [ ] **No test covers the base64 alias aliasing**, the unthrottled `registration/finish`
      branches, or revocation after a session opened under a non-canonical identifier.

---

## Confirmed sound (re-verified August 2026 — do not re-litigate)

Recorded so these questions stay closed. Everything here was checked against the current
tree in this review.

- **RFC conformance.** RFC 9807 Appendix C vectors pass (12 tests); RFC 9497 and RFC 9380
  Appendix K.2 vectors pass; cross-impl vectors match Rust for P-384/P-521/ristretto255.
  The preamble matches §6.4.1 exactly, and `ByteUtils.I2OSP` **throws** rather than
  truncating above 2^16-1, closing the obvious transcript-confusion vector. 3DH
  ephemeral/static assignment and IKM ordering are correct. The envelope correctly uses
  `Nn` for the seed in both store and recover — the classic P-521 `Nsk` bug is absent.
- **Ristretto255 decode** passes all 29 RFC 9496 Appendix A.2 must-reject vectors (0
  wrongly accepted); `SQRT_RATIO_M1`, `ENCODE`, and the Elligator map match §4.2/4.3.2/4.3.4
  term for term. The P0 above is the *protocol-layer* check §4.3.1 does not cover.
- **Constant-time MAC comparison** verified at all three sites — `OpaqueAke.java:232`,
  `OpaqueEnvelope.java:96`, `Server.java:118` — plus java-jwt 4.6.0, whose `CryptoHelper`
  was disassembled from the resolved jar to confirm it uses `MessageDigest.isEqual`. No
  `Arrays.equals`, `==`, or `.equals()` on any MAC, tag, key, or token in the audited tree.
- **Point validation** closes the invalid-curve attack on `dh2` (the one DH touching the
  long-term server key): compressed SEC1 decode derives y on-curve or fails, cofactor is 1
  for all four curves, and identity DH outputs are rejected on both AKE sides
  (`OpaqueAke.java:161-163`, `:218-220`). MAC-before-use ordering is correct — the envelope
  tag is verified *before* the recovered server public key is used for `dh2`.
- **Randomness.** Every source is `SecureRandom`; no `java.util.Random`, no `Math.random`,
  no time-derived seeding. `randomScalar` uses unbiased rejection sampling over `[1, n-1]`.
  Tokens are UUIDv4 (122 bits).
- **Thread safety.** `MessageDigest` and `Mac` created per call; no shared mutable crypto
  state; no static non-final fields in the crypto packages; no memoization of secrets.
- **Deserialization bounds** on `KE2.deserialize` and `Envelope.deserialize` are real, and
  no offset overflow is possible — every length is a suite constant.
- **Auth/JWT.** No `alg:none` or algorithm confusion (verifier built from a fixed
  `Algorithm.HMAC256`); filters fail closed and leave `SecurityContext` untouched on any
  failure; principal identity always comes from the verified claim; **no IDOR** — every
  destructive endpoint cross-checks the token subject against the body identifier
  (`:352-359`, `:379-386`, `:406-413`). Key-version handling has no downgrade path.
- **Replay.** KE3 replay is blocked by a single atomic `pendingSessionStore.remove()`, and
  the pending session is removed *before* the client MAC is verified, so a failed guess
  destroys the handshake. Recovery tokens are single-use via atomic `remove()` with TTL
  re-checked at consume — no TOCTOU against the earlier non-consuming peek.
- **CSRF-disabled premise holds** — grepping `Cookie|HttpSession|getSession` across all
  three server modules returns nothing; the JWT is read only from the `Authorization`
  header. `SECURITY.md:41-53` is accurate.
- **Body-size limits are chunked-safe in both frameworks** (Content-Length check backed by
  a bounded stream; Spring also overrides `getReader()`).
- **Error responses leak nothing** — no `e.getMessage()`, exception object, or stack trace
  reaches a client; no `printStackTrace`/`System.out`/`System.err` in scope.
- **OPRF client-IP extraction** is correct in both frameworks. **Health endpoints** expose
  only the public key and up/down. **haproxy** enforces TLS 1.3 on both frontends. **CI**
  has no `pull_request_target` and no untrusted-ref checkout; `gradle.yml:34,153` pins
  `gradle/actions` by commit SHA.
