# Security TODO

Findings from the security review of **August 2026** (six-reviewer fan-out across `hofmann-rfc`,
`hofmann-server`, `hofmann-client`, both framework integrations, and the Rust/TypeScript ports).

## Status

| Section | Done | Open |
|---|---:|---:|
| **P0 Critical** | 3 | 0 |
| **P1 High** | 9 | 0 |
| Follow-ups from verifying the 3.1.0 fixes | 7 | 0 |
| **P2 Medium** | 1 | 13 |
| **P3 Low** | 1 | 10 |
| Documentation | 0 | 4 |
| Test coverage gaps | 0 | 4 |
| **Total** | **21** | **31** |

**Every P0, P1 and verification follow-up is now closed.** What remains is P2 and below.

Entries marked `[x]` carry the commit that closed them. P0/P1 shipped in **3.1.0**; the
verification follow-ups and the last P1 land after it. Everything marked `[ ]`
is outstanding.

> Several completed items carry a scope limit in their entry — what the fix does *not* cover.

---

## RFC 9497 VOPRF/POPRF — deferred items

Carried out of the August 2026 work that added modes 0x01 and 0x02 to `hofmann-rfc`. Each was
raised during cryptographic review and consciously deferred rather than missed. Recorded here so
they do not live only in a conversation.

### Open — needs a decision

- [ ] **OPAQUE ristretto255 scalar endianness.** `ByteUtils.scalarToFixedBytes` is big-endian, and
  OPAQUE uses it to serialize private keys on the ristretto255 suite, whose scalar convention is
  little-endian (`opaque/Server.java`, `HofmannBundle`, `HofmannAutoConfiguration`). Found while
  confirming the new ristretto `serializeScalar` range check had no in-tree caller to break — it
  does not, because OPAQUE never goes through `GroupSpec.serializeScalar` at all. Out of scope for
  RFC 9497 work and `OpaqueCrossImplVectorsTest` passes, so it is either consistent across the
  Java/Rust/TypeScript ports or simply not exercised for ristretto255. Unresolved either way, and
  the only substantive open question left by that review.

- [ ] **Transport-level request-size bound for batched OPRF requests.** The verifiable servers cap
  a batch at 64 elements (1024 absolute) before any curve operation, but that fires only after the
  HTTP layer has deserialized the whole body. A bound on request size belongs with the adapters.
  Documented as owed in `hofmann-rfc/OPRF.md`.

- [ ] **Phase 6: transport and ports.** HTTP endpoints for the verifiable modes,
  `docs/oprf-api.yaml`, `hofmann-client`, TypeScript, Rust, and cross-client integration tests.
  The Java core was designed not to block this — wire models are hex strings throughout — but
  none of it exists. The 3.1.0 CHANGELOG says "library addition only" for this reason.

### Accepted residuals — documented in code, no action planned

- Proof generation is not fully constant-time: `s = r - c*k` in `GenerateProof` uses `BigInteger`
  multiplication and reduction, which are variable-time in their operands, and RFC 9497 §7.4 names
  `GenerateProof` as an operation that should be constant time. Far smaller than the scalar-
  multiplication leaks already closed — operands are fixed width after the first reduction and `s`
  is published in the proof anyway — but removing it needs constant-time scalar-field arithmetic
  `BigInteger` does not offer. Stated in `DleqProver`'s javadoc and in `OPRF.md`.
- The Montgomery ladder's two-element accumulator is indexed by a secret bit and remains
  observable to a co-located cache-probing attacker. Pre-existing; documented in
  `WeierstrassGroupSpecImpl`.

### Minor test gaps — known, judged acceptable

- [ ] `GroupSpecArithmeticTest` exercises the identity-input path properly only on ristretto255.
  On the Weierstrass curves the equivalent test passes `elementSize()` zero bytes, which
  BouncyCastle rejects as a malformed encoding before the identity check is reached; the real SEC1
  identity is the single byte `0x00`. A per-suite split now covers the encoding case, but the
  identity-specific rejection is still only genuinely tested on ristretto255.
- [ ] `PoprfClientContext` does not defensively copy its `info` and `tweakedKey` arrays, though its
  lists get `List.copyOf`. Consistent with house style across the module, so noted rather than
  recommended.


> Those are deliberate and load-bearing: identifier squatting is bounded but not eliminated, and
> the rate limiter's memory is bounded but its throughput is not. Read them before assuming a
> checked box means the whole class of attack is gone.

## How to read this file

Entries record the reproduction as well as the fix, so a completed item is kept rather than
deleted — several of them exist because a *previous* checklist claimed work was done that was
not, and the analysis is what makes that checkable.

Treat this file as **a claim log to be re-verified, not as evidence**. Of the twenty-odd entries
on the February 2026 DONE list, four did not survive verification; they are the items tagged
`[was marked DONE]` below.

Findings tagged **[reproduced]** were demonstrated by executing code, not by reading it.

---

## P0: Critical — fix before the next release

All three P0 items are fixed on branch `3.1`. Retained here only as pointers; see the commits
for the full analysis and the reproduction each was verified against.

- [x] **Reject the identity element when decoding a ristretto255 point** — `71846ed`. Also
      closed a matching hole where a blind congruent to 0 mod n produced the same
      key-independent collapse, and repaired a 400→500 regression the guard introduced at
      `POST /opaque/auth/start` in both frameworks.
- [x] **Canonicalize the credential identifier at the trust boundary** — `b8e3530`. Closed the
      revocation bypass and the 8–32× rate-limit multiplier together, and removed a
      pre-existing failure mode where padding drift between recovery steps locked users out.
- [x] **Enforce a client-side floor on key-stretching parameters** — `291cbd4`. Java and
      TypeScript. The first TypeScript attempt was bypassable by omitting one JSON field
      (`NaN` comparisons are all false, so control fell through to the identity KSF); the
      strict path now has no branch to `identityKsf` at all.

---

## P1: High

- [x] **Rate-limit `POST /opaque/registration/finish` and equalize its response branches** —
      `e63db78`. Token now consumed before the existence lookup; an already-registered
      credential returns 204 without storing rather than throwing 400. Added a 25 ms floor
      mirroring `RECOVERY_VERIFY_MIN_NANOS`, because the not-exists branch performs a write the
      exists branch skips — negligible in memory, an `INSERT` against a database-backed store.
      **Squatting is NOT fixed** and rate limiting does not meaningfully mitigate it: the
      limiter is per-identifier and squatting an unused identifier costs one token, so 2000 of
      2000 identifiers were squatted in 9 ms with the default limiter installed. See the new
      P1 item below.

- [x] **Validate uploaded `RegistrationRecord` fields before storing** — `55798f2`. Also guarded changePasswordFinish, the third write path, which was missed on the first pass. Failures normalised to 400: which exception the crypto layer raises depends on the suite, not the fault. Tests run all four suites — P-256 hides Nn/Nh/Nm confusion.

- [x] **Validate the server OPRF key at supplier construction** — `bfae3a2`. Rejects keys congruent to zero mod n. Does NOT reject k >= n: those already work (scalar multiplication reduces anyway) and `openssl rand -hex 32` exceeds ristretto255's order ~94% of the time, so refusing would break live deployments. Normalised instead.

- [x] **Use a constant-time multiplier for the NIST curves** — `df4fd03`. Explicit Montgomery ladder — BouncyCastle 1.85 no longer ships one. Covers scalarMultiplyGenerator too, which carries the client's long-term key. Hamming-weight signal 17-19% -> noise; bit-length signal closed by a fixed-width rescale.

- [x] **Stop keying rate limits and DoS-sensitive stores on attacker-chosen values** — `049bbca`. PARTIAL — see the new item below. Reclaim-before-deny converts a persistent outage into a self-healing one but does not stop a live adversary. Fixed a null-keying bug that made both the OPAQUE and the pre-existing OPRF limiter global.

- [x] **Scope the Spring Boot security filter chain** — `45ff4ca`. Made conditional rather than scoped: scoping would stop the JWT filter authenticating the consumer's endpoints, which is the library's purpose.

- [x] **Register the Spring components from the auto-configuration** — `45ff4ca`. Also fixed the CORS bean, which @Import made universally present and which crashed any consumer following the documented override.

- [x] **Fail closed on unset JWT secret and OPAQUE seeds** — `d5064f0`. Both frameworks refuse to start without key material unless `allowEphemeralKeys` is set, mirroring `allowIdentityKsf`. The committed fallbacks are gone from both deployed configs, `make up` generates throwaway keys into a gitignored `.env`, and a test asserts no key material returns — those files are not compiled, so nothing else would notice.

      Where it does bite is deployment: `hofmann-demo/server/config.yml:34,35,40,45` and
      `hofmann-testserver/config/config.yml:34,35,40,45` carry working
      `${VAR:-<committed-value>}` fallbacks for the server key seed, OPRF seed, OPRF master
      key, and JWT secret, and both `Dockerfile`s `COPY` that config at line 37. An
      operator running the published image without the env vars gets a **publicly known
      HMAC signing key**.

      Do both together: emptying the demo defaults alone just trades a known key for a
      silently random one. Add an explicit `allowEphemeralKeys` / `devMode` flag mirroring
      `allowIdentityKsf`.

- [x] **Harden the release pipeline** — `6e01e27`. All actions pinned by SHA at their existing major versions, signing material scrubbed after publish, manual release gated on main-ancestry.

## Follow-ups from verifying the 3.1.0 fixes

Not from the original review — these surfaced while adversarially verifying the fixes above.
Two are scope limits on work that shipped, recorded so partial coverage is not mistaken for
completeness.

- [x] **Bound identifier squatting with an IP-dimension limiter in the adapters** — `67e3d08`. The origin limiter is on by default now that its key is aggregated to an IPv6 /64 and it is backed by a structure that cannot be filled. **Squatting itself is still not eliminated** — that needs proof of identifier ownership at the deployment layer; this bounds the rate, not the capability.

- [x] **Spring Boot flattens every error status to 401** — `45ff4ca` (3.1.0). The ERROR dispatch is now permitted, bound to the configured error path so a custom error page aimed at a protected controller cannot be reached unauthenticated.

- [x] **A junk recovery bearer token drains the recovery limiter before validation** — `67e3d08`.
      Re-keyed onto the token at `registrationFinish`, so an attacker's guesses burn their own
      bucket. **Narrower than it first read:** `recoveryStart` and `recoveryVerify` still key on
      the credential identifier, so six unauthenticated requests naming a victim still lock them
      out of those two endpoints for about a minute. Inherent to rate-limiting an account-scoped
      operation for an unauthenticated caller — before a token exists there is nothing else to key
      on — and the origin limiter bounds how fast one source can do it. See the open item below.

- [x] **Bound the rate limiter's key space** — `67e3d08`. `FixedCapacityRateLimiter` pre-allocates and hashes into existing slots, with a per-process seed so collisions cannot be computed offline. **Bounding memory does not bound volume** — enough traffic to drain every slot still denies service; what is gone is exhausting capacity far more cheaply than saturating the buckets.

- [x] **`recoveryVerify`'s 250 ms floor still amplifies across origins** — `67e3d08`. Concurrency inside the floor is capped; requests beyond the ceiling are refused rather than queued.

- [x] **Pin `context` locally instead of adopting the server's** — `67e3d08`. Both clients accept an expected context and verify the server's against it. Opt-in, since requiring it would break every existing caller.

- [x] **`OpaqueHttpClient`'s constructor still defaults to `identityKsf`** — `67e3d08`. The constructor now requires an explicit KSF.

- [ ] **Unauthenticated callers can still lock a victim out of account recovery**
      `recoveryStart` and `recoveryVerify` key their limiter on the credential identifier, which
      is right for bounding guessing against one account and wrong given the caller is
      unauthenticated: six requests naming a victim spend that victim's budget. The origin limiter
      bounds the rate per source, and moving to the non-exhaustible limiter stopped the flood
      becoming a global recovery outage — but a targeted lockout stays cheap. Closing it needs
      something an attacker cannot supply on the victim's behalf: proof-of-work on recoveryStart,
      or the email round trip that recovery ownership rests on anyway.

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

- [x] **Snapshot `supplier.get()` once in `OprfServerManager.process`** — `bfae3a2` (3.1.0). Fixed alongside the OPRF key validation, which needed the snapshot to avoid checking one key and using another.

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
- [x] **Auto-merge without a test gate** — partially addressed 2026-08-06. `auto-wolpert.yml` is
      disabled, both at the repository level and in the workflow file, after it squash-merged a
      security release into `main` without the requested human review. `main` now requires the
      `build`, `typescript` and `rust` checks before merge, with force-pushes and deletions
      blocked. **Still open:** `auto-dependabot.yml` continues to auto-approve and auto-merge, and
      runs `dependabot/fetch-metadata` while ignoring its outputs, so a major-version bump merges
      unreviewed. Branch protection now gates it on CI, but not on review.

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
