# Security TODO

Findings from the security review of **August 2026** (six-reviewer fan-out across `hofmann-rfc`,
`hofmann-server`, `hofmann-client`, both framework integrations, and the Rust/TypeScript ports).

## Status

| Section | Done | Open |
|---|---:|---:|
| **P0 Critical** | 3 | 0 |
| **P1 High** | 9 | 0 |
| Follow-ups from verifying the 3.1.0 fixes | 7 | 1 |
| RFC 9497 VOPRF/POPRF deferred items | 1 | 4 |
| New findings (August 2026) | 0 | 1 |
| **P2 Medium** | 8 | 6 |
| **P3 Low** | 7 | 4 |
| Documentation | 0 | 4 |
| Test coverage gaps | 0 | 4 |
| **Total** | **35** | **24** |

**Every P0 and P1 is closed.** One verification follow-up remains open — the targeted
account-recovery lockout — along with the RFC 9497 deferrals, P2 and below.

> The table above previously read 31 open against 37 unchecked boxes. Two things were wrong:
> the RFC 9497 section was appended without ever being added to the table, and the follow-ups
> row claimed 0 open while the recovery-lockout item was unchecked. Both are corrected here.
> Recount with `grep -c '^- \[ \]' TODO.md` when editing this file.

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

> **Decisions taken 2026-08-06.** Endianness: investigate the Java/Rust/TypeScript ports first
> and only then choose between documenting the convention and changing it — no code change until
> we know whether they actually agree. Phase 6: Java HTTP endpoints, `docs/oprf-api.yaml` and the
> transport-level request-size bound only; the `hofmann-client`, TypeScript and Rust ports stay
> deferred. Recovery lockout (in the follow-ups section): close it with the email round trip,
> which makes it a documented deployment requirement rather than shipped library code.

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

- [x] `GroupSpecArithmeticTest` exercises the identity-input path properly only on ristretto255.
  **Resolved by restating the property rather than by adding a test.** Now that
  `deserializePoint` requires a canonical compressed encoding, the Weierstrass curves have no
  identity input encoding left to reject: SEC1 spells the identity `0x00`, a single byte, which
  the length check refuses, and no `elementSize()`-byte compressed string decodes to infinity. So
  the identity-specific rejection is *correctly* only testable on ristretto255, and the
  Weierstrass test asserts the rejection that does happen. The `isInfinity()` guard inside
  `deserializePoint` is now defence-in-depth against a future reordering rather than a live path,
  and says so.
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

      **Decided 2026-08-06: the email round trip**, not proof-of-work. The limiter key becomes
      something only the account owner can produce, which actually closes it rather than pricing
      it. The consequence is that the library cannot close this on its own — it has no way to
      send mail — so the deliverable is a documented requirement on the `RecoveryChallenger`
      integration plus whatever key material the round trip yields, and the residual stays real
      for any deployment that does not implement it. Still open until that is written and the
      keying change lands.

---

## New findings (August 2026, while closing the items below)

- [ ] **The OPRF seed is Nh bytes in the spec and 32 bytes in practice** — **[reproduced]**.
      RFC 9807 §6.3 specifies an `Nh`-byte OPRF seed. `hofmann-integration-tests`'
      `application.yml` configures a 32-byte `oprf-seed-hex`, which is `Nh` only on P-256; on
      P-384 it is short by 16 bytes and on P-521/ristretto255 by 32. The demo and test-server
      configs are the same shape. Found by adding a seed-length check to `Server`'s constructor,
      which took down every suite except P-256; the check was removed rather than the configs
      changed, because refusing would break running deployments at startup.

      **There is a real consequence, and it is not the one first written here.** `oprfSeed` is
      consumed in exactly one shape — as the PRK to HKDF-Expand in `OpaqueOprf.deriveOprfKey`
      (and in `Server.createFakeRecord`), whose output seeds `deriveKeyPair`. The credential
      identifier is public, so **the entire family of per-credential OPRF keys carries at most
      H(oprfSeed) bits of entropy**, whatever the group order. At 32 bytes that is 256 bits:
      no reduction on P-256 (n≈2^256) or ristretto255 (n≈2^252), but on **P-384 and P-521 the
      effective key space is capped at 2^256 instead of the group order**.

      Safe because 256 bits is unreachable — *not* because "the expansion accepts any length",
      which is true and irrelevant. The distinction matters: the reasoning as first stated would
      license a 16-byte seed, which is a different question. Closing this means widening the
      configured seeds per suite, or stating the bound in `SECURITY.md` so the deployment choice
      is an informed one.

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

- [x] **Stop retaining the OPAQUE session key server-side as a `String`** — `SessionData` lost
      the component entirely; nothing ever read it back, since `JwtManager.verify` needs only the
      subject and jti. That removes the unzeroable `String`, the record `toString()` that
      rendered it in full, and the reason to hold it at all. `JwtManager.issueToken(String,
      String)` is deprecated and discards its second argument; `authFinish` now zeroes the raw
      `byte[]` in a `finally`. The base64 form still reaches the client in `AuthFinishResponse`,
      which the protocol requires — the server simply no longer keeps a copy. Original finding
      follows.
      —
      `HofmannOpaqueServerManager.java:591-593` → `JwtManager.java:87` →
      `SessionData.java:13-17`. `String` cannot be zeroed, the source `byte[]` in
      `ServerAuthState` is never wiped, and `SessionData` is a record so its auto-generated
      `toString()` renders the base64 session key in full. `JwtManager.verify` reads only
      subject and jti — the session key is not needed at all.

- [x] **`InMemorySessionStore` is unbounded with no reaper** — entries were evicted only
      lazily inside `load(jti)`, i.e. only if that exact token was presented again, so a client
      that authenticated and discarded its token left a `SessionData` resident forever. Now
      mirrors the sibling stores: `DEFAULT_MAX_SESSIONS` (50,000) with reclaim-before-deny, and
      a daemon `session-reaper` sweeping every 60s against each entry's own `expiresAt`. The
      store needed a lifecycle hook to own a thread, so `SessionStore` gained a
      `default shutdown()` and `HofmannOpaqueServerManager.shutdown()` now reaches it through
      `JwtManager`. **Bounding memory does not bound volume**, same caveat as the rate limiter:
      at capacity with nothing expired, a client that has completed a valid handshake is
      refused its token.

- [x] **`CredentialStore` exposes no atomic primitive, so the takeover guard cannot be made
      safe** — added `storeIfAbsent(byte[], RegistrationRecord, int)`, overridden atomically in
      `InMemoryCredentialStore` via `putIfAbsent`, and used it for the takeover guard in
      `registrationFinish` so the check and the write are one operation. The no-oracle behaviour
      is preserved: an already-registered identifier still returns normally without storing.
      The delete-then-store pairs in the recovery branch and `changePasswordFinish` are gone
      rather than wrapped in a transaction — `store()` is contractually an upsert, so replacing
      in one operation removes the window *and* the failure mode where a crash between the two
      steps left the account permanently unregistered.
      **Scope limit:** the interface default for `storeIfAbsent` is deliberately the same
      check-then-act it replaces, because a `default` that threw would break every existing
      implementer at runtime. It is documented as non-atomic and as requiring an override
      (`INSERT ... ON CONFLICT DO NOTHING` and equivalents). A third-party store that does not
      override still has the race.

- [x] **`InMemorySessionStore` revoke/store race** — `store()` put then indexed;
      `revokeByCredentialIdentifier()` removed the index then drained it. A concurrent `store()`
      that read the set before the remove and added after the drain left a jti live in `store`
      but orphaned from the index, surviving that revocation and **every future one**. Both maps
      are now updated inside a `compute` on `credentialToJtis`, so all operations on one
      credential are serialised by that map's bin lock. **[reproduced]** against the pre-fix
      class, but only at ~50M `store()` calls across 32 threads for two orphans — the window is
      two instructions wide and only a storer already holding the set can be caught. The
      committed test (`InMemorySessionStoreConcurrencyTest`) therefore guards the invariant
      rather than reproducing the race, and says so; it passes against the pre-fix code.

- [x] **Apply the field-length cap to all request models** — the cap and the decode helper both
      moved to a new package-private `WireFields`, and all seven request models plus the two
      response models now route through it, so it cannot be present on some paths and absent on
      others. Also covers two fields that were never base64-decoded and so had no cap at all:
      `AuthFinishRequest.sessionToken` (a pending-session store key) and
      `RecoveryVerifyRequest.challengeResponse` (handed to a `RecoveryChallenger`).
      `CredentialIdentifiers` reads the constant rather than restating it.
      **Scope limit: 4096 was not tightened.** It is generous for a value retained as a map key
      across four limiters, but identifiers are application-defined and a lower bound would
      reject deployments working today. Documented in `WireFields` as a bound a deployment
      should narrow at its own trust boundary.

- [x] **Enforce canonical point encodings** — `WeierstrassGroupSpecImpl.deserializePoint` now
      requires exactly `elementSize()` bytes with a `0x02`/`0x03` prefix before BouncyCastle's
      `decodePoint` sees them. The length check already existed in `validateElement`, but only
      the verifiable modes call that; the base-mode OPRF and OPAQUE reach the group through
      `scalarMultiply`, so they were unprotected. All RFC 9497/9807/9380 vectors and the
      cross-implementation vectors still pass, so this is not an interop change.
      Raises `IllegalArgumentException`, not `SecurityException`, so the adapters answer 400
      rather than issuing an authentication challenge on an endpoint where the caller has no
      credentials to correct.
      **Consequence worth knowing:** the SEC1 identity is the single byte `0x00`, so it is now
      refused as a malformed encoding and `deserializePoint`'s `isInfinity()` guard is
      unreachable on the Weierstrass curves. Rejection is unchanged; the reason reported is.

- [x] **Snapshot `supplier.get()` once in `OprfServerManager.process`** — `bfae3a2` (3.1.0). Fixed alongside the OPRF key validation, which needed the snapshot to avoid checking one key and using another.

- [x] **Range-check `Ristretto255GroupSpec.serializeScalar`** — already closed by the RFC 9497
      VOPRF/POPRF work; the check is at `Ristretto255GroupSpec:161-167` with the reasoning in
      its javadoc. This entry was stale, not outstanding. Verified against the current tree
      rather than taken on trust — which is the point of the "claim log, not evidence" note at
      the top of this file, and it cuts both ways.

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

- [x] **Records with secret fields auto-generate leaking `toString()`** — redacting overrides
      added to `ServerProcessorDetail` (masterKey) and `ClientHashingContext` (blindingFactor and
      input). **Not addressed:** `ServerProcessorDetail` is still `Serializable`, so the same
      field is reachable through any serialization sink; removing the interface is a breaking
      API change. Original finding follows.
      —
      `ServerProcessorDetail.java:9` holds `BigInteger masterKey`, and `BigInteger` renders
      as its **full decimal value** (unlike `byte[]`, which renders as an identity hash —
      which is why `JwtKeyDetail` and `ByteKey` are safe). One
      `log.info("detail={}", supplier.get())` — the pattern already used at
      `OprfResource.java:81` and `HofmannOprfClientManager.java:75` — writes the long-term
      OPRF master key to the log. It is also `Serializable`. Same shape at
      `ClientHashingContext.java:12` (blinding factor). No call site triggers it today; add
      explicit `toString()` overrides before one does.
- [x] **Token and PII logging** — `InMemoryPendingSessionStore` logs the credential identifier
      instead of the raw session token, matching the policy `InMemoryRecoveryTokenStore` already
      spells out; `authFinish` no longer logs the token at all; and the recovery re-registration
      line moved from INFO to DEBUG so an email address is not written to the default-level log.
      Original finding follows.
      — `HofmannOpaqueServerManager.java:582` and
      `InMemoryPendingSessionStore.java:85` log the pending session token at DEBUG, which
      contradicts the policy `InMemoryRecoveryTokenStore.java:75-78` spells out for the
      structurally equivalent recovery token. `:318` logs the credential identifier —
      usually an email — at INFO.
- [x] **`SecurityException` from point validation escapes as HTTP 500** — verified against the
      current tree: every endpoint that can raise it already catches it, so the original finding
      had been closed by earlier work and this entry was stale. Two things were genuinely fixed
      here. The exception-type sprawl the entry's second half describes is narrower now, because
      malformed group-element encodings raise `IllegalArgumentException` from the canonical-
      encoding check rather than `SecurityException` from further in — one type, one status, for
      the whole class of malformed element. And `authFinish` gained an `IllegalStateException`
      → 503 catch in both adapters: bounding the session store means issuing a token can now be
      refused *after* a client has completed a valid handshake, which without the catch would
      have been a 500 introduced by this very batch of work.
      **Still open:** `/recovery/start` catches no `SecurityException`, so a
      `RecoveryChallenger` implementation that raises one returns 500. Consumer-supplied code,
      so arguably theirs to handle, but the other endpoints normalise it. Original finding
      follows.
      — `OpaqueResource.java:265-279` catches `RateLimitExceededException`,
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
- [ ] **JWT hardening — PARTIAL.** The minimum secret length is done:
      `JwtManager.MIN_SIGNING_KEY_BYTES = 32` is enforced at construction for both the signing
      key and the rotation previous key, per RFC 8725 §3.5. **Still open:** no `aud` claim is
      issued or verified, and `revoke(jti)` is still called from no endpoint, so there is no
      logout. Both need config plumbing and an endpoint across two framework integrations rather
      than a library-local change. Note the key-length check runs once at construction, so a
      rotation that introduces a short key is not caught. Original finding follows.
      — no minimum secret length (`jwtSecretHex: "00"` yields a 1-byte
      HMAC key), no `aud` claim issued or verified (two deployments sharing the default
      `hofmann` issuer would cross-accept tokens), and `revoke(jti)` is never called from
      any endpoint, so there is no logout — a stolen JWT lives its full 3600 s TTL.
- [x] **Recovery token is consumed before the identifier is checked** — now peek, compare,
      then remove. Single-use is still enforced by `remove()` being atomic rather than by the
      peek: two concurrent finishes both pass the comparison but only one `remove()` returns a
      value, and the loser is rejected. Original finding follows.
      —
      `HofmannOpaqueServerManager.java:313-317` calls `remove(bearerToken)` and only then
      compares `credId`. Anyone who observes a token can invalidate it by replaying it with
      a wrong identifier, forcing the user to restart recovery. Peek, compare, then remove.
- [x] **Deserialization strictness** — all four parts. `KE2.deserialize` now requires an exact
      length rather than a lower bound (every field is a suite constant, so trailing bytes were
      being silently dropped); `Server`'s constructor validates its key material — non-null, the
      private key not congruent to 0 mod n, and the public key equal to the point the private key
      derives; `hkdfExpand` enforces RFC 5869's `len <= 255*Nh`, beyond which the single-octet
      counter wraps and silently repeats blocks; `ExpandMessageXmd` rejects an empty DST per
      RFC 9380 §3.1.
      **Not done, deliberately:** `Server` does not check the OPRF seed length against `Nh`. See
      the new finding above — the configured seeds are 32 bytes and short on three of the four
      suites, and enforcing it took every non-P-256 suite down at startup. Original finding
      follows.
      — `KE2.deserialize` (`:26`) tests `length <` rather
      than `!=`, so trailing bytes parse and are silently dropped. No production caller
      today. `Server`'s constructor (`:38-46`) validates no key material — no range check
      on the private key, no check that the public key is the matching point. `hkdfExpand`
      (`OpaqueCipherSuite.java:175-190`) has no `len <= 255*Nh` guard.
      `ExpandMessageXmd:139-157` accepts an empty DST, which RFC 9380 §3.1 forbids.
- [x] **API footguns in the hash-to-curve layer** — `HashToCurve.DEFAULT_DST` is renamed
      `SECP256K1_XMD_SHA256_SSWU_RO_DST`, with the old name kept as a deprecated alias, so the
      value no longer presents a secp256k1 tag as a default for a class that also serves
      P-256/384/521. `OprfCipherSuite`'s four DST accessors return `.clone()` rather than the
      live arrays from process-wide statics. Original finding follows.
      — `HashToCurve.DEFAULT_DST` (`:28`) is a
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
