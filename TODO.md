# Security TODO

Open work from the **August 2026** security review (six-reviewer fan-out across `hofmann-rfc`,
`hofmann-server`, `hofmann-client`, both framework integrations, and the Rust/TypeScript ports),
plus the RFC 9497 VOPRF/POPRF deferrals and one finding raised while closing the rest.

**Every P0, P1, verification follow-up, RFC 9497 deferral, documentation and test-coverage item
is closed.** What remains is P2, P3 and the findings raised while closing the rest.

## Status

| Section | Open |
|---|---:|
| New findings | 3 |
| **P2 Medium** | 6 |
| **P3 Low** | 4 |
| **Total** | **13** |

Recount with `grep -c '^- \[ \]' TODO.md` after editing.

## How to read this file

Every entry here is **outstanding**. Completed entries are removed rather than checked off; the
analysis each carried lives in the commit that closed it and in this file's own history
(`git log -p -- TODO.md`). Nothing is lost, but it is no longer in front of you while you work.

Treat this file as **a claim log to be re-verified, not as evidence**. Of the twenty-odd entries
on a February 2026 DONE list, four did not survive verification. Three more entries were found
stale in the opposite direction in August 2026 — marked open when the work had already shipped.
It drifts both ways, so check the tree before trusting an entry.

Findings tagged **[reproduced]** were demonstrated by executing code, not by reading it.

> **Line numbers in these entries predate the August 2026 fixes** and many have drifted. The file
> and symbol names are reliable; the offsets are not. Grep rather than jumping to a line.

## Decisions taken (2026-08-06), all now carried out

- **ristretto255 scalar endianness** — investigated. The ports did **not** agree: Java read every
  suite's private key big-endian while Rust and TypeScript both use ristretto255's native
  little-endian. Closed by routing OPAQUE through `GroupSpec.serializeScalar`/`deserializeScalar`,
  which is per-suite canonical, rather than by picking a side. `OpaqueCrossImplVectorsTest` had
  been reversing the bytes to compensate; that reversal is gone, so it is now a real
  cross-implementation check.
- **Phase 6** — Java HTTP endpoints, `docs/oprf-api.yaml` and the transport request-size bound,
  done. `hofmann-client`, TypeScript and Rust remain deferred by design, and are the obvious next
  scope if a client needs the verifiable modes.
- **Recovery lockout** — closed with the challenge id. `RecoveryChallenger` gained
  `bindsChallengeId()` plus challenge-id overloads; a challenger that opts in gets the
  verification limiter keyed on a value only the account owner receives. Deployments that do not
  opt in keep the old behaviour and the residual, documented on the interface and in
  `RECOVERY.md`.

---

## RFC 9497 VOPRF/POPRF — accepted residuals

Carried out of the work that added modes 0x01 and 0x02. The deferred *items* are closed; these
two are documented in code with no action planned.

- Proof generation is not fully constant-time: `s = r - c*k` in `GenerateProof` uses `BigInteger`
  multiplication and reduction, which are variable-time in their operands, and RFC 9497 §7.4 names
  `GenerateProof` as an operation that should be constant time. Far smaller than the scalar-
  multiplication leaks already closed — operands are fixed width after the first reduction and `s`
  is published in the proof anyway — but removing it needs constant-time scalar-field arithmetic
  `BigInteger` does not offer. Stated in `DleqProver`'s javadoc and in `OPRF.md`.
- The Montgomery ladder's two-element accumulator is indexed by a secret bit and remains
  observable to a co-located cache-probing attacker. Pre-existing; documented in
  `WeierstrassGroupSpecImpl`.

---

## New findings

- [ ] **Decide whether the origin rate limiter should default on when recovery is enabled.**
      `originRateLimitConfig()` returns null by default, and the comment there explains why: as a
      blanket default it does more harm than good behind NAT and CGNAT. The consequence surfaced
      while closing the recovery lockout — it is the only global bound on `recoveryStart`, which is
      unauthenticated and whose own limiter keys on the credential identifier, so an attacker
      varying the identifier is unbounded by default. Every capacity policy in
      `InMemoryRecoveryChallengeStore` is load-bearing because of that, and each of those policies
      has already been got wrong once.

      Defaulting it on *when recovery is configured* would make flooding expensive at the source
      and stop the store's eviction rules carrying the weight. Deliberately not done as part of the
      VOPRF/POPRF work: it changes behaviour for every deployment, including those not using
      recovery at all, and belongs to whoever owns that trade-off rather than arriving inside a PR
      about something else.

- [ ] **`:test` intermittently aborts on Gradle's own result bookkeeping** — **[reproduced]**.
      Tasks fail with `java.io.EOFException` or
      `NoSuchFileException: build/test-results/test/binary/in-progress-results-generic.bin`,
      having produced results for only some test classes. The tests themselves pass: the same
      commit passes on a retry, and three consecutive `clean build` runs gave 1467 tests, 0
      failures. It is not module-specific — `hofmann-server`, `hofmann-integration-tests` and
      `hofmann-springboot` have all hit it — and it gets more frequent as the suite grows, which
      fits a race on Gradle's scratch files rather than anything in the code.

      **This is worse than an annoyance because of how it fails.** A task that aborts before
      running reports the same way as one that had no tests, so a green build is not by itself
      evidence the suite ran; verifying means counting result files per module against test
      sources. It has already produced two false diagnoses across two sessions — a reviewer
      reported a breaking change that had already been reverted, and this session briefly
      concluded from one sample per branch that a code change was at fault when it was not.

      `clean build` is markedly more reliable than `--rerun-tasks`; prefer it. Closing this
      probably means a Gradle or plugin upgrade, or finding what races on that directory.

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

---

---

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
