# Security TODO

Open work from the **August 2026** security review (six-reviewer fan-out across `hofmann-rfc`,
`hofmann-server`, `hofmann-client`, both framework integrations, and the Rust/TypeScript ports),
plus the RFC 9497 VOPRF/POPRF deferrals and one finding raised while closing the rest.

**Every P0, P1, verification follow-up, RFC 9497 deferral, documentation, test-coverage and
P2 item is closed.** What remains is P3 and the findings raised while closing the rest.

## Status

| Section | Open |
|---|---:|
| New findings | 5 |
| **P3 Low** | 4 |
| **Total** | **9** |

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

- [ ] **`:test` aborts when more than one `./gradlew` runs in the same project directory** —
      **[root cause identified]**. Symptoms: `java.io.EOFException`, or `NoSuchFileException` on
      `build/test-results/test/binary/in-progress-results-generic.bin`, or `NoClassDefFoundError`
      on arbitrary and different classes each run, with results written for only some classes or
      none. Gradle 9.6.1.

      **Cause, from a review that caught it happening.** Gradle does not serialise `build/` outputs
      across concurrent invocations on one directory. One build's `clean` deletes
      `build/classes/java/test/**` while another's worker is loading from it, and two builds
      writing the same Kryo result store truncate it — the read that fails is in Gradle's own
      report generator (`GenericHtmlTestReportGenerator` → `SerializableTestResultStore` →
      `KryoException: Buffer underflow`), not in anything this project wrote. It self-poisons: a
      truncated store makes the *next* run fail in under a second via
      `Test.getPreviousFailedTestClasses`, before any test executes, until
      `build/test-results/<task>/binary` is deleted. That is why `--rerun-tasks` stays broken
      where `clean build` recovers, and why toggling `org.gradle.parallel` changed nothing — the
      concurrency is across builds, not within one.

      **Do not measure this while another agent is building.** An earlier A/B in this repo
      concluded a build task made the flake three times more likely; a reviewer observed a second
      agent running `clean build` in the same directory during *both* arms, so that comparison is
      confounded in an unknown direction and should not be relied on.

      A `verifyTestsRan` task was tried and reverted for an unrelated and still-valid reason: the
      abort always fails the task, so a green build was never ambiguous. The ambiguity is only in
      reading result artifacts after the fact — when comparing runs, count result files per module
      against concrete test classes rather than trusting a summary.

      Closing this means serialising builds per directory, or giving each agent its own checkout.

- [ ] **The Spring Security escape hatch documented on `HofmannSecurityConfig` does not work** —
      **[reproduced]**. `HofmannSecurityConfig.java:51-66` tells a consumer they can supply their
      own `SecurityFilterChain` and the library's will back off, via
      `@ConditionalOnMissingBean(SecurityFilterChain.class)`. Declaring one the ordinary way — a
      `@Bean` on the `@SpringBootApplication` class — does **not** make it back off: the
      application fails to start with `UnreachableFilterChainException`, scoped or unscoped,
      unless the consumer also adds `@Order` below `LOWEST_PRECEDENCE - 5`, which the docs do not
      mention.

      `AutoConfigurationRegistrationTest:94` passes and does not catch this, because
      `ApplicationContextRunner.withUserConfiguration` registers beans differently from a real
      application. That makes the test worse than absent — it is evidence for a claim it does not
      actually check.

      Pre-existing; found while closing the API-docs finding. Either fix the ordering so the
      documented approach works, or document the `@Order` requirement and give the test a real
      application context.

- [ ] **The `...opaque.internal` package re-exposes every capability just made package-private** —
      **[reproduced]**. `Client` and `Server`'s five `*Deterministic` methods are package-private,
      but the same capabilities are public one package over and reachable with no reflection:
      `OpaqueCredentials.createRegistrationRequestWithBlind` and `finalizeRegistrationWithNonce`
      are `public static` with identical bodies, `OpaqueAke.generateKE2Deterministic` is the exact
      call the removed wrapper made, and `OpaqueAke.generateKE2` takes `maskingNonce` and
      `serverAkeKeySeed` as ordinary parameters — so it is invisible to
      `DeterministicApiVisibilityTest`'s name filter by construction. The `ClientAuthState` /
      `ClientRegistrationState` canonical constructors are public, which makes reassembling a
      fixed-blind KE1 a three-liner.

      A reviewer reconstructed all five capabilities from `package com.example.consumer` using
      public API only, including a full replay. Separately, package-private is defeated by a split
      package: there is no `module-info.java` and no sealed-jar manifest, so a class placed in
      `com.codeheadsystems.rfc.opaque` in another module compiles against the package-private
      methods.

      The narrower change is still worth having — it removes the hazard from the two classes a
      caller actually types — but it is not a boundary and the code no longer claims to be one.
      Closing it means either making the `internal` entry points package-private with a bridge, or
      shipping a `module-info.java` that does not export `...opaque.internal`. The latter also
      closes the split-package route. `OpaqueTestConfigs` was moved to its own package so a
      `module-info` is not blocked by a package split across the main and fixtures jars.

- [ ] **`generateKE2ForRecordOrFake` does not close the enumeration oracle on a persistent
      `CredentialStore`** — the timing equalisation covers the protocol work, and against
      `InMemoryCredentialStore` registered and unregistered are indistinguishable (AUC 0.5015 over
      18,000 interleaved samples). But the JDBC- or Redis-backed store the documentation
      recommends for production answers a hit and a miss at measurably different speeds, and that
      signal is larger and more reliable than the ~130 µs the equalisation closed. Documented on
      the method; closing it means the store answering in constant time, which is a
      store-implementation concern this library does not control.

- [ ] **CVSS-unscored advisories pass the dependency gate** — `dependencyCheckAggregate` fails on
      `failBuildOnCVSS = 4.0`, but an advisory with no CVSS score at all is estimated rather than
      scored, and the logback `HardenedObjectInputStream` issue that motivated this work estimates
      to roughly 3.9 — below any threshold that is not zero. Dependabot caught it because it
      reports at every severity. So the gate and the reporter genuinely do different jobs and
      both are needed; the gate is not a replacement.

      Closing this means either reporting unscored findings separately without failing, or
      pairing the gate with a job that diffs open Dependabot alerts against a known-accepted list.

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
