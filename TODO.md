# Security TODO

Open work from the **August 2026** security review (six-reviewer fan-out across `hofmann-rfc`,
`hofmann-server`, `hofmann-client`, both framework integrations, and the Rust/TypeScript ports),
plus the RFC 9497 VOPRF/POPRF deferrals and one finding raised while closing the rest.

**Every P0, P1, verification follow-up, RFC 9497 deferral, documentation, test-coverage and
P2 item is closed.** What remains is P3 and the findings raised while closing the rest.

## Status

| Section | Open |
|---|---:|
| New findings | 3 |
| **P3 Low** | 4 |
| **Total** | **7** |

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

## Concurrent builds — decided, not fixed in code (2026-08-08)

`:test` aborts when more than one `./gradlew` runs in the same project directory. Gradle does not
serialise `build/` outputs across concurrent invocations: one build's `clean` deletes
`build/classes/java/test/**` while another's worker loads from it, and two builds writing the same
Kryo result store truncate it. The failing read is in Gradle's own report generator
(`GenericHtmlTestReportGenerator` → `SerializableTestResultStore` → `KryoException: Buffer
underflow`), not in anything this project wrote.

**Decision: run one build per checkout, and use a separate `git worktree` to build in parallel.**
Documented in README.md under Building. A `flock` in `gradlew` was built and measured — it works
(critical-section overlap +10.9s without it, −0.5s with it) — and then reverted: `gradlew` is a
generated file, so the edit needs a guard task to survive `./gradlew wrapper`, and that is a lot of
machinery in shipped tooling for a condition that a separate checkout avoids entirely.

**The residual is that the failure does not announce itself.** It appears as an `EOFException`, a
`NoSuchFileException` on `in-progress-results-generic.bin`, or a `NoClassDefFoundError` naming a
different arbitrary class each run — which reads as a flaky test. It has already produced one
confidently wrong conclusion in this repo. If it recurs, check for a second build before
investigating anything else. `clean build` recovers; `--rerun-tasks` does not, until
`<module>/build/test-results/<task>/binary` is deleted.

**Two things that are now known rather than assumed:**

- Toggling `org.gradle.parallel` changes nothing — the concurrency is across builds, not within
  one.
- **An interrupted build does not cause this.** Three hard `SIGKILL`s to the whole process group
  mid-test, daemon included, left the next run passing every time with no corruption. Gradle
  recovers from an interrupted write on its own. An earlier version of this file claimed otherwise
  as an open finding; that was inference, not observation, and it is withdrawn.

**Do not measure this while another agent is building.** An earlier A/B here concluded a build task
made the flake three times more likely; a reviewer observed a second agent running `clean build` in
the same directory during *both* arms, so that comparison is confounded and should not be relied
on.

---

## New findings

- [ ] **`sleepUntil`'s settling phase degenerates when a branch arrives with less than the settle
      window left** — raised while closing the persistent-store enumeration oracle, and a property
      of that fix rather than of the code it replaced. `sleepUntil` ends every floor with one
      coarse sleep followed by fixed-size steps, which is what makes the floor work across the
      range that matters. But the shape is identical across branches only while the branch has more
      than `FLOOR_SETTLE_NANOS` left: past that `coarse` is non-positive, the coarse sleep is
      skipped, and the step count goes branch-dependent again — about nine steps against twenty.
      **That much is structural. It is readable in `sleepUntil` and needs no measurement.**

      Measured at a 22 ms store gap under the 25 ms floor it shows as AUC 0.82–0.84. That number is
      trustworthy in the sense that matters: noise suppresses AUC toward 0.5, so a detected 0.82 is
      real and possibly understated.

      **The comparative claim is not established, and an earlier version of this entry overstated
      it.** It read "worse than no floor", on one measurement of 0.47 for the single long sleep in
      the same band. That is a null result taken on a shared development box that is poor at fine
      timing — the same harness put that comparator at AUC 0.35 one millisecond away, at 21 ms, so
      the baseline is erratic rather than clean. "This leaks badly in that band" stands; "it is
      worse there than what it replaced" is one run against a noisy baseline and should be
      re-measured before anyone repeats it.

      The band sits inside what `AUTH_START_MIN_NANOS` already documents as broken — past ~22 ms
      the floor does not work at all, because `authStart`'s own ~2 ms is spent inside it — so no
      deployment on a sane store is exposed. It is open because nothing in the build notices:
      `AuthStartStoreTimingTest` probes 10 ms and 45 ms and steps over the band entirely.

      Closing it means either a settling phase that degrades gracefully when the branch arrives
      late, or making the floor refuse to be configured below the work it has to cover — the latter
      is probably the honest one, since a floor smaller than its own method's runtime is a
      misconfiguration rather than a tuning choice. A boundary test would have to be conditioned on
      the machine, which is why one was not added.

      **Applies to every timing figure from this work, not just this entry.** They were all taken
      on one ordinary shared development machine, and an earlier version of the code comments
      described them as coming from two — that was wrong; the spread was run-to-run variance on one
      box. Absolute offsets moved by an order of magnitude between runs of the same harness. The
      consequence has a direction: noise widens both distributions and pulls AUC toward 0.5, so the
      *null* results — "the floor closes the oracle at 1–15 ms store gaps" — are the optimistic
      ones and want re-running on a quiet host with the governor pinned and cores isolated. The
      positive results (the 3 ms one-probe distinguisher with the floor removed; this degeneracy)
      survive noise, because noise does not manufacture separation.

- [ ] **The dependency scan is configured but inert: no `NVD_API_KEY` secret** — the
      `dependency-scan` job runs on every push, goes green in about ten seconds, and scans
      nothing. OWASP Dependency-Check cannot reach the NVD feed without a key and fails rather
      than degrading, so the job skips the scan and emits a warning annotation instead. Confirmed
      on the run for PR #93: `Scan dependencies for known vulnerabilities: skipped`.

      Deliberate — the job is `continue-on-error`, and a hard failure there would be
      indistinguishable from a real finding, which would make red meaningless. But it does mean
      the gate this work added is currently doing nothing. Closing it is one action by someone
      with repository admin: request a key at
      https://nvd.nist.gov/developers/request-an-api-key and add it as the secret `NVD_API_KEY`.

      Until then the only dependency coverage is `cargo audit`, `npm audit` and the
      Dependabot alerts from `dependency-submission` — which is what the situation was before,
      minus the version floors.

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

- [ ] **CORS and header parity** — **[re-verified 2026-08-08]**. `CorsFilter` omits
      `Vary: Origin` on both non-matching early returns (only the matching path sets it) and sets
      no `Access-Control-Max-Age`; a shared cache can serve one origin's response to another.
      `SecurityHeadersFilter` sets neither `Referrer-Policy` nor `Content-Security-Policy`, and
      neither does the Spring side.

      **HSTS now has three behaviours, and the newest one is the correct one.** Dropwizard's
      `SecurityHeadersFilter` still writes it unconditionally, including over plaintext, which
      RFC 6797 §7.2 says a browser ignores. Spring writes it only when it considers the request
      secure — behind a TLS-terminating proxy, effectively never.
      `ApiDocsSecurityHeadersFilter`, added while closing the API-docs finding, writes it on
      `request.isSecure() || (trustForwardedHeaders && X-Forwarded-Proto == https)`, which is
      right in both deployments and does not let an untrusted client forge an HSTS pin. Closing
      this item means moving the other two onto that condition, not inventing a fourth.

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
