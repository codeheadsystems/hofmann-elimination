# 4. Concurrent builds are handled by an operating rule, not by a lock

- **Status:** Accepted (2026-08-07). In force. Supersedes the `flock` in `gradlew`, which was
  built, measured, and reverted the same day.
- **Decided in:** `0143bc8`, reverting `72f3e40` and `49f3f7d`
- **Implements:** [`README.md` § Building](../../README.md),
  [`TODO.md` § Concurrent builds](../../TODO.md). No code.
- **Related:** [ADR-0006](0006-advisory-dependency-scanning.md), on the same question of what a
  build is allowed to cost the people running it.

## Context

`:test` aborts when more than one `./gradlew` runs in the same project directory. Gradle does not
serialise `build/` outputs across concurrent invocations: one build's `clean` deletes
`build/classes/java/test/**` while another's worker loads from it, and two builds writing the same
Kryo result store truncate it. The failing read is in Gradle's own report generator, not in
anything this project wrote.

The condition is real and was reproduced. What makes it expensive is that it does not announce
itself — it surfaces as an `EOFException`, a `NoSuchFileException` on
`in-progress-results-generic.bin`, or a `NoClassDefFoundError` naming a different arbitrary class
each run. It reads as a flaky test, and it has already produced one confidently wrong conclusion
in this repository.

## Decision

**Run one Gradle build at a time per checkout; use a separate `git worktree` to build in
parallel.** The contention is per directory, so separate checkouts do not interact.

The rule is written in `README.md` under Building, together with what the failure looks like, so
that recognising it — which is most of the fix — does not depend on having read this ADR.

## Alternatives rejected

- **An exclusive `flock` in `gradlew` before the JVM exec.** Built and measured: it worked.
  Critical-section overlap was +10.9s without it and −0.5s with it, with the second build waiting
  11.1s against the first's 11.6s runtime. Reverted anyway, on the judgement that the machinery
  outweighed what it bought — see Consequences.
- **Taking the lock in `settings.gradle.kts`.** Twice wrong: by the time settings is evaluated the
  damage is already possible, and a configuration-cache hit skips the configuration phase
  entirely, so the lock would not be taken on the runs that matter most.
- **Toggling `org.gradle.parallel`.** Changes nothing. The concurrency is across builds, not
  within one.

## Consequences

- The protection is a convention, so it can be violated. The residual is stated rather than
  implied: if the symptoms above recur, check for a second build before investigating anything
  else. `clean build` recovers; `--rerun-tasks` does not, until
  `<module>/build/test-results/<task>/binary` is deleted.
- Nothing is added to shipped tooling. `gradlew` is a generated file — `./gradlew wrapper`
  rewrites it and drops any hand-edit — so keeping a lock alive needs a guard task, and the guard
  needs a home. The reverted version was 23 lines of shell in that generated file, over half of
  them `echo`, two of which fired on every build on a machine without `flock`: noise a contributor
  deletes on day one, leaving the guard task failing and the block gone.

## Superseded analyses

- **"A build killed mid-write truncates the Kryo result store and poisons the next run."** Written
  into `TODO.md` as an open finding on `72f3e40`. It was a guess — plausible, mechanically
  reasonable, and untested. Three hard `SIGKILL`s to the whole process group mid-test, daemon
  included, left the next run passing every time with zero corruption signatures. Gradle recovers
  from an interrupted write on its own. Withdrawn in `49f3f7d`.
  The self-poisoning in the *original* finding was real, but it was a consequence of concurrent
  corruption, not of interruption; the symptom was carried across to a different cause without
  checking.
- **"A build task makes the flake three times more likely."** An A/B measurement that a reviewer
  showed was confounded: a second agent was running `clean build` in the same directory during
  *both* arms. Do not measure this while another agent is building.
- **The first guard was over-built and partly vacuous.** Four JUnit tests and sixty lines of prose
  to grep a shell script, living in a cryptography module, with an input declaration that re-ran
  ~1,400 crypto tests on every `gradlew` edit. Two of its four assertions were near-useless.
  Reduced to a single `verifyBuildLock` task in `49f3f7d` — then removed entirely with the lock.
- **A guard that did not run at all.** `GradlewBuildLockTest` read `gradlew`, but `gradlew` was
  not a declared input to the test task, so deleting the entire lock block left the test reporting
  green. A guard that only runs when something unrelated changed is not a guard.
