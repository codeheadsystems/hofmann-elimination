# 6. Dependency scanning is advisory; the version floor is the gate

- **Status:** Accepted (2026-08-07). In force.
- **Decided in:** `3272150`, amended by `e443901`
- **Implements:** [`buildlogic.security-floor-conventions.gradle.kts`](../../buildSrc/src/main/kotlin/buildlogic.security-floor-conventions.gradle.kts),
  the `dependencyCheckAggregate` task, and the dependency-scan CI job
- **Related:** [ADR-0004](0004-one-build-per-checkout.md) — same principle: a check people route
  around is worse than no check.

## Context

The OWASP Dependency-Check plugin appeared nowhere, CI's `dependency-submission` was advisory, and
the Rust and TypeScript jobs had no audit step. The gap was demonstrably real rather than
theoretical: Dependabot had three open alerts sitting on `main`, all arriving transitively through
Dropwizard 5.0.2 — jetty-security 12.1.9 (high, digest authentication bypass), jetty-server 12.1.9
(medium, cross-request trailer leakage), and logback-core below 1.5.34 (low, object injection).

That is the failure mode of a post-hoc reporter: it worked, it told somebody, and nothing changed.

## Decision

Two mechanisms, with the blocking one deliberately not the scanner.

**The floor blocks.** `buildlogic.security-floor-conventions` pins the affected artifacts up to
patched versions using *constraints* rather than forces, so a later framework release still wins
and the floor removes itself once Dropwizard catches up. Whole families move together — mixing
12.1.10 `jetty-server` with 12.1.9 `jetty-http` is a combination nobody tests. Each entry records
which advisory it answers *and whether this project is actually exposed*, which is what makes it
safe to delete later.

**The scan advises.** `dependencyCheckAggregate` is deliberately not attached to `check`, and its
CI job runs `continue-on-error`. Test-only configurations are skipped: a CVE in a test harness is
not a vulnerability in anything this project publishes.

Since the job no longer blocks a merge, a red square has to mean one thing. "No `NVD_API_KEY`
configured" is a skip with a warning annotation on a *green* job; only a real finding is red. The
report artifact upload is the point of the job rather than a convenience — it is the only path by
which a finding reaches a human.

## Alternatives rejected

- **Attach the scan to `check`.** Since version 9, Dependency-Check pulls the NVD feed through an
  API that rate-limits hard without a key; a first run without one can take the better part of an
  hour. Making every local build depend on a network service with unpredictable latency has one
  predictable result: somebody disables it.
- **Make the scan a required check.** The scan depends on an external service whose availability
  and latency this repository does not control. A required check that goes red because someone
  else's API is down is a check people route around rather than fix.
- **Force resolution strategies instead of constraints.** Forcing would keep the floor in place
  after the framework caught up, silently pinning versions backwards.
- **Install `cargo-audit` via a marketplace action.** This repo pins actions by commit SHA to
  avoid trusting mutable tags, and an unpinnable action would undo that. Installed from crates.io
  instead — which leaves `cargo-audit` itself unpinned. For an advisory scanner that is arguably
  right, but it is a trade rather than a free win.

## Consequences

- **Nothing forces anyone to look.** That is the accepted cost of the job not blocking, and why
  the artifact upload and the annotation carry the weight.
- The suppression file ships empty and says why: every entry silences a finding, so each must name
  the CVE, say specifically why this project is not reachable, and say when to re-check.
  Otherwise it becomes where findings go to be forgotten, which is worse than not scanning.

## Superseded analyses

- **"The digest authentication bypass affects this project."** It does not — nothing here
  configures a digest realm, and the JWT arrives as a Bearer token. The floor was applied anyway,
  because the bundle installs into other people's applications and their auth configuration is not
  ours to assume. Recorded so the entry can be removed on the right grounds.
- **"The OWASP scan is verified working."** Not claimed. At the time of `3272150` it had not been
  executed end to end — that needs the NVD database and an API key. What was verified is that the
  plugin resolves, all four tasks register, and the workflow YAML parses with the job wired in.
  The first CI run was the real test.
- **The Gradle-side comment still said the NVD key was required** after `e443901` made the scan
  skip without one. Corrected in that commit.
