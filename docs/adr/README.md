# Architecture Decision Records

Decisions whose *reasoning* is load-bearing — where the code alone does not say why it is shaped
that way, and where changing it back would reintroduce something specific.

Each record carries two sections that are not standard ADR practice, and are the reason this
directory exists:

- **Status** — accepted, superseded, or reverted, with the date and the commit. A decision that
  was later reversed keeps its record rather than being deleted.
- **Superseded analyses** — reasoning that was recorded, acted on, and later shown wrong. This
  repository has a habit of writing down conclusions confidently and then disproving them, and the
  disproofs are more useful than the conclusions. Several of the entries below exist because a
  wrong analysis outlived its correction and misled someone months later.

## Index

| # | Decision | Status |
|---|---|---|
| [0001](0001-fixed-capacity-rate-limiting.md) | Fixed-capacity buckets for attacker-controlled rate-limit keys | Accepted 2026-08-06 |
| [0002](0002-origin-rate-limiting-on-by-default.md) | Origin rate limiting ships enabled, at 600/min per aggregated origin | Accepted 2026-08-06, supersedes the 3.0.0 opt-in default |
| [0003](0003-recovery-challenge-id-binding.md) | Recovery guessing is bound by a server-issued challenge id | Accepted 2026-08-07, amended ×3 |
| [0004](0004-one-build-per-checkout.md) | Concurrent builds are handled by an operating rule, not by a lock | Accepted 2026-08-07, supersedes a reverted `flock` |
| [0005](0005-closed-contexts-refuse-use.md) | A closed context refuses use rather than answering from zeroes | Accepted 2026-08-08 |
| [0006](0006-advisory-dependency-scanning.md) | Dependency scanning is advisory; the version floor is the gate | Accepted 2026-08-07 |
| [0007](0007-spring-security-autoconfiguration.md) | `HofmannSecurityConfig` is an `@AutoConfiguration` | Accepted 2026-08-08 |
| [0008](0008-sealed-opaque-package.md) | The OPAQUE package is folded into one and sealed in the jar | Accepted 2026-08-08 |

## Relationship to the other documents

- **`TODO.md`** holds *open* work, and says of itself that it drifts in both directions. When an
  item there closes as a decision rather than as code, it should end up here.
- **`CHANGELOG.md`** records what each release did. An ADR records why, and survives the release
  that changed it.
- **`SECURITY.md`, `RECOVERY.md`, `USAGE.md`** are operator-facing. An ADR is for whoever is about
  to change the code.

## Writing a new one

Copy the shape of an existing record: Status, Context, Decision, Alternatives rejected,
Consequences, Superseded analyses. Number sequentially; do not renumber.

**Link both ways.** The record links to the source it governs; the source carries a one-line
pointer back. A record nobody finds from the code is a record nobody reads. Grep for
`docs/adr/` to see the existing pointers.

Superseding a decision does not delete its record — add a new one, and set the old record's Status
to `Superseded by NNNN`.
