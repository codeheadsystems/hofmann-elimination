# 3. Recovery guessing is bound by a server-issued challenge id

- **Status:** Accepted (2026-08-07), amended three times the same day. In force.
- **Decided in:** `057147e`, amended by `94fe756`, `e04c2ca`, `5063673`
- **Implements:** [`HofmannOpaqueServerManager.recoveryVerifyBinding`](../../hofmann-server/src/main/java/com/codeheadsystems/hofmann/server/manager/HofmannOpaqueServerManager.java),
  [`RecoveryChallenger`](../../hofmann-server/src/main/java/com/codeheadsystems/hofmann/server/recovery/RecoveryChallenger.java),
  [`InMemoryRecoveryChallengeStore`](../../hofmann-server/src/main/java/com/codeheadsystems/hofmann/server/store/InMemoryRecoveryChallengeStore.java)
- **Related:** [ADR-0001](0001-fixed-capacity-rate-limiting.md), [ADR-0002](0002-origin-rate-limiting-on-by-default.md).
  User-facing guidance lives in [`RECOVERY.md`](../../RECOVERY.md).

## Context

`recoveryStart` and `recoveryVerify` are unauthenticated, and their limiter keyed on the
credential identifier — a value the caller supplies and an attacker knows. A handful of requests
naming a victim spent that victim's budget and stopped them completing a recovery they had
legitimately started. On the one endpoint whose purpose is rescuing an account the user has
already lost access to.

This cannot be fixed by rate-limiting differently. Before a challenge exists there is nothing to
key on that an attacker cannot also supply.

## Decision

`recoveryStart` generates a challenge id, stores it against the credential identifier, and hands
it to the `RecoveryChallenger` for out-of-band delivery. The verification limiter keys on that id
**only when this server issued it for the credential the request names**. Anything else — absent,
unknown, expired, or issued for someone else — charges the credential identifier.

An id issued for a *different* credential is refused outright before `verifyResponse` runs,
metered first so the refusal is not a free path, and inside the same timing floor as a wrong code
so the two are not distinguishable.

The two endpoints draw from separate buckets. Without that, a flood of starts would exhaust the
budget verification needs and the challenge id would have bought nothing.

The store evicts rather than refusing at capacity: at the global cap it takes from whichever
identifier holds the most, and at the per-identifier cap it takes that identifier's own oldest
entry. The per-identifier cap is *derived* — the number of starts the limiter permits within one
TTL (6/min × 600s = 60) — not chosen.

## Alternatives rejected

- **A `bindsChallengeId()` capability flag.** The original design, and a trap: a challenger that
  could not deliver the id would have silently kept the full residual while looking configured.
  The server now records and checks the id regardless of what the challenger does with it; a
  challenger that cannot deliver it simply gets no benefit from the second half of the check.
- **Charging the id's own bucket when it was issued for another credential** — "it belongs to
  whoever holds it, let them spend their own budget". This inverted what was being metered. See
  Superseded analyses.
- **Refusing to record at store capacity.** See Superseded analyses.
- **Charging both buckets on the matched path.** Would close the attribution oracle below, by
  reintroducing the lockout this ADR exists to remove.

## Consequences

- An attacker naming a victim spends their own budget. Spending the victim's costs a 122-bit
  guess.
- **`recoveryStart` remains identifier-keyed**, so an attacker can still stop a victim requesting
  a *new* challenge. That is the price of letting an unauthenticated caller trigger an email.
- **An accepted attribution oracle.** Because only a matching id charges the challenge bucket, a
  holder of a leaked id can drain `verify:<candidate>` and read 429-versus-401 to learn whose id
  it is. The distinguisher *is* the protection. It costs a drained candidate bucket per probe, for
  identity disclosure only, with no speedup to guessing the code.
- On a multi-node deployment with an unshared store the server's own check cannot fire, because
  the id was never recorded on the node that sees the verify. The check is defence in depth; the
  challenger's binding is the load-bearing half.

## Superseded analyses

- **"A genuine id belongs to whoever holds it, so charge their bucket."** Wrong, and a regression
  against *both* configurations it replaced. What is metered is a guess against the *named*
  credential's challenge, so the budget must attach to the credential under attack. An attacker
  recovers their own account, keeps the id, points it at a victim, and refreshes the meter at
  will. The tell was that both branches of the comparison returned the same expression.
- **"Refusing to record at capacity is safer than evicting."** Backwards. Refusing did to *every*
  recovery started after a flood what eviction does to one, signalled only by a `WARN`.
- **The per-identifier cap, as first written, restored the targeted lockout** it was added to
  prevent — refuse-at-capacity reintroduced one scope down, and cheaper than the original.
- **Global oldest-first eviction was targetable**: an attacker spread across a few hundred
  identifiers could evict a victim's in-flight challenge.
- **"Document the eviction window."** The suggested fix for the residual in `e04c2ca`, where a
  sustained flood evicted forward past the victim's newest entry in ~5.3 minutes. Removing the
  window was cheaper than documenting it, so the cap was derived from the limiter instead.
- **`RecoveryChallenger`'s javadoc promised the server had already checked the id against the
  credential.** It had not, and an implementer trusting that sentence would have skipped the check
  that stops the attack.
