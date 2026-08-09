# 2. Origin rate limiting ships enabled, at 600/min per aggregated origin

- **Status:** Accepted (2026-08-06), superseding the opt-in default taken in 3.0.0. In force.
- **Decided in:** `67e3d08`
- **Implements:** [`RateLimitConfigSupplier.originRateLimitConfig()`](../../hofmann-server/src/main/java/com/codeheadsystems/hofmann/server/ratelimit/RateLimitConfigSupplier.java),
  [`ClientIpResolver`](../../hofmann-server/src/main/java/com/codeheadsystems/hofmann/server/ratelimit/ClientIpResolver.java)
- **Related:** depends on [ADR-0001](0001-fixed-capacity-rate-limiting.md);
  [ADR-0003](0003-recovery-challenge-id-binding.md) relies on this being the global bound.

## Context

The credential-keyed limiters bound repeated attempts against one account and nothing else. An
attacker who varies the identifier is unthrottled by them, and reaches the pending-session store
and the recovery challenge store at whatever rate they can send. Bounding by request origin is the
missing dimension.

In 3.0.0 that bound shipped disabled, for two stated reasons: at 120/min it throttled legitimate
deployments — one login draws two tokens, so a corporate NAT or mobile CGNAT shares one bucket —
while an attacker sidestepped it with a few dozen addresses, or a single IPv6 /64. Both objections
were sound against the limiter as it then existed.

Two changes removed them. `ClientIpResolver.aggregate` now collapses IPv6 to the /64 prefix — one
subscriber line, rather than the 2^64 distinct keys a bare address allowed — and the limiter
behind it became a `FixedCapacityRateLimiter`, which cannot be filled ([ADR-0001](0001-fixed-capacity-rate-limiting.md)).

## Decision

`originRateLimitConfig()` returns `RateLimitConfig(600, 600.0/60, 50_000)` by default: 600 tokens
per aggregated origin per minute, which is 300 logins a minute from one origin. Returning `null`
from an override disables origin limiting entirely.

IPv4 addresses are keyed unchanged. Addresses there are scarce enough that a single one is a
meaningful unit, and aggregating to a /24 would lump unrelated networks together.

The origin key is only taken from `X-Forwarded-For` when the deployment sets
`trustForwardedHeaders`, and then from the **right-most** entry — the address appended by the
immediate trusted proxy, and the only value an external client cannot forge.

## Alternatives rejected

- **Keep it opt-in.** Rejected once aggregation and fixed capacity landed: the reasons for opting
  out no longer described the limiter being opted out of.
- **Enable it only when account recovery is configured.** Considered in `a85f258` as "the cheapest
  structural fix". Rejected as a conditional default that changes behaviour for deployments not
  using recovery, and as the wrong thing to decide inside a PR about something else.
- **Key on the full IPv6 address.** That is the defect being fixed, not an alternative to it.
- **Prefix-aggregate IPv4 too.** Rejected as lumping unrelated networks into one bucket.

## Consequences

- A denial now has a cause an operator may not control: origins can share a slot, and one denied
  by a neighbour's traffic is denied in front of all six OPAQUE endpoints.
- It still does not stop a distributed source, or an attacker holding more than one /64. It is a
  bound on cheap single-source floods, not on determined ones.
- Deployments that terminate TLS behind a proxy **must** set `trustForwardedHeaders`, or every
  request keys on the proxy's address and the limiter becomes one global bucket.

## Superseded analyses

- **"Disabled by default, because as a blanket default it does more harm than good."** This was
  the 3.0.0 decision and it was correct then. It was superseded on 2026-08-06 and the prose was
  never updated — so `RateLimitConfigSupplier`, `InMemoryRecoveryChallengeStore`,
  `HofmannOpaqueServerManager` and `OpaqueController` went on telling operators the limiter was
  off and that they should turn it on, while the shipped default returned a live 600/min config.
  One of those sites was rewritten as recently as PR #100 with the false framing preserved.
  Corrected in the PR carrying this ADR.
- **`a85f258`, "Record the origin-limiter default as its own decision"** (2026-08-07), recorded
  `originRateLimitConfig()` as "null by default for a documented reason" — one day after
  `67e3d08` had made it non-null. The entry was written from the prose rather than from the
  method. It has since been removed from `TODO.md`; it is noted here because it is the clearest
  illustration of why this file exists.
- **"An attacker sidesteps it with one IPv6 /64."** True of the pre-aggregation key, and no longer
  the objection it was. The residual is an attacker with *several* prefixes, which is a different
  and more expensive claim.
