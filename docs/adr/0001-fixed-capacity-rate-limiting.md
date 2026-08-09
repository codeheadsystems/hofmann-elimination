# 1. Fixed-capacity buckets for attacker-controlled rate-limit keys

- **Status:** Accepted (2026-08-06). In force.
- **Decided in:** `67e3d08`, corrected by `31b5548`
- **Implements:** [`FixedCapacityRateLimiter`](../../hofmann-server/src/main/java/com/codeheadsystems/hofmann/server/ratelimit/FixedCapacityRateLimiter.java),
  [`InMemoryRateLimiter`](../../hofmann-server/src/main/java/com/codeheadsystems/hofmann/server/ratelimit/InMemoryRateLimiter.java)
- **Related:** [ADR-0002](0002-origin-rate-limiting-on-by-default.md) applies this to request
  origins; [ADR-0003](0003-recovery-challenge-id-binding.md) depends on it holding.

## Context

Every limiter in this library keys on a value the caller supplies — a credential identifier or a
client address. `InMemoryRateLimiter` allocates a bucket per distinct key and denies once it
reaches `maxEntries`. That inverts the protection: a low-rate flood of one-shot keys fills the
map, and from then on every caller whose bucket is not resident is denied. A cheap flood becomes a
total outage, in front of every endpoint the limiter guards.

Reclaiming stale entries does not close it. The reaper evicts entries idle beyond a five-minute
window, so it helps only against an attacker who stops. Keeping 50,000 keys warm inside that
window sustained the outage at roughly 167 requests per second, indefinitely.

## Decision

Rate limiting over an attacker-controlled key space uses `FixedCapacityRateLimiter`: buckets are
pre-allocated at construction and a key hashes into an existing slot rather than allocating a new
one. Memory is fixed, there is no capacity condition, and therefore no capacity-driven denial. The
failure mode is not mitigated, it is absent.

The slot hash folds a per-process seed through the key's characters, so which keys collide cannot
be solved for offline or reproduced across restarts.

`InMemoryRateLimiter` is kept, not deleted. Over a small trusted key space it gives exact per-key
accounting and remains the better choice.

## Alternatives rejected

- **Bound the map and reclaim aggressively.** Measured and rejected above: it is a defence against
  an attacker who gets bored.
- **Seed only the final 32-bit hash.** Insufficient. Keys with equal `String.hashCode` collide
  under every seed, and those collisions are constructible with no knowledge of it.
- **Deny nothing at capacity (fail open).** Removes the outage by removing the limiter.

## Consequences

- **Precision is traded for availability.** Distinct keys can share a slot and therefore a budget.
  With `slots` buckets the chance a given key collides with a specific victim is `1/slots` — at
  the default `DEFAULT_SLOTS = 65_536`, an attacker cannot meaningfully target one account by
  flooding. Collisions cost accuracy; exhausting a map costs availability.
- **`RateLimitConfig.maxEntries` is meaningless** for this limiter. It is still set to a real
  value in the shipped defaults so that a consumer wiring the same config into the map-backed
  implementation gets a working limiter rather than one that denies everything.
- **Bounding memory does not bound volume.** An attacker sending enough traffic to drain every
  slot still denies service, exactly as they would by saturating any per-key limit. What is gone
  is the disproportionate case.

## Superseded analyses

- **"Reclaiming stale entries bounds the map well enough."** Withdrawn. It holds only while the
  attacker stops sending; a flood that touches each key inside the stale window keeps every entry
  alive and the outage holds indefinitely.
- **The first version of the guarding test overclaimed the protection**, reading as though fixed
  memory bounded request volume. Corrected in `31b5548`, and the limitation is now stated in the
  class javadoc under "What this does not do".
- **The prose describing this decision outlived it.** As late as PR #100 (2026-08-09),
  `RateLimitConfigSupplier` and `ClientIpResolver` still described the origin limiter as
  map-backed and exhaustible and pointed at `TODO.md` for a fixed-size structure as unfinished
  work — both of which had shipped here. Corrected in that PR. See
  [ADR-0002](0002-origin-rate-limiting-on-by-default.md), where the same drift ran deeper.
