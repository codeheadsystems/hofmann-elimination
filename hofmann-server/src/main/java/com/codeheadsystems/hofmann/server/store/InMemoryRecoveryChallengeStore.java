package com.codeheadsystems.hofmann.server.store;

import java.time.Instant;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Non-persistent in-memory {@link RecoveryChallengeStore}.
 *
 * <p><strong>At capacity this evicts, it does not refuse.</strong> An earlier version refused, on
 * the reasoning that evicting would let an attacker force a legitimate in-flight recovery back
 * onto identifier keying. Refusing produces the same outcome for <em>every</em> recovery started
 * after the flood rather than for one — the same primitive with a much larger blast radius, and
 * signalled only by a log line. Since {@code recoveryStart} is unauthenticated and its limiter
 * keys on the credential identifier, an attacker who varies the identifier is bounded only by the
 * origin limiter, which is <em>off by default</em>. Filling the store was therefore cheap, and
 * doing so silently disabled the protection for everyone.
 *
 * <p>Two bounds, and neither refuses. A per-identifier cap, at which that identifier's <em>own</em>
 * oldest entry is dropped — refusing there reintroduced the same failure per-identifier, which is
 * precisely the targeting this feature exists to defeat, and more cheaply than the lockout it
 * replaced: {@code recoveryStart} permits a sustained 6/min, which at a 600s TTL is 60 outstanding
 * against a cap of 32. And at global capacity, eviction takes from the identifier holding the
 * <em>most</em> rather than whatever is globally oldest, so flooding is self-defeating: the
 * flooder is always at the cap and therefore always the eviction candidate, while a legitimate
 * user holding one or two entries is never chosen.
 *
 * <p>Access is synchronised rather than lock-free. Both recovery endpoints are heavily rate
 * limited and {@code recoveryVerify} already sits behind a 250 ms constant-time floor, so
 * contention here is irrelevant, and insertion-ordered eviction with per-identifier counting is
 * far easier to get right under one lock than with concurrent bookkeeping across two maps.
 */
public class InMemoryRecoveryChallengeStore implements RecoveryChallengeStore {

  private static final Logger log = LoggerFactory.getLogger(InMemoryRecoveryChallengeStore.class);

  /** Default TTL for challenge ids (seconds). Ten minutes, matching the recovery token. */
  public static final long DEFAULT_TTL_SECONDS = 600;

  /** Default maximum concurrent challenge ids. */
  public static final int DEFAULT_MAX_CHALLENGES = 10_000;

  /**
   * Default maximum outstanding challenges for a single credential identifier.
   *
   * <p>A concurrency bound, not a ceiling: reaching it evicts this identifier's oldest entry
   * rather than refusing the new one, so a user whose challenges have been churned by an attacker
   * still gets their current challenge recorded.
   *
   * <p><strong>Derived, not picked.</strong> It is the number of starts the recovery limiter
   * permits within one TTL — 6 per minute over 600 seconds. That equality is what makes the value
   * matter: under a sustained flood the victim's real challenge is the <em>newest</em> entry, so
   * it survives until this many further starts have evicted forward past it, which at the
   * permitted rate takes exactly one TTL. Eviction therefore never shortens a challenge below the
   * lifetime it would have had anyway.
   *
   * <p>At an arbitrary value it does. The previous 32 gave {@code 32 / 6 per minute} ≈ 5.3
   * minutes, after which a sustained flood evicted the victim's real challenge, verification fell
   * back to identifier keying, and the lockout returned — a smaller version of the failure this
   * store exists to prevent, decided by the ratio of two constants nobody had related to each
   * other.
   *
   * <p><strong>Retuning either constant moves that window.</strong> Raising the recovery refill
   * rate or lowering this cap shortens it; keep {@code maxPerIdentifier >= refillPerMinute *
   * ttlMinutes} and eviction stays invisible to legitimate users. One identifier still holds at
   * most 0.6% of the store at these defaults.
   */
  public static final int DEFAULT_MAX_PER_IDENTIFIER = 60;

  private final long ttlSeconds;
  private final int maxChallenges;
  private final int maxPerIdentifier;
  /** Insertion-ordered so eviction can take the oldest without scanning for a minimum. */
  private final LinkedHashMap<String, TimestampedEntry> challenges = new LinkedHashMap<>();
  private final Map<String, Integer> perIdentifier = new java.util.HashMap<>();
  private final ScheduledExecutorService reaper;

  /**
   * Creates a store with the default TTL (10 minutes), capacity (10,000) and per-identifier cap.
   */
  public InMemoryRecoveryChallengeStore() {
    this(DEFAULT_TTL_SECONDS, DEFAULT_MAX_CHALLENGES, DEFAULT_MAX_PER_IDENTIFIER);
  }

  /**
   * Creates a store with custom bounds.
   *
   * @param ttlSeconds       time-to-live for challenge ids
   * @param maxChallenges    maximum concurrent challenge ids
   * @param maxPerIdentifier maximum outstanding challenges for one credential identifier
   */
  public InMemoryRecoveryChallengeStore(long ttlSeconds, int maxChallenges,
                                        int maxPerIdentifier) {
    this.ttlSeconds = ttlSeconds;
    this.maxChallenges = maxChallenges;
    this.maxPerIdentifier = maxPerIdentifier;
    this.reaper = Executors.newSingleThreadScheduledExecutor(r -> {
      Thread t = new Thread(r, "recovery-challenge-reaper");
      t.setDaemon(true);
      return t;
    });
    long period = Math.max(1, ttlSeconds / 4);
    reaper.scheduleAtFixedRate(this::evictExpired, ttlSeconds, period, TimeUnit.SECONDS);
  }

  @Override
  public synchronized void store(String challengeId, String credentialIdentifierBase64) {
    evictExpiredLocked();
    // At the per-identifier cap, drop this identifier's own oldest rather than refusing to record
    // the new one. Refusing here was the global failure mode reintroduced per-identifier, and
    // per-identifier is exactly the targeting this feature exists to defeat: recoveryStart's
    // limiter permits a sustained 6/min, and at a 600s TTL that is 60 outstanding against a cap of
    // 32 — reached in five minutes and held indefinitely. From then on the victim's *real*
    // challenge went unrecorded, so their verification fell back to identifier keying and the
    // attacker drained that separate bucket. Cheaper and more precise than the lockout this
    // replaced.
    //
    // The newest challenge is the one that matters; older ones for the same identifier are
    // abandoned attempts. Evicting them keeps the flood bound — an identifier still never holds
    // more than maxPerIdentifier — while guaranteeing the challenge the user is about to present
    // is the one that got recorded.
    while (perIdentifier.getOrDefault(credentialIdentifierBase64, 0) >= maxPerIdentifier) {
      if (!evictOldestForLocked(credentialIdentifierBase64)) {
        break;
      }
    }
    while (challenges.size() >= maxChallenges) {
      if (!evictFromLargestHolderLocked()) {
        return;
      }
      log.warn("Recovery challenge store at capacity ({} entries); evicted a challenge from the "
          + "largest holder. Verification for it falls back to identifier-keyed rate limiting.",
          maxChallenges);
    }
    challenges.put(challengeId, new TimestampedEntry(credentialIdentifierBase64, Instant.now()));
    perIdentifier.merge(credentialIdentifierBase64, 1, Integer::sum);
    // The id is not logged: it is what the verification limiter keys on, and a log reader who
    // learns it can drain that challenge's budget.
    log.debug("Recorded recovery challenge for credential {}", credentialIdentifierBase64);
  }

  @Override
  public synchronized Optional<String> peek(String challengeId) {
    if (challengeId == null) {
      return Optional.empty();
    }
    TimestampedEntry entry = challenges.get(challengeId);
    if (entry == null) {
      return Optional.empty();
    }
    if (entry.createdAt().isBefore(Instant.now().minusSeconds(ttlSeconds))) {
      removeLocked(challengeId, entry);
      return Optional.empty();
    }
    return Optional.of(entry.credentialIdentifierBase64());
  }

  private synchronized void evictExpired() {
    evictExpiredLocked();
  }

  private void evictExpiredLocked() {
    Instant cutoff = Instant.now().minusSeconds(ttlSeconds);
    Iterator<Map.Entry<String, TimestampedEntry>> it = challenges.entrySet().iterator();
    // Insertion-ordered, so the expired entries are a prefix and the scan can stop at the first
    // live one rather than walking the whole map.
    while (it.hasNext()) {
      Map.Entry<String, TimestampedEntry> entry = it.next();
      if (!entry.getValue().createdAt().isBefore(cutoff)) {
        break;
      }
      it.remove();
      decrementLocked(entry.getValue().credentialIdentifierBase64());
    }
  }

  /** Removes the oldest entry belonging to one identifier. Insertion order makes it the first. */
  private boolean evictOldestForLocked(String credentialIdentifierBase64) {
    Iterator<Map.Entry<String, TimestampedEntry>> it = challenges.entrySet().iterator();
    while (it.hasNext()) {
      Map.Entry<String, TimestampedEntry> entry = it.next();
      if (entry.getValue().credentialIdentifierBase64().equals(credentialIdentifierBase64)) {
        it.remove();
        decrementLocked(credentialIdentifierBase64);
        return true;
      }
    }
    return false;
  }

  /**
   * Removes the oldest entry belonging to whichever identifier holds the most.
   *
   * <p>Not the globally oldest, which is targetable: an attacker filling the store across a few
   * hundred identifiers — which need not exist — evicts whatever is oldest, including a victim's
   * in-flight challenge. Taking from the largest holder makes flooding self-defeating, because the
   * flooder is always at the per-identifier cap and therefore always the eviction candidate, while
   * a legitimate user holding one or two entries is never chosen.
   */
  private boolean evictFromLargestHolderLocked() {
    int largestCount = 0;
    for (Integer count : perIdentifier.values()) {
      largestCount = Math.max(largestCount, count);
    }
    if (largestCount == 0) {
      return false;
    }
    // Oldest among the largest holders. Scanning in insertion order rather than picking any
    // identifier at the maximum makes the choice deterministic when holders are level — which is
    // the normal state, since most identifiers hold exactly one — and reduces to plain
    // oldest-first when nobody is flooding.
    final int max = largestCount;
    Iterator<Map.Entry<String, TimestampedEntry>> it = challenges.entrySet().iterator();
    while (it.hasNext()) {
      Map.Entry<String, TimestampedEntry> entry = it.next();
      String holder = entry.getValue().credentialIdentifierBase64();
      if (perIdentifier.getOrDefault(holder, 0) == max) {
        it.remove();
        decrementLocked(holder);
        return true;
      }
    }
    return false;
  }

  private void removeLocked(String challengeId, TimestampedEntry entry) {
    challenges.remove(challengeId);
    decrementLocked(entry.credentialIdentifierBase64());
  }

  private void decrementLocked(String credentialIdentifierBase64) {
    perIdentifier.computeIfPresent(credentialIdentifierBase64,
        (k, count) -> count <= 1 ? null : count - 1);
  }

  @Override
  public void shutdown() {
    reaper.shutdown();
  }

  private record TimestampedEntry(String credentialIdentifierBase64, Instant createdAt) {
  }
}
