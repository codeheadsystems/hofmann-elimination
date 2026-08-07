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
 * <p>Two bounds together: a per-identifier cap, so one credential cannot consume the whole store
 * and the flood is bounded at its source; and oldest-first eviction at global capacity, so a flood
 * costs the oldest outstanding challenges rather than all future ones.
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
   * <p>Sized above what the recovery limiter permits within one TTL — a few starts a minute over
   * ten minutes — so a legitimate user retrying never hits it, while one identifier cannot take
   * more than a thousandth of the store.
   */
  public static final int DEFAULT_MAX_PER_IDENTIFIER = 32;

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
    if (perIdentifier.getOrDefault(credentialIdentifierBase64, 0) >= maxPerIdentifier) {
      // Bounded at the source. Only this identifier's own recoveries are affected, and only
      // beyond a count no legitimate user reaches within one TTL — so the flood cannot spread to
      // anybody else's protection, which is the property that failed before.
      log.warn("Credential already has {} outstanding recovery challenges; not recording another. "
          + "Verification for it falls back to identifier-keyed rate limiting.", maxPerIdentifier);
      return;
    }
    while (challenges.size() >= maxChallenges) {
      if (!evictOldestLocked()) {
        return;
      }
      log.warn("Recovery challenge store at capacity ({} entries); evicted the oldest challenge. "
          + "Verification for it falls back to identifier-keyed rate limiting.", maxChallenges);
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

  private boolean evictOldestLocked() {
    Iterator<Map.Entry<String, TimestampedEntry>> it = challenges.entrySet().iterator();
    if (!it.hasNext()) {
      return false;
    }
    Map.Entry<String, TimestampedEntry> oldest = it.next();
    it.remove();
    decrementLocked(oldest.getValue().credentialIdentifierBase64());
    return true;
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
