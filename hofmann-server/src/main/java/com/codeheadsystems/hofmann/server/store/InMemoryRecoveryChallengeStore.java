package com.codeheadsystems.hofmann.server.store;

import java.time.Instant;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Non-persistent in-memory {@link RecoveryChallengeStore}, mirroring
 * {@link InMemoryRecoveryTokenStore}.
 *
 * <p>Capacity is bounded and entries are reaped on a TTL. The capacity matters more here than for
 * the token store: entries are created by {@code recoveryStart}, which is unauthenticated, so the
 * key space is driven by request volume. Reaching capacity is answered by refusing to record the
 * challenge rather than by evicting one — dropping an existing entry would hand an attacker a way
 * to force a legitimate in-flight recovery back onto identifier keying.
 */
public class InMemoryRecoveryChallengeStore implements RecoveryChallengeStore {

  private static final Logger log = LoggerFactory.getLogger(InMemoryRecoveryChallengeStore.class);

  /** Default TTL for challenge ids (seconds). Ten minutes, matching the recovery token. */
  public static final long DEFAULT_TTL_SECONDS = 600;

  /** Default maximum concurrent challenge ids. */
  public static final int DEFAULT_MAX_CHALLENGES = 10_000;

  private final long ttlSeconds;
  private final int maxChallenges;
  private final ConcurrentHashMap<String, TimestampedEntry> challenges = new ConcurrentHashMap<>();
  private final ScheduledExecutorService reaper;

  /**
   * Creates a store with the default TTL (10 minutes) and capacity (10,000).
   */
  public InMemoryRecoveryChallengeStore() {
    this(DEFAULT_TTL_SECONDS, DEFAULT_MAX_CHALLENGES);
  }

  /**
   * Creates a store with a custom TTL and capacity.
   *
   * @param ttlSeconds    time-to-live for challenge ids
   * @param maxChallenges maximum concurrent challenge ids
   */
  public InMemoryRecoveryChallengeStore(long ttlSeconds, int maxChallenges) {
    this.ttlSeconds = ttlSeconds;
    this.maxChallenges = maxChallenges;
    this.reaper = Executors.newSingleThreadScheduledExecutor(r -> {
      Thread t = new Thread(r, "recovery-challenge-reaper");
      t.setDaemon(true);
      return t;
    });
    long period = Math.max(1, ttlSeconds / 4);
    reaper.scheduleAtFixedRate(this::evictExpired, ttlSeconds, period, TimeUnit.SECONDS);
  }

  @Override
  public void store(String challengeId, String credentialIdentifierBase64) {
    if (challenges.size() >= maxChallenges) {
      evictExpired();
      if (challenges.size() >= maxChallenges) {
        // Not recording it is not fatal: verification falls back to identifier keying, which is
        // the pre-existing behaviour. Log at WARN because that fallback is exactly the lockout
        // this store exists to prevent, so a sustained occurrence is a security-relevant state
        // and not merely a capacity note.
        log.warn("Recovery challenge store at capacity ({} entries) after reclaiming expired "
            + "entries; this challenge is not recorded and its verification will fall back to "
            + "identifier-keyed rate limiting.", maxChallenges);
        return;
      }
    }
    challenges.put(challengeId, new TimestampedEntry(credentialIdentifierBase64, Instant.now()));
    // The id is not logged: it is what the verification limiter keys on, and a log reader who
    // learns it can drain that challenge's budget.
    log.debug("Recorded recovery challenge for credential {}", credentialIdentifierBase64);
  }

  @Override
  public Optional<String> peek(String challengeId) {
    if (challengeId == null) {
      return Optional.empty();
    }
    TimestampedEntry entry = challenges.get(challengeId);
    if (entry == null) {
      return Optional.empty();
    }
    if (entry.createdAt().isBefore(Instant.now().minusSeconds(ttlSeconds))) {
      challenges.remove(challengeId);
      return Optional.empty();
    }
    return Optional.of(entry.credentialIdentifierBase64());
  }

  private void evictExpired() {
    Instant cutoff = Instant.now().minusSeconds(ttlSeconds);
    challenges.entrySet().removeIf(e -> e.getValue().createdAt().isBefore(cutoff));
  }

  @Override
  public void shutdown() {
    reaper.shutdown();
  }

  private record TimestampedEntry(String credentialIdentifierBase64, Instant createdAt) {
  }
}
