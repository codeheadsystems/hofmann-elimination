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
 * Non-persistent in-memory {@link RecoveryTokenStore} backed by a {@link ConcurrentHashMap}.
 * <p>
 * Expired tokens are reaped by a background thread. All tokens are lost on server restart.
 * Suitable for single-node deployments, development, and integration testing.
 * <p>
 * For multi-node clusters, implement {@link RecoveryTokenStore} with a distributed backend
 * (e.g. Redis with TTL).
 */
public class InMemoryRecoveryTokenStore implements RecoveryTokenStore {

  private static final Logger log = LoggerFactory.getLogger(InMemoryRecoveryTokenStore.class);

  /**
   * Default TTL for recovery tokens (seconds). 10 minutes.
   */
  public static final long DEFAULT_TTL_SECONDS = 600;

  /**
   * Default maximum concurrent recovery tokens.
   */
  public static final int DEFAULT_MAX_TOKENS = 10_000;

  private final long ttlSeconds;
  private final int maxTokens;
  private final ConcurrentHashMap<String, TimestampedEntry> tokens = new ConcurrentHashMap<>();
  private final ScheduledExecutorService reaper;

  /**
   * Creates a store with default TTL (10 minutes) and capacity (10,000).
   */
  public InMemoryRecoveryTokenStore() {
    this(DEFAULT_TTL_SECONDS, DEFAULT_MAX_TOKENS);
  }

  /**
   * Creates a store with custom TTL and capacity.
   *
   * @param ttlSeconds time-to-live for recovery tokens
   * @param maxTokens  maximum concurrent recovery tokens
   */
  public InMemoryRecoveryTokenStore(long ttlSeconds, int maxTokens) {
    this.ttlSeconds = ttlSeconds;
    this.maxTokens = maxTokens;
    this.reaper = Executors.newSingleThreadScheduledExecutor(r -> {
      Thread t = new Thread(r, "recovery-token-reaper");
      t.setDaemon(true);
      return t;
    });
    long reaperPeriod = Math.max(1, ttlSeconds / 4);
    reaper.scheduleAtFixedRate(
        () -> {
          Instant cutoff = Instant.now().minusSeconds(ttlSeconds);
          tokens.entrySet().removeIf(e -> e.getValue().createdAt().isBefore(cutoff));
        }, reaperPeriod, reaperPeriod, TimeUnit.SECONDS);
  }

  @Override
  public void store(String token, String credentialIdentifierBase64) {
    if (tokens.size() >= maxTokens) {
      throw new IllegalStateException("Too many pending recovery tokens");
    }
    tokens.put(token, new TimestampedEntry(credentialIdentifierBase64, Instant.now()));
    // Do not log the raw recovery token: it is a single-use bearer credential that
    // authorizes account re-registration, so logging it (even at DEBUG) would let anyone
    // with log access take over the account. Log only the non-secret credential identifier.
    log.debug("Stored recovery token for credential {}", credentialIdentifierBase64);
  }

  @Override
  public Optional<String> peek(String token) {
    TimestampedEntry entry = tokens.get(token);
    if (entry == null) {
      return Optional.empty();
    }
    if (entry.createdAt().isBefore(Instant.now().minusSeconds(ttlSeconds))) {
      tokens.remove(token);
      return Optional.empty();
    }
    return Optional.of(entry.credentialIdentifierBase64());
  }

  @Override
  public Optional<String> remove(String token) {
    TimestampedEntry entry = tokens.remove(token);
    if (entry == null) {
      return Optional.empty();
    }
    if (entry.createdAt().isBefore(Instant.now().minusSeconds(ttlSeconds))) {
      return Optional.empty();
    }
    return Optional.of(entry.credentialIdentifierBase64());
  }

  @Override
  public void shutdown() {
    reaper.shutdown();
  }

  private record TimestampedEntry(
      String credentialIdentifierBase64,
      Instant createdAt) {
  }
}
