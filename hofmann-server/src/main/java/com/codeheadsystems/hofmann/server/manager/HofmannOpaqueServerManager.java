package com.codeheadsystems.hofmann.server.manager;

import com.codeheadsystems.hofmann.model.opaque.AuthFinishRequest;
import com.codeheadsystems.hofmann.model.opaque.AuthFinishResponse;
import com.codeheadsystems.hofmann.model.opaque.AuthStartRequest;
import com.codeheadsystems.hofmann.model.opaque.AuthStartResponse;
import com.codeheadsystems.hofmann.model.opaque.RecoveryStartRequest;
import com.codeheadsystems.hofmann.model.opaque.RecoveryVerifyRequest;
import com.codeheadsystems.hofmann.model.opaque.RecoveryVerifyResponse;
import com.codeheadsystems.hofmann.model.opaque.RegistrationDeleteRequest;
import com.codeheadsystems.hofmann.model.opaque.RegistrationFinishRequest;
import com.codeheadsystems.hofmann.model.opaque.RegistrationStartRequest;
import com.codeheadsystems.hofmann.model.opaque.RegistrationStartResponse;
import com.codeheadsystems.hofmann.server.ratelimit.InMemoryRateLimiter;
import com.codeheadsystems.hofmann.server.ratelimit.RateLimitConfigSupplier;
import com.codeheadsystems.hofmann.server.ratelimit.RateLimitExceededException;
import com.codeheadsystems.hofmann.server.ratelimit.RateLimiter;
import com.codeheadsystems.hofmann.server.recovery.RecoveryChallenger;
import com.codeheadsystems.hofmann.server.store.CredentialStore;
import com.codeheadsystems.hofmann.server.store.InMemoryPendingSessionStore;
import com.codeheadsystems.hofmann.server.store.InMemoryRecoveryTokenStore;
import com.codeheadsystems.hofmann.server.store.PendingSessionStore;
import com.codeheadsystems.hofmann.server.store.RecoveryTokenStore;
import com.codeheadsystems.hofmann.server.store.VersionedCredential;
import com.codeheadsystems.rfc.opaque.Server;
import com.codeheadsystems.rfc.opaque.model.KE1;
import com.codeheadsystems.rfc.opaque.model.RegistrationRecord;
import com.codeheadsystems.rfc.opaque.model.ServerKE2Result;
import java.util.Base64;
import java.util.Optional;
import java.util.UUID;
import java.util.function.Supplier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Framework-agnostic service implementing the OPAQUE-3DH protocol (RFC 9807) server side.
 * <p>
 * Encapsulates all session management and protocol orchestration so that
 * framework-specific adapters ({@code OpaqueResource} for JAX-RS / Dropwizard,
 * {@code OpaqueController} for Spring Boot) can remain thin wrappers that only
 * translate exceptions into framework-specific HTTP error responses.
 * <p>
 * <strong>Key rotation:</strong> accepts a {@code Supplier<OpaqueServerKeyDetail>} to support
 * multiple server key versions. Credentials registered under older key versions are authenticated
 * using the corresponding old keys, and the response includes a {@code keyRotationRequired} flag
 * so clients can re-register under the current keys via the change-password flow.
 * <p>
 * <strong>Exception contract</strong> (callers should map these to HTTP responses):
 * <ul>
 *   <li>{@link IllegalArgumentException}      — bad / missing request data → HTTP 400</li>
 *   <li>{@link SecurityException}             — auth failure or expired session → HTTP 401</li>
 *   <li>{@link UnsupportedOperationException} — recovery not configured → HTTP 404</li>
 *   <li>{@link IllegalStateException}         — session store at capacity → HTTP 503</li>
 * </ul>
 */
public class HofmannOpaqueServerManager {

  private static final Logger log = LoggerFactory.getLogger(HofmannOpaqueServerManager.class);
  private static final Base64.Encoder B64 = Base64.getEncoder();

  /**
   * Minimum wall-clock time {@link #recoveryVerify} takes, regardless of outcome, so that the
   * latency of the call does not reveal whether the credential exists. See {@link #recoveryVerify}.
   */
  private static final long RECOVERY_VERIFY_MIN_NANOS = 250L * 1_000_000L; // 250 ms

  /**
   * Minimum wall-clock duration of the non-recovery {@code registrationFinish} path.
   * <p>
   * The two branches do different amounts of work: an already-registered credential returns
   * straight after the store lookup, while an unregistered one additionally reads the key
   * detail and performs a write. Against {@link
   * com.codeheadsystems.hofmann.server.store.InMemoryCredentialStore} that difference measures
   * around 340 ns and is unexploitable, but the documented production path is a database-backed
   * {@code CredentialStore}, where the extra work is an INSERT — commonly 0.2–5 ms, which is
   * remotely measurable and would reopen the very enumeration oracle unifying the two responses
   * was meant to close.
   * <p>
   * 25 ms comfortably covers a typical INSERT while staying far below the 250 ms recovery floor,
   * since this runs on every registration rather than only on recovery. Note the floor only
   * masks work that finishes inside it: a store whose writes routinely exceed 25 ms would leak
   * again, which is the same caveat that applies to {@link #RECOVERY_VERIFY_MIN_NANOS}.
   */
  private static final long REGISTRATION_FINISH_MIN_NANOS = 25L * 1_000_000L; // 25 ms

  private final Supplier<OpaqueServerKeyDetail> keyDetailSupplier;
  private final CredentialStore credentialStore;
  private final JwtManager jwtManager;
  private final RateLimiter authRateLimiter;
  private final RateLimiter registrationRateLimiter;
  private final PendingSessionStore pendingSessionStore;
  private final RecoveryChallenger recoveryChallenger;
  private final RecoveryTokenStore recoveryTokenStore;
  private final RateLimiter recoveryRateLimiter;

  /**
   * Instantiates a new Hofmann opaque server manager with default rate limiters
   * and an in-memory pending session store. Recovery is disabled.
   *
   * @param server          the server
   * @param credentialStore the credential store
   * @param jwtManager      the jwt manager
   */
  public HofmannOpaqueServerManager(Server server, CredentialStore credentialStore, JwtManager jwtManager) {
    this(() -> new OpaqueServerKeyDetail(server), credentialStore, jwtManager,
        new InMemoryRateLimiter(new RateLimitConfigSupplier.DefaultRateLimitConfigSupplier().authRateLimitConfig()),
        new InMemoryRateLimiter(new RateLimitConfigSupplier.DefaultRateLimitConfigSupplier().registrationRateLimitConfig()));
  }

  /**
   * Instantiates a new Hofmann opaque server manager with custom rate limiters
   * and a default in-memory pending session store. Recovery is disabled.
   *
   * @param keyDetailSupplier       supplies the current and previous server keys
   * @param credentialStore         the credential store
   * @param jwtManager              the jwt manager
   * @param authRateLimiter         rate limiter for authentication endpoints (keyed by credential)
   * @param registrationRateLimiter rate limiter for registration endpoints (keyed by credential)
   */
  public HofmannOpaqueServerManager(Supplier<OpaqueServerKeyDetail> keyDetailSupplier,
                                    CredentialStore credentialStore, JwtManager jwtManager,
                                    RateLimiter authRateLimiter, RateLimiter registrationRateLimiter) {
    this(keyDetailSupplier, credentialStore, jwtManager, authRateLimiter, registrationRateLimiter,
        new InMemoryPendingSessionStore());
  }

  /**
   * Instantiates a new Hofmann opaque server manager with custom rate limiters
   * and a custom pending session store. Recovery is disabled.
   *
   * @param keyDetailSupplier       supplies the current and previous server keys
   * @param credentialStore         the credential store
   * @param jwtManager              the jwt manager
   * @param authRateLimiter         rate limiter for authentication endpoints (keyed by credential)
   * @param registrationRateLimiter rate limiter for registration endpoints (keyed by credential)
   * @param pendingSessionStore     store for in-flight authentication sessions
   */
  public HofmannOpaqueServerManager(Supplier<OpaqueServerKeyDetail> keyDetailSupplier,
                                    CredentialStore credentialStore, JwtManager jwtManager,
                                    RateLimiter authRateLimiter, RateLimiter registrationRateLimiter,
                                    PendingSessionStore pendingSessionStore) {
    this(keyDetailSupplier, credentialStore, jwtManager, authRateLimiter, registrationRateLimiter,
        pendingSessionStore, null, null, null);
  }

  /**
   * Instantiates a new Hofmann opaque server manager with full configuration including
   * account recovery support.
   * <p>
   * Pass {@code null} for {@code recoveryChallenger} to disable recovery endpoints (they
   * will throw {@link UnsupportedOperationException}).
   *
   * @param keyDetailSupplier       supplies the current and previous server keys
   * @param credentialStore         the credential store
   * @param jwtManager              the jwt manager
   * @param authRateLimiter         rate limiter for authentication endpoints (keyed by credential)
   * @param registrationRateLimiter rate limiter for registration endpoints (keyed by credential)
   * @param pendingSessionStore     store for in-flight authentication sessions
   * @param recoveryChallenger      out-of-band challenge sender/verifier, or null to disable recovery
   * @param recoveryTokenStore      store for recovery tokens, or null (defaults to in-memory if challenger is set)
   * @param recoveryRateLimiter     rate limiter for recovery endpoints, or null (defaults to in-memory if challenger is set)
   */
  public HofmannOpaqueServerManager(Supplier<OpaqueServerKeyDetail> keyDetailSupplier,
                                    CredentialStore credentialStore, JwtManager jwtManager,
                                    RateLimiter authRateLimiter, RateLimiter registrationRateLimiter,
                                    PendingSessionStore pendingSessionStore,
                                    RecoveryChallenger recoveryChallenger,
                                    RecoveryTokenStore recoveryTokenStore,
                                    RateLimiter recoveryRateLimiter) {
    this.keyDetailSupplier = keyDetailSupplier;
    this.credentialStore = credentialStore;
    this.jwtManager = jwtManager;
    this.authRateLimiter = authRateLimiter;
    this.registrationRateLimiter = registrationRateLimiter;
    this.pendingSessionStore = pendingSessionStore;
    this.recoveryChallenger = recoveryChallenger;
    if (recoveryChallenger != null) {
      this.recoveryTokenStore = recoveryTokenStore != null
          ? recoveryTokenStore : new InMemoryRecoveryTokenStore();
      this.recoveryRateLimiter = recoveryRateLimiter != null
          ? recoveryRateLimiter : new InMemoryRateLimiter(
          new RateLimitConfigSupplier.DefaultRateLimitConfigSupplier().recoveryRateLimitConfig());
    } else {
      this.recoveryTokenStore = null;
      this.recoveryRateLimiter = null;
    }
  }

  /**
   * Backward-compatible full constructor that accepts a single {@link Server}.
   *
   * @param server                  the server
   * @param credentialStore         the credential store
   * @param jwtManager              the jwt manager
   * @param authRateLimiter         rate limiter for authentication endpoints (keyed by credential)
   * @param registrationRateLimiter rate limiter for registration endpoints (keyed by credential)
   * @param pendingSessionStore     store for in-flight authentication sessions
   * @param recoveryChallenger      out-of-band challenge sender/verifier, or null to disable recovery
   * @param recoveryTokenStore      store for recovery tokens, or null
   * @param recoveryRateLimiter     rate limiter for recovery endpoints, or null
   */
  public HofmannOpaqueServerManager(Server server, CredentialStore credentialStore, JwtManager jwtManager,
                                    RateLimiter authRateLimiter, RateLimiter registrationRateLimiter,
                                    PendingSessionStore pendingSessionStore,
                                    RecoveryChallenger recoveryChallenger,
                                    RecoveryTokenStore recoveryTokenStore,
                                    RateLimiter recoveryRateLimiter) {
    this(() -> new OpaqueServerKeyDetail(server), credentialStore, jwtManager,
        authRateLimiter, registrationRateLimiter, pendingSessionStore,
        recoveryChallenger, recoveryTokenStore, recoveryRateLimiter);
  }

  /**
   * Shuts down background resources (pending session reaper, rate limiters).
   * <p>
   * Should be called on application shutdown to release background threads.
   * In Dropwizard, register this instance as a {@code Managed} component.
   * In Spring Boot, declare the bean with {@code @Bean(destroyMethod = "shutdown")}.
   */
  public void shutdown() {
    pendingSessionStore.shutdown();
    authRateLimiter.shutdown();
    registrationRateLimiter.shutdown();
    if (recoveryTokenStore != null) {
      recoveryTokenStore.shutdown();
    }
    if (recoveryRateLimiter != null) {
      recoveryRateLimiter.shutdown();
    }
  }

  /**
   * Returns whether account recovery is enabled (a {@link RecoveryChallenger} was provided).
   *
   * @return true if recovery endpoints are available
   */
  public boolean isRecoveryEnabled() {
    return recoveryChallenger != null;
  }

  // ── Registration ─────────────────────────────────────────────────────────

  /**
   * Phase 1 of registration: evaluates the OPRF on the blinded element and returns
   * the evaluated element + server public key.
   *
   * @param req the req
   * @return the registration start response
   * @throws IllegalArgumentException if the request contains missing or invalid fields
   */
  public RegistrationStartResponse registrationStart(RegistrationStartRequest req) {
    return registrationStart(req, null);
  }

  /**
   * Phase 1 of registration with optional recovery token.
   * <p>
   * When a recovery token is present, validates that the token is valid and matches the
   * credential identifier. The token is not consumed here — it will be consumed in
   * {@link #registrationFinish(RegistrationFinishRequest, String)}.
   *
   * @param req         the registration start request
   * @param bearerToken optional recovery token (without "Bearer " prefix), or null for normal registration
   * @return the registration start response
   * @throws IllegalArgumentException if the request contains missing or invalid fields
   * @throws SecurityException        if the recovery token is invalid, expired, or mismatched
   */
  public RegistrationStartResponse registrationStart(RegistrationStartRequest req, String bearerToken) {
    log.debug("registrationStart()");
    if (!registrationRateLimiter.tryConsume(req.credentialIdentifierBase64())) {
      throw new RateLimitExceededException();
    }
    if (bearerToken != null && !bearerToken.isBlank()) {
      validateRecoveryToken(bearerToken, req.credentialIdentifierBase64());
    }
    Server server = keyDetailSupplier.get().currentServer();
    return new RegistrationStartResponse(
        server.createRegistrationResponse(req.registrationRequest(), req.credentialIdentifier()));
  }

  /**
   * Phase 2 of registration: stores the client's registration record.
   *
   * @param req the req
   * @throws IllegalArgumentException if the request contains missing or invalid fields
   */
  public void registrationFinish(RegistrationFinishRequest req) {
    registrationFinish(req, null);
  }

  /**
   * Phase 2 of registration with optional recovery token.
   * <p>
   * When a recovery token is present, this performs recovery re-registration:
   * the old credential is deleted, all active JWTs are revoked, the recovery
   * token is consumed, and the new registration record is stored.
   *
   * @param req         the registration finish request
   * @param bearerToken optional recovery token (without "Bearer " prefix), or null for normal registration
   * @throws IllegalArgumentException if the request contains missing or invalid fields
   * @throws SecurityException        if the recovery token is invalid, expired, or mismatched
   */
  public void registrationFinish(RegistrationFinishRequest req, String bearerToken) {
    log.debug("registrationFinish()");
    if (bearerToken != null && !bearerToken.isBlank()) {
      if (recoveryTokenStore == null) {
        // A recovery token was supplied but recovery is not configured: treat as invalid.
        throw new SecurityException("Invalid or expired recovery token");
      }
      // Rate-limit recovery-token consumption to throttle online token guessing. The token is a
      // single-use bearer credential that authorizes account re-registration; registrationStart is
      // throttled per credential identifier but finish was previously unthrottled, leaving the
      // token-guessing gate wide open. We reuse the recovery rate limiter (keyed by credential
      // identifier, consistent with the rest of the design), so an attacker's guesses against any
      // single account are bounded. Checked before consuming the token so every attempt counts
      // whether or not the token turns out to be valid. Note: a legitimate recovery draws three
      // tokens from this bucket (recoveryStart + recoveryVerify + registrationFinish), which the
      // default capacity (maxTokens=6) accommodates with retry headroom; size the recovery limit
      // accordingly if you tune it.
      if (recoveryRateLimiter != null
          && !recoveryRateLimiter.tryConsume(req.credentialIdentifierBase64())) {
        throw new RateLimitExceededException();
      }
      // Recovery-token lifecycle: registrationStart only peeks the token (non-consuming) so the
      // client can safely retry start after a network failure. This finish step is the single,
      // atomic consume gate: remove() returns the bound credential id exactly once, so the
      // account-mutating work below (delete old record, revoke sessions, store new record) runs
      // at most once per token. A second finish with the same token gets Optional.empty() and is
      // rejected. TTL/expiry is re-checked here by the store, so there is no TOCTOU against the
      // earlier peek.
      String credId = recoveryTokenStore.remove(bearerToken)
          .orElseThrow(() -> new SecurityException("Invalid or expired recovery token"));
      if (!credId.equals(req.credentialIdentifierBase64())) {
        throw new SecurityException("Recovery token does not match credential");
      }
      log.info("Recovery re-registration for credential {}", req.credentialIdentifierBase64());
      credentialStore.delete(req.credentialIdentifier());
      jwtManager.revokeByCredentialIdentifier(req.credentialIdentifierBase64());
    } else {
      // Normal (non-recovery) registration. Both branches below must be indistinguishable to an
      // unauthenticated caller, in latency as well as in response, so the whole path runs under
      // a fixed floor — see REGISTRATION_FINISH_MIN_NANOS. The floor deliberately wraps only
      // this branch: the recovery path above is already authenticated by a bearer token and
      // carries its own limiter.
      final long deadlineNanos = System.nanoTime() + REGISTRATION_FINISH_MIN_NANOS;
      try {
        // Consume a token BEFORE looking the credential up:
        // registrationStart is throttled but finish previously was not, so an attacker could
        // probe this endpoint without limit. The check has to precede the existence lookup so
        // that every attempt costs the same whether or not the credential turns out to exist.
        if (!registrationRateLimiter.tryConsume(req.credentialIdentifierBase64())) {
          throw new RateLimitExceededException();
        }
        if (credentialStore.loadVersioned(req.credentialIdentifier()).isPresent()) {
          // Must not overwrite an existing record: registrationStart/Finish are unauthenticated,
          // so without this guard anyone who knows a victim's credential identifier could
          // re-register it with their own password and take over the account. Existing
          // credentials are updated through the authenticated change-password flow or the
          // recovery flow (which deletes the old record above before storing the new one).
          //
          // Return normally rather than throwing. Throwing produced HTTP 400 for an existing
          // credential and 204 for a new one, which is an unauthenticated existence oracle — it
          // defeated the enumeration resistance authStart goes to real trouble to provide, where
          // an unknown credential gets a manufactured KE2 precisely so this bit cannot be read.
          // The security property that matters is "does not overwrite", and that is preserved;
          // signalling *why* nothing was written is what leaked. A legitimate client re-running
          // registration therefore sees success without its record being replaced.
          log.debug("registrationFinish: credential already registered, record left unchanged");
          return;
        }
        int currentVersion = keyDetailSupplier.get().currentVersion();
        credentialStore.store(req.credentialIdentifier(), req.registrationRecord(), currentVersion);
        return;
      } finally {
        sleepUntil(deadlineNanos);
      }
    }
    int currentVersion = keyDetailSupplier.get().currentVersion();
    credentialStore.store(req.credentialIdentifier(), req.registrationRecord(), currentVersion);
  }

  /**
   * Deletes a previously registered credential and immediately revokes all active sessions
   * for that credential.
   * <p>
   * Requires a valid JWT bearer token whose subject (credential identifier) matches the
   * credential being deleted.  This prevents unauthenticated or cross-user deletion.
   * <p>
   * After this method returns, any JWT tokens previously issued for the deleted credential
   * will be rejected by {@link JwtManager#verify}, even if they have not yet expired.
   *
   * @param req         the delete request containing the credential identifier
   * @param bearerToken the JWT bearer token (without "Bearer " prefix)
   * @throws IllegalArgumentException if the request contains missing or invalid fields
   * @throws SecurityException        if the token is missing, invalid, expired, or does not                                  match the credential being deleted
   */
  public void registrationDelete(RegistrationDeleteRequest req, String bearerToken) {
    log.debug("registrationDelete()");
    if (bearerToken == null || bearerToken.isBlank()) {
      throw new SecurityException("Authentication required");
    }
    JwtManager.VerifyResult result = jwtManager.verify(bearerToken)
        .orElseThrow(() -> new SecurityException("Authentication failed"));
    if (!result.subject().equals(req.credentialIdentifierBase64())) {
      throw new SecurityException("Authentication failed");
    }
    credentialStore.delete(req.credentialIdentifier());
    jwtManager.revokeByCredentialIdentifier(req.credentialIdentifierBase64());
  }

  // ── Password Change ──────────────────────────────────────────────────────

  /**
   * Phase 1 of password change: validates the JWT and evaluates the OPRF.
   * Identical to registrationStart() but requires a valid JWT whose subject
   * matches the credential identifier.
   *
   * @param req         the registration start request
   * @param bearerToken the JWT bearer token (without "Bearer " prefix)
   * @return the registration start response
   * @throws SecurityException        if the JWT is missing, invalid, or mismatched
   * @throws IllegalArgumentException if the request contains missing or invalid fields
   */
  public RegistrationStartResponse changePasswordStart(RegistrationStartRequest req, String bearerToken) {
    log.debug("changePasswordStart()");
    if (bearerToken == null || bearerToken.isBlank()) {
      throw new SecurityException("Authentication required");
    }
    JwtManager.VerifyResult result = jwtManager.verify(bearerToken)
        .orElseThrow(() -> new SecurityException("Authentication failed"));
    if (!result.subject().equals(req.credentialIdentifierBase64())) {
      throw new SecurityException("Authentication failed");
    }
    if (!registrationRateLimiter.tryConsume(req.credentialIdentifierBase64())) {
      throw new RateLimitExceededException();
    }
    Server server = keyDetailSupplier.get().currentServer();
    return new RegistrationStartResponse(
        server.createRegistrationResponse(req.registrationRequest(), req.credentialIdentifier()));
  }

  /**
   * Phase 2 of password change: validates the JWT, atomically deletes the old
   * registration record, revokes all sessions, and stores the new record.
   *
   * @param req         the registration finish request
   * @param bearerToken the JWT bearer token (without "Bearer " prefix)
   * @throws SecurityException        if the JWT is missing, invalid, or mismatched
   * @throws IllegalArgumentException if the request contains missing or invalid fields
   */
  public void changePasswordFinish(RegistrationFinishRequest req, String bearerToken) {
    log.debug("changePasswordFinish()");
    if (bearerToken == null || bearerToken.isBlank()) {
      throw new SecurityException("Authentication required");
    }
    JwtManager.VerifyResult result = jwtManager.verify(bearerToken)
        .orElseThrow(() -> new SecurityException("Authentication failed"));
    if (!result.subject().equals(req.credentialIdentifierBase64())) {
      throw new SecurityException("Authentication failed");
    }
    credentialStore.delete(req.credentialIdentifier());
    jwtManager.revokeByCredentialIdentifier(req.credentialIdentifierBase64());
    int currentVersion = keyDetailSupplier.get().currentVersion();
    credentialStore.store(req.credentialIdentifier(), req.registrationRecord(), currentVersion);
  }

  // ── Recovery ───────────────────────────────────────────────────────────

  /**
   * Initiates account recovery by sending an out-of-band challenge.
   * <p>
   * Always returns successfully to prevent user enumeration — the
   * {@link RecoveryChallenger} is responsible for not revealing whether
   * the credential exists.
   *
   * @param req the recovery start request
   * @throws UnsupportedOperationException if recovery is not configured
   * @throws IllegalArgumentException      if the request contains missing or invalid fields
   */
  public void recoveryStart(RecoveryStartRequest req) {
    log.debug("recoveryStart()");
    if (recoveryChallenger == null) {
      throw new UnsupportedOperationException("Account recovery is not configured");
    }
    if (!recoveryRateLimiter.tryConsume(req.credentialIdentifierBase64())) {
      throw new RateLimitExceededException();
    }
    recoveryChallenger.sendChallenge(req.credentialIdentifier());
  }

  /**
   * Verifies the challenge response and issues a single-use recovery token.
   *
   * @param req the recovery verify request
   * @return the recovery verify response containing the recovery token
   * @throws UnsupportedOperationException if recovery is not configured
   * @throws IllegalArgumentException      if the request contains missing or invalid fields
   * @throws SecurityException             if the challenge response is incorrect or expired
   */
  public RecoveryVerifyResponse recoveryVerify(RecoveryVerifyRequest req) {
    log.debug("recoveryVerify()");
    if (recoveryChallenger == null) {
      throw new UnsupportedOperationException("Account recovery is not configured");
    }
    // Throttle every verification attempt (not just recoveryStart). Without this the OOB
    // challenge code can be brute-forced at request rate, and the unconditional 250ms floor
    // below turns each unthrottled call into a thread-exhaustion DoS. Rate-limit rejection
    // depends only on the credential identifier, not on whether the account exists, so it is
    // not itself an enumeration oracle.
    if (!recoveryRateLimiter.tryConsume(req.credentialIdentifierBase64())) {
      throw new RateLimitExceededException();
    }
    // Enforce a constant-time floor over the whole verification. A RecoveryChallenger may
    // short-circuit (return false instantly) for an unknown credential while doing real
    // comparison work for a known one. Without this floor that latency difference is a
    // user-enumeration oracle that defeats OPAQUE's enumeration resistance: recoveryStart
    // always returns 202, but an attacker could distinguish existing from non-existing
    // accounts by timing recoveryVerify. The floor (applied to both the success and the
    // failure path) bounds the observable timing to its jitter. Implementations should still
    // use constant-time comparison; if a challenger's verification can exceed the floor for
    // existing accounts, raise RECOVERY_VERIFY_MIN_NANOS accordingly.
    final long deadlineNanos = System.nanoTime() + RECOVERY_VERIFY_MIN_NANOS;
    try {
      if (!recoveryChallenger.verifyResponse(
          req.credentialIdentifier(), req.validatedChallengeResponse())) {
        throw new SecurityException("Recovery verification failed");
      }
      String token = UUID.randomUUID().toString();
      recoveryTokenStore.store(token, req.credentialIdentifierBase64());
      return new RecoveryVerifyResponse(token);
    } finally {
      sleepUntil(deadlineNanos);
    }
  }

  /** Busy-free wait until {@code deadlineNanos} (from {@link System#nanoTime()}) has passed. */
  private static void sleepUntil(final long deadlineNanos) {
    long remaining = deadlineNanos - System.nanoTime();
    while (remaining > 0) {
      try {
        Thread.sleep(remaining / 1_000_000L, (int) (remaining % 1_000_000L));
      } catch (InterruptedException e) {
        Thread.currentThread().interrupt();
        return;
      }
      remaining = deadlineNanos - System.nanoTime();
    }
  }

  private void validateRecoveryToken(String token, String expectedCredentialIdentifierBase64) {
    if (recoveryTokenStore == null) {
      throw new SecurityException("Invalid or expired recovery token");
    }
    // Intentionally non-consuming (peek): registrationStart performs no persistent state change
    // (it only returns a registration response), so a token may validate multiple start calls
    // within its TTL. This keeps start idempotent and retryable if the client loses the response.
    // Single use is enforced by the atomic remove() in registrationFinish, which is the only step
    // that mutates account state. See registrationFinish for the full lifecycle.
    String credId = recoveryTokenStore.peek(token)
        .orElseThrow(() -> new SecurityException("Invalid or expired recovery token"));
    if (!credId.equals(expectedCredentialIdentifierBase64)) {
      throw new SecurityException("Recovery token does not match credential");
    }
  }

  // ── Authentication ────────────────────────────────────────────────────────

  /**
   * AKE phase 1: generates KE2 and returns it with a session token.
   * When the credential identifier is unknown, a fake KE2 is returned to prevent
   * user enumeration (RFC 9807 §10.6).
   *
   * @param req the req
   * @return the auth start response
   * @throws IllegalArgumentException if the request contains missing or invalid fields
   * @throws IllegalStateException    if the session store has reached capacity
   */
  public AuthStartResponse authStart(AuthStartRequest req) {
    log.debug("authStart()");
    if (!authRateLimiter.tryConsume(req.credentialIdentifierBase64())) {
      throw new RateLimitExceededException();
    }
    byte[] credentialIdentifier = req.credentialIdentifier();
    KE1 ke1 = req.ke1();

    OpaqueServerKeyDetail keyDetail = keyDetailSupplier.get();
    Optional<VersionedCredential> versioned = credentialStore.loadVersioned(credentialIdentifier);

    ServerKE2Result ke2Result;
    int keyVersion;
    if (versioned.isPresent()) {
      VersionedCredential vc = versioned.get();
      keyVersion = vc.keyVersion();
      Server server = keyDetail.serverForVersion(keyVersion);
      if (server == null) {
        log.warn("No server key for version {} — credential cannot be authenticated", keyVersion);
        // Fall through to fake KE2 to avoid leaking that the credential exists but is unmigrated
        server = keyDetail.currentServer();
        ke2Result = server.generateFakeKE2(ke1, credentialIdentifier, null, null);
        keyVersion = keyDetail.currentVersion();
      } else {
        ke2Result = server.generateKE2(null, vc.record(), credentialIdentifier, ke1, null);
      }
    } else {
      keyVersion = keyDetail.currentVersion();
      ke2Result = keyDetail.currentServer().generateFakeKE2(ke1, credentialIdentifier, null, null);
    }

    String sessionToken = UUID.randomUUID().toString();
    pendingSessionStore.store(sessionToken, ke2Result.serverAuthState(),
        req.credentialIdentifierBase64(), keyVersion);

    return new AuthStartResponse(sessionToken, ke2Result.ke2());
  }

  /**
   * AKE phase 2: verifies the client MAC and returns the session key.
   * <p>
   * When the credential was authenticated with an older server key version,
   * the response includes {@code keyRotationRequired=true} so the client
   * can re-register via the change-password flow.
   *
   * @param req the req
   * @return the auth finish response
   * @throws IllegalArgumentException if the request contains missing or invalid fields
   * @throws SecurityException        if the session token is unknown / expired, or if                                  the client MAC does not verify
   */
  public AuthFinishResponse authFinish(AuthFinishRequest req) {
    log.debug("authFinish(sessionToken={})", req.sessionToken());
    PendingSessionStore.PendingSession pending = pendingSessionStore.remove(req.sessionToken())
        .orElseThrow(() -> new SecurityException("Session not found or expired"));

    OpaqueServerKeyDetail keyDetail = keyDetailSupplier.get();
    Server server = keyDetail.serverForVersion(pending.keyVersion());
    if (server == null) {
      server = keyDetail.currentServer();
    }
    byte[] sessionKey = server.serverFinish(pending.state(), req.ke3());
    String sessionKeyBase64 = B64.encodeToString(sessionKey);
    String token = jwtManager.issueToken(pending.credentialIdentifierBase64(), sessionKeyBase64);

    Boolean rotationRequired = pending.keyVersion() < keyDetail.currentVersion() ? Boolean.TRUE : null;
    return new AuthFinishResponse(sessionKeyBase64, token, rotationRequired);
  }
}
