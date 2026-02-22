package com.codeheadsystems.hofmann.server.manager;

import com.codeheadsystems.hofmann.model.opaque.AuthFinishRequest;
import com.codeheadsystems.hofmann.model.opaque.AuthFinishResponse;
import com.codeheadsystems.hofmann.model.opaque.AuthStartRequest;
import com.codeheadsystems.hofmann.model.opaque.AuthStartResponse;
import com.codeheadsystems.hofmann.model.opaque.RegistrationDeleteRequest;
import com.codeheadsystems.hofmann.model.opaque.RegistrationFinishRequest;
import com.codeheadsystems.hofmann.model.opaque.RegistrationStartRequest;
import com.codeheadsystems.hofmann.model.opaque.RegistrationStartResponse;
import com.codeheadsystems.hofmann.server.auth.JwtManager;
import com.codeheadsystems.hofmann.server.store.CredentialStore;
import com.codeheadsystems.opaque.Server;
import com.codeheadsystems.opaque.model.KE1;
import com.codeheadsystems.opaque.model.RegistrationRecord;
import com.codeheadsystems.opaque.model.ServerKE2Result;
import java.time.Instant;
import java.util.Base64;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
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
 * <strong>Exception contract</strong> (callers should map these to HTTP responses):
 * <ul>
 *   <li>{@link IllegalArgumentException} — bad / missing request data → HTTP 400</li>
 *   <li>{@link SecurityException}        — auth failure or expired session → HTTP 401</li>
 *   <li>{@link IllegalStateException}    — session store at capacity → HTTP 503</li>
 * </ul>
 */
public class HofmannOpaqueServerManager {

  private static final Logger log = LoggerFactory.getLogger(HofmannOpaqueServerManager.class);
  private static final Base64.Encoder B64 = Base64.getEncoder();

  /**
   * TTL for pending authentication sessions (seconds).
   */
  private static final long SESSION_TTL_SECONDS = 120;

  /**
   * Maximum concurrent pending sessions.
   * An attacker spamming /auth/start without finishing could otherwise cause OOM.
   */
  private static final int MAX_PENDING_SESSIONS = 10_000;

  private final Server server;
  private final CredentialStore credentialStore;
  private final JwtManager jwtManager;

  private final ConcurrentHashMap<String, TimestampedAuthState> pendingSessions =
      new ConcurrentHashMap<>();

  private final ScheduledExecutorService sessionReaper =
      Executors.newSingleThreadScheduledExecutor(r -> {
        Thread t = new Thread(r, "opaque-session-reaper");
        t.setDaemon(true);
        return t;
      });

  public HofmannOpaqueServerManager(Server server, CredentialStore credentialStore, JwtManager jwtManager) {
    this.server = server;
    this.credentialStore = credentialStore;
    this.jwtManager = jwtManager;
    sessionReaper.scheduleAtFixedRate(
        () -> {
          Instant cutoff = Instant.now().minusSeconds(SESSION_TTL_SECONDS);
          pendingSessions.entrySet().removeIf(e -> e.getValue().createdAt().isBefore(cutoff));
        }, SESSION_TTL_SECONDS, SESSION_TTL_SECONDS / 4, TimeUnit.SECONDS);
  }

  /**
   * Shuts down the session reaper thread pool.
   * <p>
   * Should be called on application shutdown to release the background thread.
   * In Dropwizard, register this instance as a {@code Managed} component.
   * In Spring Boot, declare the bean with {@code @Bean(destroyMethod = "shutdown")}.
   */
  public void shutdown() {
    sessionReaper.shutdown();
  }

  // ── Registration ─────────────────────────────────────────────────────────

  /**
   * Phase 1 of registration: evaluates the OPRF on the blinded element and returns
   * the evaluated element + server public key.
   *
   * @throws IllegalArgumentException if the request contains missing or invalid fields
   */
  public RegistrationStartResponse registrationStart(RegistrationStartRequest req) {
    log.debug("registrationStart()");
    return new RegistrationStartResponse(
        server.createRegistrationResponse(req.registrationRequest(), req.credentialIdentifier()));
  }

  /**
   * Phase 2 of registration: stores the client's registration record.
   *
   * @throws IllegalArgumentException if the request contains missing or invalid fields
   */
  public void registrationFinish(RegistrationFinishRequest req) {
    log.debug("registrationFinish()");
    credentialStore.store(req.credentialIdentifier(), req.registrationRecord());
  }

  /**
   * Deletes a previously registered credential.
   * <p>
   * Requires a valid JWT bearer token whose subject (credential identifier) matches the
   * credential being deleted.  This prevents unauthenticated or cross-user deletion.
   *
   * @param req         the delete request containing the credential identifier
   * @param bearerToken the JWT bearer token (without "Bearer " prefix)
   * @throws IllegalArgumentException if the request contains missing or invalid fields
   * @throws SecurityException        if the token is missing, invalid, expired, or does not
   *                                  match the credential being deleted
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
  }

  // ── Authentication ────────────────────────────────────────────────────────

  /**
   * AKE phase 1: generates KE2 and returns it with a session token.
   * When the credential identifier is unknown, a fake KE2 is returned to prevent
   * user enumeration (RFC 9807 §10.6).
   *
   * @throws IllegalArgumentException if the request contains missing or invalid fields
   * @throws IllegalStateException    if the session store has reached capacity
   */
  public AuthStartResponse authStart(AuthStartRequest req) {
    log.debug("authStart()");
    byte[] credentialIdentifier = req.credentialIdentifier();
    KE1 ke1 = req.ke1();

    Optional<RegistrationRecord> record = credentialStore.load(credentialIdentifier);
    ServerKE2Result ke2Result = record
        .map(r -> server.generateKE2(null, r, credentialIdentifier, ke1, null))
        .orElseGet(() -> server.generateFakeKE2(ke1, credentialIdentifier, null, null));

    if (pendingSessions.size() >= MAX_PENDING_SESSIONS) {
      throw new IllegalStateException("Too many pending sessions");
    }
    String sessionToken = UUID.randomUUID().toString();
    pendingSessions.put(sessionToken,
        new TimestampedAuthState(ke2Result.serverAuthState(), Instant.now(),
            req.credentialIdentifierBase64()));

    return new AuthStartResponse(sessionToken, ke2Result.ke2());
  }

  /**
   * AKE phase 2: verifies the client MAC and returns the session key.
   *
   * @throws IllegalArgumentException if the request contains missing or invalid fields
   * @throws SecurityException        if the session token is unknown / expired, or if
   *                                  the client MAC does not verify
   */
  public AuthFinishResponse authFinish(AuthFinishRequest req) {
    log.debug("authFinish(sessionToken={})", req.sessionToken());
    TimestampedAuthState timestamped = pendingSessions.remove(req.sessionToken());
    if (timestamped == null
        || timestamped.createdAt().isBefore(Instant.now().minusSeconds(SESSION_TTL_SECONDS))) {
      throw new SecurityException("Session not found or expired");
    }
    byte[] sessionKey = server.serverFinish(timestamped.state(), req.ke3());
    String sessionKeyBase64 = B64.encodeToString(sessionKey);
    String token = jwtManager.issueToken(timestamped.credentialIdentifierBase64(), sessionKeyBase64);
    return new AuthFinishResponse(sessionKeyBase64, token);
  }

  private record TimestampedAuthState(
      com.codeheadsystems.opaque.model.ServerAuthState state,
      Instant createdAt,
      String credentialIdentifierBase64) {
  }
}
