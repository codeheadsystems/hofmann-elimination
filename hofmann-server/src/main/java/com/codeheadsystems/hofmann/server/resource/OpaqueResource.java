package com.codeheadsystems.hofmann.server.resource;

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
import com.codeheadsystems.opaque.config.OpaqueConfig;
import com.codeheadsystems.opaque.model.CredentialRequest;
import com.codeheadsystems.opaque.model.Envelope;
import com.codeheadsystems.opaque.model.KE1;
import com.codeheadsystems.opaque.model.KE2;
import com.codeheadsystems.opaque.model.KE3;
import com.codeheadsystems.opaque.model.RegistrationRecord;
import com.codeheadsystems.opaque.model.RegistrationRequest;
import com.codeheadsystems.opaque.model.RegistrationResponse;
import com.codeheadsystems.opaque.model.ServerAuthState;
import com.codeheadsystems.opaque.model.ServerKE2Result;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.DELETE;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.WebApplicationException;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
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
 * JAX-RS resource implementing the OPAQUE-3DH protocol (RFC 9807).
 * <p>
 * Endpoints:
 * <ul>
 *   <li>{@code POST /opaque/registration/start}  — OPRF evaluation (registration phase)</li>
 *   <li>{@code POST /opaque/registration/finish} — store the client's registration record</li>
 *   <li>{@code DELETE /opaque/registration}      — delete a credential</li>
 *   <li>{@code POST /opaque/auth/start}          — generate KE2 (AKE phase 1)</li>
 *   <li>{@code POST /opaque/auth/finish}         — verify KE3, return session key (AKE phase 2)</li>
 * </ul>
 *
 * <p>Server-side AKE state ({@link ServerAuthState}) is kept in an in-memory map keyed by a
 * random session token. Entries are evicted after a short TTL to prevent unbounded growth.
 * <p>
 * Wire DTOs are defined in {@code hofmann-common} so they can be shared with other framework
 * integrations (Dropwizard, Spring Boot, etc.) without duplicating the model classes.
 */
@Path("/opaque")
@Produces(MediaType.APPLICATION_JSON)
@Consumes(MediaType.APPLICATION_JSON)
public class OpaqueResource {

  private static final Logger log = LoggerFactory.getLogger(OpaqueResource.class);
  private static final Base64.Encoder B64 = Base64.getEncoder();
  private static final Base64.Decoder B64D = Base64.getDecoder();

  /**
   * TTL for pending authentication sessions (seconds).
   */
  private static final long SESSION_TTL_SECONDS = 120;

  /**
   * Maximum number of concurrent pending sessions to prevent memory exhaustion DoS.
   * An attacker spamming /auth/start without completing /auth/finish could otherwise
   * grow the session store unboundedly until OOM.
   */
  private static final int MAX_PENDING_SESSIONS = 10_000;

  private final Server server;
  private final OpaqueConfig config;
  private final CredentialStore credentialStore;
  private final JwtManager jwtManager;

  /**
   * Pending server-side AKE states keyed by session token.
   * Each entry is timestamped for per-entry TTL expiration.
   */
  private final ConcurrentHashMap<String, TimestampedAuthState> pendingSessions = new ConcurrentHashMap<>();

  private final ScheduledExecutorService sessionReaper = Executors.newSingleThreadScheduledExecutor(
      r -> {
        Thread t = new Thread(r, "opaque-session-reaper");
        t.setDaemon(true);
        return t;
      });

  public OpaqueResource(Server server, OpaqueConfig config, CredentialStore credentialStore,
                        JwtManager jwtManager) {
    this.server = server;
    this.config = config;
    this.credentialStore = credentialStore;
    this.jwtManager = jwtManager;
    // Evict individually expired sessions rather than bulk-clearing all sessions,
    // so that a session created 1 second ago is not evicted alongside one created 119 seconds ago.
    sessionReaper.scheduleAtFixedRate(
        () -> {
          Instant cutoff = Instant.now().minusSeconds(SESSION_TTL_SECONDS);
          pendingSessions.entrySet().removeIf(e -> e.getValue().createdAt().isBefore(cutoff));
        }, SESSION_TTL_SECONDS, SESSION_TTL_SECONDS / 4, TimeUnit.SECONDS);
  }

  // ── Registration ─────────────────────────────────────────────────────────

  /**
   * Phase 1 of registration: client sends a blinded password element; server evaluates the OPRF
   * and returns the evaluated element along with the server's public key.
   */
  @POST
  @Path("/registration/start")
  public RegistrationStartResponse registrationStart(RegistrationStartRequest req) {
    log.debug("registrationStart()");
    byte[] blindedElement = decodeBase64(req.blindedElementBase64(), "blindedElement");
    byte[] credentialIdentifier = decodeBase64(req.credentialIdentifierBase64(), "credentialIdentifier");

    RegistrationResponse resp = server.createRegistrationResponse(
        new RegistrationRequest(blindedElement), credentialIdentifier);

    return new RegistrationStartResponse(
        B64.encodeToString(resp.evaluatedElement()),
        B64.encodeToString(resp.serverPublicKey()));
  }

  /**
   * Phase 2 of registration: client finalizes and sends the registration record for storage.
   */
  @POST
  @Path("/registration/finish")
  public Response registrationFinish(RegistrationFinishRequest req) {
    log.debug("registrationFinish()");
    byte[] credentialIdentifier = decodeBase64(req.credentialIdentifierBase64(), "credentialIdentifier");
    byte[] clientPublicKey = decodeBase64(req.clientPublicKeyBase64(), "clientPublicKey");
    byte[] maskingKey = decodeBase64(req.maskingKeyBase64(), "maskingKey");
    byte[] envelopeNonce = decodeBase64(req.envelopeNonceBase64(), "envelopeNonce");
    byte[] authTag = decodeBase64(req.authTagBase64(), "authTag");

    Envelope envelope = new Envelope(envelopeNonce, authTag);
    RegistrationRecord record = new RegistrationRecord(clientPublicKey, maskingKey, envelope);
    credentialStore.store(credentialIdentifier, record);

    return Response.noContent().build();
  }

  /**
   * Deletes a previously registered credential.
   */
  @DELETE
  @Path("/registration")
  public Response registrationDelete(RegistrationDeleteRequest req) {
    log.debug("registrationDelete()");
    byte[] credentialIdentifier = decodeBase64(req.credentialIdentifierBase64(), "credentialIdentifier");
    credentialStore.delete(credentialIdentifier);
    return Response.noContent().build();
  }

  // ── Authentication ────────────────────────────────────────────────────────

  /**
   * AKE phase 1: client sends KE1; server generates and returns KE2.
   * Returns a session token that the client must include in the {@code /auth/finish} call.
   * <p>
   * When the credential identifier is not registered, a fake KE2 is returned to prevent
   * user enumeration (RFC 9807 §10.6).
   */
  @POST
  @Path("/auth/start")
  public AuthStartResponse authStart(AuthStartRequest req) {
    log.debug("authStart()");
    byte[] credentialIdentifier = decodeBase64(req.credentialIdentifierBase64(), "credentialIdentifier");
    byte[] blindedElement = decodeBase64(req.blindedElementBase64(), "blindedElement");
    byte[] clientNonce = decodeBase64(req.clientNonceBase64(), "clientNonce");
    byte[] clientAkePk = decodeBase64(req.clientAkePublicKeyBase64(), "clientAkePublicKey");

    KE1 ke1 = new KE1(new CredentialRequest(blindedElement), clientNonce, clientAkePk);

    Optional<RegistrationRecord> record = credentialStore.load(credentialIdentifier);
    ServerKE2Result ke2Result = record
        .map(r -> server.generateKE2(null, r, credentialIdentifier, ke1, null))
        .orElseGet(() -> server.generateFakeKE2(ke1, credentialIdentifier, null, null));

    // Enforce maximum pending sessions to prevent memory exhaustion DoS
    if (pendingSessions.size() >= MAX_PENDING_SESSIONS) {
      throw new WebApplicationException("Too many pending sessions", Response.Status.SERVICE_UNAVAILABLE);
    }
    String sessionToken = UUID.randomUUID().toString();
    pendingSessions.put(sessionToken,
        new TimestampedAuthState(ke2Result.serverAuthState(), Instant.now(),
            req.credentialIdentifierBase64()));

    KE2 ke2 = ke2Result.ke2();
    return new AuthStartResponse(
        sessionToken,
        B64.encodeToString(ke2.credentialResponse().evaluatedElement()),
        B64.encodeToString(ke2.credentialResponse().maskingNonce()),
        B64.encodeToString(ke2.credentialResponse().maskedResponse()),
        B64.encodeToString(ke2.serverNonce()),
        B64.encodeToString(ke2.serverAkePublicKey()),
        B64.encodeToString(ke2.serverMac()));
  }

  /**
   * AKE phase 2: client sends KE3; server verifies the client MAC and returns the session key.
   */
  @POST
  @Path("/auth/finish")
  public AuthFinishResponse authFinish(AuthFinishRequest req) {
    log.debug("authFinish(sessionToken={})", req.sessionToken());
    TimestampedAuthState timestamped = pendingSessions.remove(req.sessionToken());
    if (timestamped == null
        || timestamped.createdAt().isBefore(Instant.now().minusSeconds(SESSION_TTL_SECONDS))) {
      throw new WebApplicationException(Response.Status.UNAUTHORIZED);
    }
    ServerAuthState authState = timestamped.state();

    KE3 ke3 = new KE3(decodeBase64(req.clientMacBase64(), "clientMac"));
    try {
      byte[] sessionKey = server.serverFinish(authState, ke3);
      String sessionKeyBase64 = B64.encodeToString(sessionKey);
      String token = jwtManager.issueToken(timestamped.credentialIdentifierBase64(), sessionKeyBase64);
      return new AuthFinishResponse(sessionKeyBase64, token);
    } catch (SecurityException e) {
      log.debug("KE3 verification failed: {}", e.getMessage());
      throw new WebApplicationException(Response.Status.UNAUTHORIZED);
    }
  }

  /**
   * Decodes base64 input, returning HTTP 400 for malformed data instead of leaking
   * an IllegalArgumentException stack trace that reveals internal message structure.
   */
  private static byte[] decodeBase64(String encoded, String fieldName) {
    if (encoded == null || encoded.isBlank()) {
      throw new WebApplicationException("Missing required field: " + fieldName,
          Response.Status.BAD_REQUEST);
    }
    try {
      return B64D.decode(encoded);
    } catch (IllegalArgumentException e) {
      throw new WebApplicationException("Invalid base64 in field: " + fieldName,
          Response.Status.BAD_REQUEST);
    }
  }

  private record TimestampedAuthState(ServerAuthState state, Instant createdAt,
                                      String credentialIdentifierBase64) {
  }
}
