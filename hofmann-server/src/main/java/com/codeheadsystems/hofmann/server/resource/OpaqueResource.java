package com.codeheadsystems.hofmann.server.resource;

import com.codeheadsystems.hofmann.model.opaque.AuthFinishRequest;
import com.codeheadsystems.hofmann.model.opaque.AuthFinishResponse;
import com.codeheadsystems.hofmann.model.opaque.AuthStartRequest;
import com.codeheadsystems.hofmann.model.opaque.AuthStartResponse;
import com.codeheadsystems.hofmann.model.opaque.RegistrationDeleteRequest;
import com.codeheadsystems.hofmann.model.opaque.RegistrationFinishRequest;
import com.codeheadsystems.hofmann.model.opaque.RegistrationStartRequest;
import com.codeheadsystems.hofmann.model.opaque.RegistrationStartResponse;
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

  private final Server server;
  private final OpaqueConfig config;
  private final CredentialStore credentialStore;

  /**
   * Pending server-side AKE states keyed by session token.
   */
  private final ConcurrentHashMap<String, ServerAuthState> pendingSessions = new ConcurrentHashMap<>();

  private final ScheduledExecutorService sessionReaper = Executors.newSingleThreadScheduledExecutor(
      r -> new Thread(r, "opaque-session-reaper"));

  public OpaqueResource(Server server, OpaqueConfig config, CredentialStore credentialStore) {
    this.server = server;
    this.config = config;
    this.credentialStore = credentialStore;
    sessionReaper.scheduleAtFixedRate(
        pendingSessions::clear, SESSION_TTL_SECONDS, SESSION_TTL_SECONDS, TimeUnit.SECONDS);
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
    byte[] blindedElement = B64D.decode(req.blindedElementBase64());
    byte[] credentialIdentifier = B64D.decode(req.credentialIdentifierBase64());

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
    byte[] credentialIdentifier = B64D.decode(req.credentialIdentifierBase64());
    byte[] clientPublicKey = B64D.decode(req.clientPublicKeyBase64());
    byte[] maskingKey = B64D.decode(req.maskingKeyBase64());
    byte[] envelopeNonce = B64D.decode(req.envelopeNonceBase64());
    byte[] authTag = B64D.decode(req.authTagBase64());

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
    byte[] credentialIdentifier = B64D.decode(req.credentialIdentifierBase64());
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
    byte[] credentialIdentifier = B64D.decode(req.credentialIdentifierBase64());
    byte[] blindedElement = B64D.decode(req.blindedElementBase64());
    byte[] clientNonce = B64D.decode(req.clientNonceBase64());
    byte[] clientAkePk = B64D.decode(req.clientAkePublicKeyBase64());

    KE1 ke1 = new KE1(new CredentialRequest(blindedElement), clientNonce, clientAkePk);

    Optional<RegistrationRecord> record = credentialStore.load(credentialIdentifier);
    ServerKE2Result ke2Result = record
        .map(r -> server.generateKE2(null, r, credentialIdentifier, ke1, null))
        .orElseGet(() -> server.generateFakeKE2(ke1, credentialIdentifier, null, null));

    String sessionToken = UUID.randomUUID().toString();
    pendingSessions.put(sessionToken, ke2Result.serverAuthState());

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
    ServerAuthState authState = pendingSessions.remove(req.sessionToken());
    if (authState == null) {
      throw new WebApplicationException("Unknown or expired session token", Response.Status.UNAUTHORIZED);
    }

    KE3 ke3 = new KE3(B64D.decode(req.clientMacBase64()));
    try {
      byte[] sessionKey = server.serverFinish(authState, ke3);
      return new AuthFinishResponse(B64.encodeToString(sessionKey));
    } catch (SecurityException e) {
      log.debug("KE3 verification failed: {}", e.getMessage());
      throw new WebApplicationException(Response.Status.UNAUTHORIZED);
    }
  }
}
