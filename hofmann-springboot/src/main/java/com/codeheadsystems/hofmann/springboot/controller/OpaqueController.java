package com.codeheadsystems.hofmann.springboot.controller;

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
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

@RestController
@RequestMapping("/opaque")
public class OpaqueController {

  private static final Logger log = LoggerFactory.getLogger(OpaqueController.class);
  private static final Base64.Encoder B64 = Base64.getEncoder();
  private static final Base64.Decoder B64D = Base64.getDecoder();
  private static final long SESSION_TTL_SECONDS = 120;
  private static final int MAX_PENDING_SESSIONS = 10_000;

  private final Server server;
  private final OpaqueConfig config;
  private final CredentialStore credentialStore;
  private final JwtManager jwtManager;

  private final ConcurrentHashMap<String, TimestampedAuthState> pendingSessions = new ConcurrentHashMap<>();

  private final ScheduledExecutorService sessionReaper = Executors.newSingleThreadScheduledExecutor(
      r -> {
        Thread t = new Thread(r, "opaque-session-reaper");
        t.setDaemon(true);
        return t;
      });

  public OpaqueController(Server server, OpaqueConfig config, CredentialStore credentialStore,
                          JwtManager jwtManager) {
    this.server = server;
    this.config = config;
    this.credentialStore = credentialStore;
    this.jwtManager = jwtManager;
    sessionReaper.scheduleAtFixedRate(
        () -> {
          Instant cutoff = Instant.now().minusSeconds(SESSION_TTL_SECONDS);
          pendingSessions.entrySet().removeIf(e -> e.getValue().createdAt().isBefore(cutoff));
        }, SESSION_TTL_SECONDS, SESSION_TTL_SECONDS / 4, TimeUnit.SECONDS);
  }

  private static byte[] decodeBase64(String encoded, String fieldName) {
    if (encoded == null || encoded.isBlank()) {
      throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Missing required field: " + fieldName);
    }
    try {
      return B64D.decode(encoded);
    } catch (IllegalArgumentException e) {
      throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid base64 in field: " + fieldName);
    }
  }

  @PostMapping("/registration/start")
  public RegistrationStartResponse registrationStart(@RequestBody RegistrationStartRequest req) {
    log.debug("registrationStart()");
    byte[] blindedElement = decodeBase64(req.blindedElementBase64(), "blindedElement");
    byte[] credentialIdentifier = decodeBase64(req.credentialIdentifierBase64(), "credentialIdentifier");

    RegistrationResponse resp = server.createRegistrationResponse(
        new RegistrationRequest(blindedElement), credentialIdentifier);

    return new RegistrationStartResponse(
        B64.encodeToString(resp.evaluatedElement()),
        B64.encodeToString(resp.serverPublicKey()));
  }

  @PostMapping("/registration/finish")
  public ResponseEntity<Void> registrationFinish(@RequestBody RegistrationFinishRequest req) {
    log.debug("registrationFinish()");
    byte[] credentialIdentifier = decodeBase64(req.credentialIdentifierBase64(), "credentialIdentifier");
    byte[] clientPublicKey = decodeBase64(req.clientPublicKeyBase64(), "clientPublicKey");
    byte[] maskingKey = decodeBase64(req.maskingKeyBase64(), "maskingKey");
    byte[] envelopeNonce = decodeBase64(req.envelopeNonceBase64(), "envelopeNonce");
    byte[] authTag = decodeBase64(req.authTagBase64(), "authTag");

    Envelope envelope = new Envelope(envelopeNonce, authTag);
    RegistrationRecord record = new RegistrationRecord(clientPublicKey, maskingKey, envelope);
    credentialStore.store(credentialIdentifier, record);

    return ResponseEntity.noContent().build();
  }

  @DeleteMapping("/registration")
  public ResponseEntity<Void> registrationDelete(@RequestBody RegistrationDeleteRequest req) {
    log.debug("registrationDelete()");
    byte[] credentialIdentifier = decodeBase64(req.credentialIdentifierBase64(), "credentialIdentifier");
    credentialStore.delete(credentialIdentifier);
    return ResponseEntity.noContent().build();
  }

  @PostMapping("/auth/start")
  public AuthStartResponse authStart(@RequestBody AuthStartRequest req) {
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

    if (pendingSessions.size() >= MAX_PENDING_SESSIONS) {
      throw new ResponseStatusException(HttpStatus.SERVICE_UNAVAILABLE, "Too many pending sessions");
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

  @PostMapping("/auth/finish")
  public AuthFinishResponse authFinish(@RequestBody AuthFinishRequest req) {
    log.debug("authFinish(sessionToken={})", req.sessionToken());
    TimestampedAuthState timestamped = pendingSessions.remove(req.sessionToken());
    if (timestamped == null
        || timestamped.createdAt().isBefore(Instant.now().minusSeconds(SESSION_TTL_SECONDS))) {
      throw new ResponseStatusException(HttpStatus.UNAUTHORIZED);
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
      throw new ResponseStatusException(HttpStatus.UNAUTHORIZED);
    }
  }

  private record TimestampedAuthState(ServerAuthState state, Instant createdAt,
                                      String credentialIdentifierBase64) {
  }
}
