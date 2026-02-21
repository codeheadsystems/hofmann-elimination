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
  private static final long SESSION_TTL_SECONDS = 120;
  private static final int MAX_PENDING_SESSIONS = 10_000;

  private final Server server;
  private final CredentialStore credentialStore;
  private final JwtManager jwtManager;

  private final ConcurrentHashMap<String, TimestampedAuthState> pendingSessions = new ConcurrentHashMap<>();

  private final ScheduledExecutorService sessionReaper = Executors.newSingleThreadScheduledExecutor(
      r -> {
        Thread t = new Thread(r, "opaque-session-reaper");
        t.setDaemon(true);
        return t;
      });

  public OpaqueController(Server server, CredentialStore credentialStore, JwtManager jwtManager) {
    this.server = server;
    this.credentialStore = credentialStore;
    this.jwtManager = jwtManager;
    sessionReaper.scheduleAtFixedRate(
        () -> {
          Instant cutoff = Instant.now().minusSeconds(SESSION_TTL_SECONDS);
          pendingSessions.entrySet().removeIf(e -> e.getValue().createdAt().isBefore(cutoff));
        }, SESSION_TTL_SECONDS, SESSION_TTL_SECONDS / 4, TimeUnit.SECONDS);
  }

  @PostMapping("/registration/start")
  public RegistrationStartResponse registrationStart(@RequestBody RegistrationStartRequest req) {
    log.debug("registrationStart()");
    try {
      return new RegistrationStartResponse(
          server.createRegistrationResponse(req.registrationRequest(), req.credentialIdentifier()));
    } catch (IllegalArgumentException e) {
      throw new ResponseStatusException(HttpStatus.BAD_REQUEST, e.getMessage());
    }
  }

  @PostMapping("/registration/finish")
  public ResponseEntity<Void> registrationFinish(@RequestBody RegistrationFinishRequest req) {
    log.debug("registrationFinish()");
    try {
      credentialStore.store(req.credentialIdentifier(), req.registrationRecord());
      return ResponseEntity.noContent().build();
    } catch (IllegalArgumentException e) {
      throw new ResponseStatusException(HttpStatus.BAD_REQUEST, e.getMessage());
    }
  }

  @DeleteMapping("/registration")
  public ResponseEntity<Void> registrationDelete(@RequestBody RegistrationDeleteRequest req) {
    log.debug("registrationDelete()");
    try {
      credentialStore.delete(req.credentialIdentifier());
      return ResponseEntity.noContent().build();
    } catch (IllegalArgumentException e) {
      throw new ResponseStatusException(HttpStatus.BAD_REQUEST, e.getMessage());
    }
  }

  @PostMapping("/auth/start")
  public AuthStartResponse authStart(@RequestBody AuthStartRequest req) {
    log.debug("authStart()");
    try {
      byte[] credentialIdentifier = req.credentialIdentifier();
      KE1 ke1 = req.ke1();

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

      return new AuthStartResponse(sessionToken, ke2Result.ke2());
    } catch (IllegalArgumentException e) {
      throw new ResponseStatusException(HttpStatus.BAD_REQUEST, e.getMessage());
    }
  }

  @PostMapping("/auth/finish")
  public AuthFinishResponse authFinish(@RequestBody AuthFinishRequest req) {
    log.debug("authFinish(sessionToken={})", req.sessionToken());
    TimestampedAuthState timestamped = pendingSessions.remove(req.sessionToken());
    if (timestamped == null
        || timestamped.createdAt().isBefore(Instant.now().minusSeconds(SESSION_TTL_SECONDS))) {
      throw new ResponseStatusException(HttpStatus.UNAUTHORIZED);
    }
    try {
      byte[] sessionKey = server.serverFinish(timestamped.state(), req.ke3());
      String sessionKeyBase64 = B64.encodeToString(sessionKey);
      String token = jwtManager.issueToken(timestamped.credentialIdentifierBase64(), sessionKeyBase64);
      return new AuthFinishResponse(sessionKeyBase64, token);
    } catch (SecurityException e) {
      log.debug("KE3 verification failed: {}", e.getMessage());
      throw new ResponseStatusException(HttpStatus.UNAUTHORIZED);
    } catch (IllegalArgumentException e) {
      throw new ResponseStatusException(HttpStatus.BAD_REQUEST, e.getMessage());
    }
  }

  private record TimestampedAuthState(com.codeheadsystems.opaque.model.ServerAuthState state,
                                      Instant createdAt,
                                      String credentialIdentifierBase64) {
  }
}
