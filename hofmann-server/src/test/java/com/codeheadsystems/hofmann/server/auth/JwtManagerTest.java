package com.codeheadsystems.hofmann.server.auth;

import static org.assertj.core.api.Assertions.assertThat;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.codeheadsystems.hofmann.server.store.InMemorySessionStore;
import java.time.Instant;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import com.codeheadsystems.hofmann.server.auth.JwtManager.VerifyResult;

class JwtManagerTest {

  private static final byte[] SECRET = "test-secret-must-be-at-least-32-bytes!".getBytes();
  private static final byte[] WRONG_SECRET = "wrong-secret-must-be-at-least-32-bytes".getBytes();

  private InMemorySessionStore sessionStore;
  private JwtManager jwtManager;

  @BeforeEach
  void setUp() {
    sessionStore = new InMemorySessionStore();
    jwtManager = new JwtManager(SECRET, "test-issuer", 3600, sessionStore);
  }

  @Test
  void issueAndVerify_roundTrip() {
    String token = jwtManager.issueToken("Y3JlZA==", "a2V5");
    Optional<VerifyResult> result = jwtManager.verify(token);
    assertThat(result).isPresent();
    assertThat(result.get().subject()).isEqualTo("Y3JlZA==");
  }

  @Test
  void verify_revokedToken_returnsEmpty() {
    String token = jwtManager.issueToken("Y3JlZA==", "a2V5");
    String jti = JWT.decode(token).getId();
    jwtManager.revoke(jti);

    assertThat(jwtManager.verify(token)).isEmpty();
  }

  @Test
  void verify_wrongSecret_returnsEmpty() {
    String token = jwtManager.issueToken("Y3JlZA==", "a2V5");

    JwtManager wrongManager = new JwtManager(WRONG_SECRET, "test-issuer", 3600,
        new InMemorySessionStore());
    assertThat(wrongManager.verify(token)).isEmpty();
  }

  @Test
  void verify_expiredToken_returnsEmpty() {
    // Create a manager with 0 TTL — token expires immediately
    JwtManager shortLived = new JwtManager(SECRET, "test-issuer", 0, sessionStore);
    // Can't create with 0 TTL as it'd be at the boundary — use a manually expired token
    String token = JWT.create()
        .withIssuer("test-issuer")
        .withJWTId("expired-jti")
        .withSubject("Y3JlZA==")
        .withIssuedAt(Instant.now().minusSeconds(7200))
        .withExpiresAt(Instant.now().minusSeconds(3600))
        .sign(Algorithm.HMAC256(SECRET));

    assertThat(jwtManager.verify(token)).isEmpty();
  }

  @Test
  void verify_tamperedToken_returnsEmpty() {
    String token = jwtManager.issueToken("Y3JlZA==", "a2V5");
    // Flip a character in the signature part
    String tampered = token.substring(0, token.length() - 2) + "XX";
    assertThat(jwtManager.verify(tampered)).isEmpty();
  }
}
