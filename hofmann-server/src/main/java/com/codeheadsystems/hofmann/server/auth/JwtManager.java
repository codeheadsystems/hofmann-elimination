package com.codeheadsystems.hofmann.server.auth;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.codeheadsystems.hofmann.server.store.SessionData;
import com.codeheadsystems.hofmann.server.store.SessionStore;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Issues and verifies JWT bearer tokens after successful OPAQUE authentication.
 * <p>
 * Tokens are signed with HMAC-SHA256. Each token's JTI is stored in a {@link SessionStore}
 * so that sessions can be revoked before expiry.
 */
public class JwtManager {

  private static final Logger log = LoggerFactory.getLogger(JwtManager.class);

  private final Algorithm algorithm;
  private final JWTVerifier verifier;
  private final SessionStore sessionStore;
  private final String issuer;
  private final long ttlSeconds;

  /**
   * Creates a new JwtManager.
   *
   * @param secret       HMAC-SHA256 signing secret
   * @param issuer       JWT issuer claim
   * @param ttlSeconds   token time-to-live in seconds
   * @param sessionStore backing store for session data and revocation
   */
  public JwtManager(byte[] secret, String issuer, long ttlSeconds, SessionStore sessionStore) {
    this.algorithm = Algorithm.HMAC256(secret);
    this.verifier = JWT.require(algorithm).withIssuer(issuer).build();
    this.sessionStore = sessionStore;
    this.issuer = issuer;
    this.ttlSeconds = ttlSeconds;
  }

  /**
   * Issues a JWT for a successfully authenticated credential.
   *
   * @param credentialIdentifierBase64 base64-encoded credential identifier
   * @param sessionKeyBase64           base64-encoded session key from the 3DH handshake
   * @return signed JWT string
   */
  public String issueToken(String credentialIdentifierBase64, String sessionKeyBase64) {
    String jti = UUID.randomUUID().toString();
    Instant now = Instant.now();
    Instant expiresAt = now.plusSeconds(ttlSeconds);

    String token = JWT.create()
        .withIssuer(issuer)
        .withJWTId(jti)
        .withSubject(credentialIdentifierBase64)
        .withIssuedAt(now)
        .withExpiresAt(expiresAt)
        .sign(algorithm);

    sessionStore.store(jti, new SessionData(credentialIdentifierBase64, sessionKeyBase64, now, expiresAt));
    log.debug("Issued JWT jti={} for credential", jti);
    return token;
  }

  /**
   * Result of a successful JWT verification.
   *
   * @param subject the JWT subject (credential identifier base64)
   * @param jti     the JWT ID
   */
  public record VerifyResult(String subject, String jti) {
  }

  /**
   * Verifies a JWT and returns the subject and JTI if valid and not revoked.
   *
   * @param token JWT string
   * @return verify result if valid, empty if invalid or revoked
   */
  public Optional<VerifyResult> verify(String token) {
    try {
      DecodedJWT decoded = verifier.verify(token);
      String jti = decoded.getId();
      // Check the session store for revocation
      Optional<SessionData> session = sessionStore.load(jti);
      if (session.isEmpty()) {
        log.debug("JWT jti={} not found in session store (revoked or expired)", jti);
        return Optional.empty();
      }
      return Optional.of(new VerifyResult(decoded.getSubject(), jti));
    } catch (JWTVerificationException e) {
      log.debug("JWT verification failed: {}", e.getMessage());
      return Optional.empty();
    }
  }

  /**
   * Revokes a token by its JTI.
   *
   * @param jti the JWT ID to revoke
   */
  public void revoke(String jti) {
    sessionStore.revoke(jti);
  }
}
