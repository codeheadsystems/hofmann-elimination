package com.codeheadsystems.hofmann.server.manager;

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
import java.util.function.Supplier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Issues and verifies JWT bearer tokens after successful OPAQUE authentication.
 * <p>
 * Tokens are signed with HMAC-SHA256. Each token's JTI is stored in a {@link SessionStore}
 * so that sessions can be revoked before expiry.
 * <p>
 * Key material is supplied via a {@link Supplier Supplier&lt;JwtKeyDetail&gt;}, allowing
 * runtime key rotation without server restart — modeled after the OPRF
 * {@code Supplier<ServerProcessorDetail>} pattern.
 */
public class JwtManager {

  private static final Logger log = LoggerFactory.getLogger(JwtManager.class);

  private final Supplier<JwtKeyDetail> keyDetailSupplier;
  private final SessionStore sessionStore;
  private final String issuer;
  private final long ttlSeconds;

  /**
   * Creates a new JwtManager with a dynamic key supplier.
   *
   * @param keyDetailSupplier supplies the current (and optionally previous) signing key
   * @param issuer            JWT issuer claim
   * @param ttlSeconds        token time-to-live in seconds
   * @param sessionStore      backing store for session data and revocation
   */
  public JwtManager(Supplier<JwtKeyDetail> keyDetailSupplier, String issuer, long ttlSeconds,
                    SessionStore sessionStore) {
    this.keyDetailSupplier = keyDetailSupplier;
    this.sessionStore = sessionStore;
    this.issuer = issuer;
    this.ttlSeconds = ttlSeconds;
    // Fail at construction rather than at first use, and check through the supplier so a rotation
    // cannot introduce a weak key later without the same complaint at issue time.
    requireAdequateKey(keyDetailSupplier.get());
  }

  /**
   * Minimum HMAC-SHA256 key length, in bytes.
   *
   * <p>RFC 8725 §3.5 and RFC 2104 both put the floor at the hash output size. Below it the key is
   * brute-forceable offline from a single captured token — {@code jwtSecretHex: "00"} yielded a
   * one-byte HMAC key that the configuration accepted without comment, and a forged token from a
   * recovered key authenticates as any subject the attacker names.
   */
  public static final int MIN_SIGNING_KEY_BYTES = 32;

  private static void requireAdequateKey(JwtKeyDetail detail) {
    if (detail == null || detail.signingKey() == null
        || detail.signingKey().length < MIN_SIGNING_KEY_BYTES) {
      throw new IllegalArgumentException(
          "JWT signing key must be at least " + MIN_SIGNING_KEY_BYTES
              + " bytes for HMAC-SHA256; got "
              + (detail == null || detail.signingKey() == null
                  ? "none" : detail.signingKey().length + " bytes"));
    }
    // The previous key only verifies, never signs, but a short one is just as forgeable and
    // tokens signed with it are still accepted for the rotation window.
    if (detail.previousKey() != null && detail.previousKey().length < MIN_SIGNING_KEY_BYTES) {
      throw new IllegalArgumentException(
          "Previous JWT signing key must be at least " + MIN_SIGNING_KEY_BYTES + " bytes");
    }
  }

  /**
   * Creates a new JwtManager with a static key (no rotation support).
   *
   * @param secret       HMAC-SHA256 signing secret
   * @param issuer       JWT issuer claim
   * @param ttlSeconds   token time-to-live in seconds
   * @param sessionStore backing store for session data and revocation
   */
  public JwtManager(byte[] secret, String issuer, long ttlSeconds, SessionStore sessionStore) {
    this(() -> new JwtKeyDetail(secret), issuer, ttlSeconds, sessionStore);
  }

  /**
   * Issues a JWT for a successfully authenticated credential.
   *
   * @param credentialIdentifierBase64 base64-encoded credential identifier
   * @param sessionKeyBase64           ignored; retained only for source compatibility
   * @return signed JWT string
   * @deprecated the session key is no longer stored server-side — see {@link SessionData}.
   *     Use {@link #issueToken(String)}; this overload discards its second argument.
   */
  @Deprecated(since = "3.2.0", forRemoval = true)
  public String issueToken(String credentialIdentifierBase64, String sessionKeyBase64) {
    return issueToken(credentialIdentifierBase64);
  }

  /**
   * Issues a JWT for a successfully authenticated credential.
   *
   * @param credentialIdentifierBase64 base64-encoded credential identifier
   * @return signed JWT string
   */
  public String issueToken(String credentialIdentifierBase64) {
    String jti = UUID.randomUUID().toString();
    Instant now = Instant.now();
    Instant expiresAt = now.plusSeconds(ttlSeconds);

    JwtKeyDetail detail = keyDetailSupplier.get();
    Algorithm algorithm = Algorithm.HMAC256(detail.signingKey());

    String token = JWT.create()
        .withIssuer(issuer)
        .withJWTId(jti)
        .withSubject(credentialIdentifierBase64)
        .withIssuedAt(now)
        .withExpiresAt(expiresAt)
        .sign(algorithm);

    sessionStore.store(jti, new SessionData(credentialIdentifierBase64, now, expiresAt));
    log.debug("Issued JWT jti={} for credential", jti);
    return token;
  }

  /**
   * Verifies a JWT and returns the subject and JTI if valid and not revoked.
   * <p>
   * If a {@link JwtKeyDetail#previousKey()} is available, tokens that fail verification
   * with the current signing key are retried with the previous key. This allows graceful
   * key rotation: tokens signed with the old key remain valid until they expire.
   *
   * @param token JWT string
   * @return verify result if valid, empty if invalid or revoked
   */
  public Optional<VerifyResult> verify(String token) {
    JwtKeyDetail detail = keyDetailSupplier.get();

    // Try the current signing key first
    Optional<DecodedJWT> decoded = verifyWith(token, detail.signingKey());

    // Fall back to the previous key during rotation
    if (decoded.isEmpty() && detail.previousKey() != null) {
      decoded = verifyWith(token, detail.previousKey());
    }

    if (decoded.isEmpty()) {
      return Optional.empty();
    }

    DecodedJWT jwt = decoded.get();
    String jti = jwt.getId();
    // Check the session store for revocation
    Optional<SessionData> session = sessionStore.load(jti);
    if (session.isEmpty()) {
      log.debug("JWT jti={} not found in session store (revoked or expired)", jti);
      return Optional.empty();
    }
    return Optional.of(new VerifyResult(jwt.getSubject(), jti));
  }

  private Optional<DecodedJWT> verifyWith(String token, byte[] key) {
    try {
      Algorithm algorithm = Algorithm.HMAC256(key);
      JWTVerifier verifier = JWT.require(algorithm).withIssuer(issuer).build();
      return Optional.of(verifier.verify(token));
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

  /**
   * Revokes all active sessions for the given credential identifier.
   * <p>
   * Must be called when a credential is deleted so that any JWT tokens issued for that
   * credential are immediately rejected, rather than remaining valid until natural expiry.
   *
   * @param credentialIdentifierBase64 base64-encoded credential identifier
   */
  public void revokeByCredentialIdentifier(String credentialIdentifierBase64) {
    sessionStore.revokeByCredentialIdentifier(credentialIdentifierBase64);
  }

  /**
   * Releases resources held by the backing {@link SessionStore}, such as its expiry reaper.
   * <p>
   * Called from {@code HofmannOpaqueServerManager.shutdown()}; the session store is reached
   * only through this manager, so it has no other route to a lifecycle hook.
   */
  public void shutdown() {
    sessionStore.shutdown();
  }

  /**
   * Result of a successful JWT verification.
   *
   * @param subject the JWT subject (credential identifier base64)
   * @param jti     the JWT ID
   */
  public record VerifyResult(String subject, String jti) {
  }
}
