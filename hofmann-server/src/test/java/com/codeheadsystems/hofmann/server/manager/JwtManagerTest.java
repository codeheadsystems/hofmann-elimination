package com.codeheadsystems.hofmann.server.manager;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.codeheadsystems.hofmann.server.manager.JwtManager.VerifyResult;
import com.codeheadsystems.hofmann.server.store.InMemorySessionStore;
import java.time.Instant;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Supplier;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * The type Jwt manager test.
 */
class JwtManagerTest {

  private static final byte[] SECRET = "test-secret-must-be-at-least-32-bytes!".getBytes();
  private static final byte[] WRONG_SECRET = "wrong-secret-must-be-at-least-32-bytes".getBytes();
  private static final byte[] NEW_SECRET = "new--secret-must-be-at-least-32-bytes!".getBytes();

  private InMemorySessionStore sessionStore;
  private JwtManager jwtManager;

  /**
   * Sets up.
   */
  @BeforeEach
  void setUp() {
    sessionStore = new InMemorySessionStore();
    jwtManager = new JwtManager(SECRET, "test-issuer", 3600, sessionStore);
  }

  /**
   * Issue and verify round trip.
   */
  @Test
  void issueAndVerify_roundTrip() {
    String token = jwtManager.issueToken("Y3JlZA==", "a2V5");
    Optional<VerifyResult> result = jwtManager.verify(token);
    assertThat(result).isPresent();
    assertThat(result.get().subject()).isEqualTo("Y3JlZA==");
  }

  /**
   * Verify revoked token returns empty.
   */
  @Test
  void verify_revokedToken_returnsEmpty() {
    String token = jwtManager.issueToken("Y3JlZA==", "a2V5");
    String jti = JWT.decode(token).getId();
    jwtManager.revoke(jti);

    assertThat(jwtManager.verify(token)).isEmpty();
  }

  /**
   * Verify wrong secret returns empty.
   */
  @Test
  void verify_wrongSecret_returnsEmpty() {
    String token = jwtManager.issueToken("Y3JlZA==", "a2V5");

    JwtManager wrongManager = new JwtManager(WRONG_SECRET, "test-issuer", 3600,
        new InMemorySessionStore());
    assertThat(wrongManager.verify(token)).isEmpty();
  }

  /**
   * Verify expired token returns empty.
   */
  @Test
  void verify_expiredToken_returnsEmpty() {
    // Create a manually expired token
    String token = JWT.create()
        .withIssuer("test-issuer")
        .withJWTId("expired-jti")
        .withSubject("Y3JlZA==")
        .withIssuedAt(Instant.now().minusSeconds(7200))
        .withExpiresAt(Instant.now().minusSeconds(3600))
        .sign(Algorithm.HMAC256(SECRET));

    assertThat(jwtManager.verify(token)).isEmpty();
  }

  /**
   * Verify tampered token returns empty.
   */
  @Test
  void verify_tamperedToken_returnsEmpty() {
    String token = jwtManager.issueToken("Y3JlZA==", "a2V5");
    // Flip a character in the signature part
    String tampered = token.substring(0, token.length() - 2) + "XX";
    assertThat(jwtManager.verify(tampered)).isEmpty();
  }

  // ── Key rotation tests ──────────────────────────────────────────────────

  /**
   * Tokens signed with the old key verify successfully when it is set as previousKey.
   */
  @Test
  void verify_withPreviousKey_acceptsOldTokens() {
    // Sign a token with the original key
    String token = jwtManager.issueToken("Y3JlZA==", "a2V5");

    // Rotate: new signing key, old key as previous
    JwtManager rotated = new JwtManager(
        () -> new JwtKeyDetail(NEW_SECRET, SECRET),
        "test-issuer", 3600, sessionStore);

    Optional<VerifyResult> result = rotated.verify(token);
    assertThat(result).isPresent();
    assertThat(result.get().subject()).isEqualTo("Y3JlZA==");
  }

  /**
   * After rotation, new tokens are signed with the current key (not the previous one).
   */
  @Test
  void issueToken_afterRotation_signsWithCurrentKey() {
    JwtManager rotated = new JwtManager(
        () -> new JwtKeyDetail(NEW_SECRET, SECRET),
        "test-issuer", 3600, sessionStore);

    String token = rotated.issueToken("Y3JlZA==", "a2V5");

    // Verify with new key only — should succeed
    JwtManager newKeyOnly = new JwtManager(NEW_SECRET, "test-issuer", 3600, sessionStore);
    assertThat(newKeyOnly.verify(token)).isPresent();

    // Verify with old key only — should fail
    JwtManager oldKeyOnly = new JwtManager(SECRET, "test-issuer", 3600, new InMemorySessionStore());
    assertThat(oldKeyOnly.verify(token)).isEmpty();
  }

  /**
   * When neither the current nor previous key matches, verification fails.
   */
  @Test
  void verify_neitherKeyMatches_returnsEmpty() {
    String token = jwtManager.issueToken("Y3JlZA==", "a2V5");

    // Rotate to completely different keys
    JwtManager rotated = new JwtManager(
        () -> new JwtKeyDetail(NEW_SECRET, WRONG_SECRET),
        "test-issuer", 3600, sessionStore);

    assertThat(rotated.verify(token)).isEmpty();
  }

  /**
   * Dynamic supplier: key can change between calls without rebuilding JwtManager.
   */
  @Test
  void verify_dynamicSupplier_picksUpKeyChange() {
    AtomicReference<JwtKeyDetail> detailRef = new AtomicReference<>(new JwtKeyDetail(SECRET));
    JwtManager dynamic = new JwtManager(detailRef::get, "test-issuer", 3600, sessionStore);

    // Issue with original key
    String token1 = dynamic.issueToken("Y3JlZA==", "a2V5");
    assertThat(dynamic.verify(token1)).isPresent();

    // Rotate dynamically
    detailRef.set(new JwtKeyDetail(NEW_SECRET, SECRET));

    // Old token still verifies (via previousKey)
    assertThat(dynamic.verify(token1)).isPresent();

    // New token is signed with new key
    String token2 = dynamic.issueToken("bmV3", "a2V5");
    assertThat(dynamic.verify(token2)).isPresent();

    // Complete rotation: drop previous key
    detailRef.set(new JwtKeyDetail(NEW_SECRET));

    // New token still works
    assertThat(dynamic.verify(token2)).isPresent();

    // Old token no longer works
    assertThat(dynamic.verify(token1)).isEmpty();
  }

  /**
   * A weak key must be refused at construction.
   */
  @Test
  void construct_withShortSigningKey_throws() {
    assertThatThrownBy(() ->
        new JwtManager(new byte[]{0x00}, "test-issuer", 3600, new InMemorySessionStore()))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("at least 32 bytes");
  }

  /**
   * A rotation to a weak key must be refused at issue time, not silently used for signing.
   *
   * <p>This is the case the construction-time check alone misses, and it is the one the
   * {@code Supplier} exists to enable: the manager starts with a good key, so construction
   * passes, and the weak key arrives later. {@code Algorithm.HMAC256} accepts any length without
   * complaint, so without the re-check in {@code issueToken} a one-byte key would sign real
   * tokens — the {@code jwtSecretHex: "00"} finding, reached by rotation instead of by config.
   */
  @Test
  void issueToken_afterRotationToAShortKey_throwsRatherThanSigning() {
    AtomicReference<JwtKeyDetail> detailRef = new AtomicReference<>(new JwtKeyDetail(SECRET));
    JwtManager dynamic = new JwtManager(detailRef::get, "test-issuer", 3600, sessionStore);

    // Healthy to begin with.
    assertThat(dynamic.verify(dynamic.issueToken("Y3JlZA=="))).isPresent();

    // Someone rotates in a one-byte key.
    detailRef.set(new JwtKeyDetail(new byte[]{0x00}));

    assertThatThrownBy(() -> dynamic.issueToken("Y3JlZA=="))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("at least 32 bytes");
  }

  /**
   * A short previous key is skipped during verification, not thrown on.
   *
   * <p>Verification runs on every authenticated request, so throwing here would answer a
   * configuration mistake with a total outage. Skipping refuses tokens forged under the weak key
   * while leaving tokens signed with the good current key working.
   */
  @Test
  void verify_withShortPreviousKey_skipsItWithoutBreakingCurrentTokens() {
    AtomicReference<JwtKeyDetail> detailRef = new AtomicReference<>(new JwtKeyDetail(SECRET));
    JwtManager dynamic = new JwtManager(detailRef::get, "test-issuer", 3600, sessionStore);
    String goodToken = dynamic.issueToken("Y3JlZA==");

    // A token forged under the weak key that is about to become the "previous" key.
    String forged = JWT.create()
        .withIssuer("test-issuer")
        .withJWTId("forged-jti")
        .withSubject("Y3JlZA==")
        .withIssuedAt(Instant.now())
        .withExpiresAt(Instant.now().plusSeconds(3600))
        .sign(Algorithm.HMAC256(new byte[]{0x00}));

    detailRef.set(new JwtKeyDetail(SECRET, new byte[]{0x00}));

    // Live sessions survive...
    assertThat(dynamic.verify(goodToken)).isPresent();
    // ...and the forgery under the weak previous key is refused.
    assertThat(dynamic.verify(forged)).isEmpty();
  }
}
