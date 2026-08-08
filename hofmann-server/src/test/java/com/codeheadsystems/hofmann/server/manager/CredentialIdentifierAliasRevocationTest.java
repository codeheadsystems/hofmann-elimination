package com.codeheadsystems.hofmann.server.manager;

import static org.assertj.core.api.Assertions.assertThat;

import com.codeheadsystems.hofmann.model.opaque.AuthFinishRequest;
import com.codeheadsystems.hofmann.model.opaque.AuthStartRequest;
import com.codeheadsystems.hofmann.model.opaque.AuthStartResponse;
import com.codeheadsystems.hofmann.model.opaque.RecoveryVerifyRequest;
import com.codeheadsystems.hofmann.model.opaque.RegistrationDeleteRequest;
import com.codeheadsystems.hofmann.server.ratelimit.InMemoryRateLimiter;
import com.codeheadsystems.hofmann.server.ratelimit.RateLimitConfigSupplier;
import com.codeheadsystems.hofmann.server.ratelimit.RateLimitExceededException;
import com.codeheadsystems.hofmann.server.ratelimit.RateLimiter;
import com.codeheadsystems.hofmann.server.recovery.RecoveryChallenger;
import com.codeheadsystems.hofmann.server.store.InMemoryCredentialStore;
import com.codeheadsystems.hofmann.server.store.InMemoryPendingSessionStore;
import com.codeheadsystems.hofmann.server.store.InMemoryRecoveryTokenStore;
import com.codeheadsystems.hofmann.server.store.InMemorySessionStore;
import com.codeheadsystems.rfc.opaque.Client;
import com.codeheadsystems.rfc.opaque.Server;
import com.codeheadsystems.rfc.opaque.config.OpaqueConfig;
import com.codeheadsystems.rfc.opaque.model.AuthResult;
import com.codeheadsystems.rfc.opaque.model.ClientAuthState;
import com.codeheadsystems.rfc.opaque.model.ClientRegistrationState;
import com.codeheadsystems.rfc.opaque.model.KE1;
import com.codeheadsystems.rfc.opaque.config.OpaqueTestConfigs;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.LinkedHashSet;
import java.util.List;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * Server-level regression test for the credential-identifier aliasing vulnerability.
 *
 * <p>{@code Base64.getDecoder()} ignores padding and the unused trailing bits of the final
 * character, so one identifier has up to 32 accepted base64 spellings. The credential store is
 * keyed on the decoded bytes but the session index, the JWT subject and every rate-limiter
 * bucket are keyed on the string. Without canonicalization at the DTO boundary, a session
 * opened under one spelling survives a deletion performed under another, and each spelling
 * gets its own rate-limit budget.
 *
 * <p>The canonicalization lives in hofmann-rfc; this test pins the security property where it
 * actually matters, so that removing the override from any single request model fails here.
 */
class CredentialIdentifierAliasRevocationTest {

  private static final byte[] JWT_SECRET = "test-secret-must-be-at-least-32-bytes!".getBytes();
  private static final byte[] ALICE = "alice@example.com".getBytes(StandardCharsets.UTF_8);
  private static final byte[] PASSWORD = "correct-horse-battery".getBytes(StandardCharsets.UTF_8);
  private static final OpaqueConfig CONFIG = OpaqueTestConfigs.forTesting();
  private static final Base64.Encoder B64 = Base64.getEncoder();

  private static final String CANONICAL = B64.encodeToString(ALICE);
  /** An accepted, non-canonical spelling of the same identifier (padding elided). */
  private static final String ALIAS = CANONICAL.replace("=", "");

  private Client client;
  private Server server;
  private InMemoryCredentialStore credentialStore;
  private JwtManager jwtManager;
  private HofmannOpaqueServerManager manager;

  @BeforeEach
  void setUp() {
    client = new Client(CONFIG);
    server = Server.generate(CONFIG);
    credentialStore = new InMemoryCredentialStore();
    jwtManager = new JwtManager(JWT_SECRET, "test-issuer", 3600, new InMemorySessionStore());
    manager = new HofmannOpaqueServerManager(server, credentialStore, jwtManager);
  }

  @AfterEach
  void tearDown() {
    manager.shutdown();
  }

  private void register() {
    ClientRegistrationState state = client.createRegistrationRequest(PASSWORD);
    credentialStore.store(ALICE, client.finalizeRegistration(
        state, server.createRegistrationResponse(state.request(), ALICE), null, null));
  }

  /** Runs a full OPAQUE authentication using the given base64 spelling, returning the JWT. */
  private String authenticateAs(String spelling) {
    ClientAuthState state = client.generateKE1(PASSWORD);
    KE1 ke1 = state.ke1();
    AuthStartResponse start = manager.authStart(new AuthStartRequest(
        spelling,
        B64.encodeToString(ke1.credentialRequest().blindedElement()),
        B64.encodeToString(ke1.clientNonce()),
        B64.encodeToString(ke1.clientAkePublicKey())));
    AuthResult result = client.generateKE3(state, null, null, start.ke2());
    return manager.authFinish(new AuthFinishRequest(start.sessionToken(), result.ke3())).token();
  }

  @Test
  void aliasSpellingYieldsCanonicalJwtSubject() {
    register();
    assertThat(ALIAS).isNotEqualTo(CANONICAL);
    assertThat(Base64.getDecoder().decode(ALIAS)).isEqualTo(ALICE);

    assertThat(subjectOf(authenticateAs(ALIAS)))
        .as("a JWT issued for an aliased spelling must carry the canonical subject")
        .isEqualTo(CANONICAL);
  }

  @Test
  void sessionOpenedUnderAliasIsRevokedByDeleteUnderCanonicalSpelling() {
    register();
    String aliasJwt = authenticateAs(ALIAS);
    String canonicalJwt = authenticateAs(CANONICAL);
    assertThat(jwtManager.verify(aliasJwt)).isPresent();

    manager.registrationDelete(new RegistrationDeleteRequest(ALICE), canonicalJwt);

    assertThat(jwtManager.verify(aliasJwt))
        .as("a session opened under an aliased spelling must not survive account deletion")
        .isEmpty();
  }

  @Test
  void everyAliasDrawsFromASingleRateLimitBucket() {
    RateLimiter recoveryLimiter = new InMemoryRateLimiter(
        new RateLimitConfigSupplier.DefaultRateLimitConfigSupplier().recoveryRateLimitConfig());
    RecoveryChallenger rejectAll = new RecoveryChallenger() {
      @Override public void sendChallenge(byte[] id) { }
      @Override public boolean verifyResponse(byte[] id, String response) { return false; }
    };
    HofmannOpaqueServerManager m = new HofmannOpaqueServerManager(
        server, credentialStore, jwtManager, k -> true, k -> true,
        new InMemoryPendingSessionStore(), rejectAll, new InMemoryRecoveryTokenStore(),
        recoveryLimiter);
    try {
      List<String> aliases = acceptedSpellings(ALICE);
      assertThat(aliases).as("premise: this identifier has multiple accepted spellings")
          .hasSizeGreaterThan(1);

      int permitted = 0;
      for (String spelling : aliases) {
        for (int i = 0; i < 6; i++) {
          try {
            m.recoveryVerify(new RecoveryVerifyRequest(spelling, "000000"));
            permitted++;
          } catch (RateLimitExceededException e) {
            assertThat(permitted)
                .as("all %d spellings must share one capacity-6 bucket", aliases.size())
                .isEqualTo(6);
            return;
          } catch (SecurityException e) {
            permitted++;
          }
        }
      }
      throw new AssertionError(
          "rate limiter never engaged: " + permitted + " attempts permitted from a capacity-6 bucket");
    } finally {
      m.shutdown();
    }
  }

  private static String subjectOf(String jwt) {
    String payload = new String(
        Base64.getUrlDecoder().decode(jwt.split("\\.")[1]), StandardCharsets.UTF_8);
    int start = payload.indexOf("\"sub\":\"") + 7;
    return payload.substring(start, payload.indexOf('"', start));
  }

  /** Every base64 string the JDK decoder accepts as an encoding of {@code raw}. */
  private static List<String> acceptedSpellings(byte[] raw) {
    String alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    String unpadded = B64.encodeToString(raw).replace("=", "");
    LinkedHashSet<String> found = new LinkedHashSet<>();
    for (char c : alphabet.toCharArray()) {
      String base = unpadded.substring(0, unpadded.length() - 1) + c;
      for (String candidate : List.of(base, base + "=", base + "==")) {
        try {
          if (Arrays.equals(Base64.getDecoder().decode(candidate), raw)) {
            found.add(candidate);
          }
        } catch (IllegalArgumentException ignored) {
          // not a valid encoding, therefore not an alias
        }
      }
    }
    return new ArrayList<>(found);
  }
}
