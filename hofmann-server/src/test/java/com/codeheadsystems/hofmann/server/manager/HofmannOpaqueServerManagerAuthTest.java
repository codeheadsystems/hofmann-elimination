package com.codeheadsystems.hofmann.server.manager;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.codeheadsystems.hofmann.model.opaque.AuthFinishRequest;
import com.codeheadsystems.hofmann.model.opaque.AuthFinishResponse;
import com.codeheadsystems.hofmann.model.opaque.AuthStartRequest;
import com.codeheadsystems.hofmann.model.opaque.AuthStartResponse;
import com.codeheadsystems.hofmann.model.opaque.RegistrationFinishRequest;
import com.codeheadsystems.hofmann.server.ratelimit.RateLimitExceededException;
import com.codeheadsystems.hofmann.server.store.InMemoryCredentialStore;
import com.codeheadsystems.hofmann.server.store.InMemorySessionStore;
import com.codeheadsystems.rfc.opaque.Client;
import com.codeheadsystems.rfc.opaque.Server;
import com.codeheadsystems.rfc.opaque.config.OpaqueConfig;
import com.codeheadsystems.rfc.opaque.model.AuthResult;
import com.codeheadsystems.rfc.opaque.model.ClientAuthState;
import com.codeheadsystems.rfc.opaque.model.ClientRegistrationState;
import com.codeheadsystems.rfc.opaque.model.KE2;
import com.codeheadsystems.rfc.opaque.model.KE3;
import com.codeheadsystems.rfc.opaque.model.RegistrationRecord;
import com.codeheadsystems.rfc.opaque.model.RegistrationResponse;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * Exercises the full OPAQUE authentication flow through {@link HofmannOpaqueServerManager}
 * using a real {@link Client}/{@link Server} pair and in-memory stores.
 *
 * <p>Focuses on the security properties of authStart/authFinish:
 * <ul>
 *   <li>a registered credential authenticates end to end;</li>
 *   <li>an unknown credential still yields a well-formed (fake) KE2 and a stored pending
 *       session, so its shape is indistinguishable from a real one (RFC 9807 §10.6);</li>
 *   <li>pending sessions are single-use — a replayed or bogus session token is rejected;</li>
 *   <li>an already-registered credential cannot be silently taken over by an unauthenticated
 *       registrationFinish.</li>
 * </ul>
 */
class HofmannOpaqueServerManagerAuthTest {

  private static final byte[] JWT_SECRET = "test-secret-must-be-at-least-32-bytes!".getBytes();
  private static final byte[] ALICE = "alice@example.com".getBytes(StandardCharsets.UTF_8);
  private static final byte[] UNKNOWN = "nobody@example.com".getBytes(StandardCharsets.UTF_8);
  private static final byte[] PASSWORD = "correct-horse-battery".getBytes(StandardCharsets.UTF_8);
  private static final OpaqueConfig CONFIG = OpaqueConfig.forTesting();

  private Client client;
  private Server server;
  private InMemoryCredentialStore credentialStore;
  private InMemorySessionStore sessionStore;
  private JwtManager jwtManager;
  private HofmannOpaqueServerManager manager;

  @BeforeEach
  void setUp() {
    client = new Client(CONFIG);
    server = Server.generate(CONFIG);
    credentialStore = new InMemoryCredentialStore();
    sessionStore = new InMemorySessionStore();
    jwtManager = new JwtManager(JWT_SECRET, "test-issuer", 3600, sessionStore);
    manager = new HofmannOpaqueServerManager(server, credentialStore, jwtManager);
  }

  @AfterEach
  void tearDown() {
    manager.shutdown();
  }

  /** Registers {@code credentialIdentifier} with {@link #PASSWORD} and stores the record. */
  private void register(byte[] credentialIdentifier) {
    ClientRegistrationState regState = client.createRegistrationRequest(PASSWORD);
    RegistrationResponse response =
        server.createRegistrationResponse(regState.request(), credentialIdentifier);
    RegistrationRecord record = client.finalizeRegistration(regState, response, null, null);
    credentialStore.store(credentialIdentifier, record);
  }

  @Test
  void authStartThenFinish_happyPath_succeeds() {
    register(ALICE);

    ClientAuthState authState = client.generateKE1(PASSWORD);
    AuthStartResponse startResponse = manager.authStart(new AuthStartRequest(ALICE, authState.ke1()));

    assertThat(startResponse.sessionToken()).isNotBlank();
    KE2 ke2 = startResponse.ke2();
    AuthResult clientResult = client.generateKE3(authState, null, null, ke2);

    AuthFinishResponse finishResponse = manager.authFinish(
        new AuthFinishRequest(startResponse.sessionToken(), clientResult.ke3()));

    assertThat(finishResponse.token()).isNotBlank();
    assertThat(finishResponse.sessionKeyBase64()).isNotBlank();
    // The issued JWT must be immediately verifiable and bound to alice.
    assertThat(jwtManager.verify(finishResponse.token())).isPresent();
    // No key rotation in play for a freshly registered credential.
    assertThat(finishResponse.keyRotationRequired()).isNull();
  }

  @Test
  void authStart_unknownCredential_returnsFakeKe2WithSameShape() {
    register(ALICE);

    // A real KE2 for alice and a fake KE2 for an unregistered credential must be
    // indistinguishable in structure — same field sizes — so timing/shape leaks nothing.
    ClientAuthState realState = client.generateKE1(PASSWORD);
    KE2 realKe2 = manager.authStart(new AuthStartRequest(ALICE, realState.ke1())).ke2();

    ClientAuthState fakeState = client.generateKE1(PASSWORD);
    AuthStartResponse fakeResponse = manager.authStart(new AuthStartRequest(UNKNOWN, fakeState.ke1()));
    KE2 fakeKe2 = fakeResponse.ke2();

    assertThat(fakeResponse.sessionToken()).isNotBlank();
    assertThat(fakeKe2.credentialResponse().evaluatedElement())
        .hasSameSizeAs(realKe2.credentialResponse().evaluatedElement());
    assertThat(fakeKe2.credentialResponse().maskingNonce())
        .hasSameSizeAs(realKe2.credentialResponse().maskingNonce());
    assertThat(fakeKe2.credentialResponse().maskedResponse())
        .hasSameSizeAs(realKe2.credentialResponse().maskedResponse());
    assertThat(fakeKe2.serverNonce()).hasSameSizeAs(realKe2.serverNonce());
    assertThat(fakeKe2.serverAkePublicKey()).hasSameSizeAs(realKe2.serverAkePublicKey());
    assertThat(fakeKe2.serverMac()).hasSameSizeAs(realKe2.serverMac());
  }

  @Test
  void authStart_unknownCredential_stillStoresPendingSession() {
    // For enumeration resistance the fake-KE2 path must also store a pending session, so that
    // a follow-up authFinish reaches MAC verification (fails "Authentication failed") instead of
    // short-circuiting at the session lookup ("Session not found"). The two error paths must not
    // be distinguishable by an attacker probing an unregistered account.
    ClientAuthState fakeState = client.generateKE1(PASSWORD);
    AuthStartResponse fakeResponse = manager.authStart(new AuthStartRequest(UNKNOWN, fakeState.ke1()));

    KE3 bogusKe3 = new KE3(new byte[CONFIG.Nm()]); // all-zero client MAC
    assertThatThrownBy(() -> manager.authFinish(
        new AuthFinishRequest(fakeResponse.sessionToken(), bogusKe3)))
        .isInstanceOf(SecurityException.class)
        .hasMessageContaining("Authentication failed");
  }

  @Test
  void authFinish_replayedSessionToken_isRejected() {
    register(ALICE);

    ClientAuthState authState = client.generateKE1(PASSWORD);
    AuthStartResponse startResponse = manager.authStart(new AuthStartRequest(ALICE, authState.ke1()));
    AuthResult clientResult = client.generateKE3(authState, null, null, startResponse.ke2());
    AuthFinishRequest finishReq =
        new AuthFinishRequest(startResponse.sessionToken(), clientResult.ke3());

    // First finish consumes the single-use pending session.
    manager.authFinish(finishReq);

    // Replaying the same session token must fail — the session is gone.
    assertThatThrownBy(() -> manager.authFinish(finishReq))
        .isInstanceOf(SecurityException.class)
        .hasMessageContaining("Session not found or expired");
  }

  @Test
  void authFinish_unknownSessionToken_isRejected() {
    KE3 anyKe3 = new KE3(new byte[CONFIG.Nm()]);
    assertThatThrownBy(() -> manager.authFinish(new AuthFinishRequest("bogus-token", anyKe3)))
        .isInstanceOf(SecurityException.class)
        .hasMessageContaining("Session not found or expired");
  }

  @Test
  void registrationFinish_duplicateUnauthenticated_leavesRecordUnchanged() {
    register(ALICE);
    RegistrationRecord original = credentialStore.load(ALICE).orElseThrow();

    // A second, unauthenticated registrationFinish (no recovery token) for an already
    // registered credential must not overwrite the record — otherwise anyone knowing alice's
    // credential identifier could re-register it with their own password and take over the
    // account.
    ClientRegistrationState regState = client.createRegistrationRequest(PASSWORD);
    RegistrationResponse response = server.createRegistrationResponse(regState.request(), ALICE);
    RegistrationRecord attackerRecord = client.finalizeRegistration(regState, response, null, null);

    manager.registrationFinish(new RegistrationFinishRequest(ALICE, attackerRecord));

    assertThat(credentialStore.load(ALICE).orElseThrow().clientPublicKey())
        .as("the stored record must be alice's original, not the attacker's")
        .isEqualTo(original.clientPublicKey());
  }

  /**
   * The takeover guard must not double as an existence oracle. registrationFinish is
   * unauthenticated, so if an already-registered credential threw while an unregistered one
   * succeeded, anyone could enumerate accounts one cheap request at a time — defeating the
   * enumeration resistance authStart provides by manufacturing a KE2 for unknown credentials.
   */
  @Test
  void registrationFinish_doesNotRevealWhetherCredentialExists() {
    register(ALICE);
    ClientRegistrationState regState = client.createRegistrationRequest(PASSWORD);
    RegistrationResponse response = server.createRegistrationResponse(regState.request(), ALICE);
    RegistrationRecord record = client.finalizeRegistration(regState, response, null, null);

    // Existing credential: no exception.
    assertThatCode(() ->
        manager.registrationFinish(new RegistrationFinishRequest(ALICE, record)))
        .doesNotThrowAnyException();

    // Unregistered credential: also no exception. The two are indistinguishable to the caller.
    byte[] unregistered = "nobody@example.com".getBytes(java.nio.charset.StandardCharsets.UTF_8);
    assertThatCode(() ->
        manager.registrationFinish(new RegistrationFinishRequest(unregistered, record)))
        .doesNotThrowAnyException();
  }

  /**
   * registrationStart was throttled but finish was not, leaving the probe above free and
   * unlimited. Every attempt must now cost a token whether or not the credential exists.
   *
   * <p>ALICE is registered first deliberately, so this exercises the <em>already exists</em>
   * branch — the one that returns early. Testing only the not-exists branch would pass even if
   * the token were consumed after the existence lookup, which is precisely the ordering bug
   * that would restore free probing of registered accounts.
   */
  @Test
  void registrationFinish_isRateLimited() {
    register(ALICE);
    ClientRegistrationState regState = client.createRegistrationRequest(PASSWORD);
    RegistrationResponse response = server.createRegistrationResponse(regState.request(), ALICE);
    RegistrationRecord record = client.finalizeRegistration(regState, response, null, null);

    HofmannOpaqueServerManager throttled = new HofmannOpaqueServerManager(
        () -> new OpaqueServerKeyDetail(server), credentialStore, jwtManager,
        k -> true, k -> false);
    try {
      assertThatThrownBy(() -> throttled.registrationFinish(
          new RegistrationFinishRequest(ALICE, record)))
          .isInstanceOf(RateLimitExceededException.class);
    } finally {
      throttled.shutdown();
    }
  }
}
