package com.codeheadsystems.hofmann.server.manager;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.catchThrowable;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.codeheadsystems.hofmann.model.opaque.RecoveryStartRequest;
import com.codeheadsystems.hofmann.model.opaque.RecoveryVerifyRequest;
import com.codeheadsystems.hofmann.model.opaque.RecoveryVerifyResponse;
import com.codeheadsystems.hofmann.model.opaque.RegistrationFinishRequest;
import com.codeheadsystems.hofmann.model.opaque.RegistrationStartRequest;
import com.codeheadsystems.hofmann.server.recovery.RecoveryChallenger;
import com.codeheadsystems.hofmann.server.store.InMemoryCredentialStore;
import com.codeheadsystems.hofmann.server.store.InMemoryRecoveryTokenStore;
import com.codeheadsystems.hofmann.server.store.InMemorySessionStore;
import com.codeheadsystems.rfc.opaque.Server;
import com.codeheadsystems.rfc.opaque.model.Envelope;
import com.codeheadsystems.rfc.opaque.model.RegistrationRecord;
import com.codeheadsystems.rfc.opaque.model.RegistrationRequest;
import com.codeheadsystems.rfc.opaque.model.RegistrationResponse;
import java.util.Base64;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class HofmannOpaqueServerManagerRecoveryTest {

  private static final byte[] JWT_SECRET = "test-secret-must-be-at-least-32-bytes!".getBytes();
  private static final byte[] ALICE = "alice".getBytes();
  private static final String ALICE_B64 = Base64.getEncoder().encodeToString(ALICE);

  @Mock private Server server;
  @Mock private RecoveryChallenger recoveryChallenger;

  private InMemoryCredentialStore credentialStore;
  private InMemorySessionStore sessionStore;
  private InMemoryRecoveryTokenStore recoveryTokenStore;
  private JwtManager jwtManager;
  private HofmannOpaqueServerManager manager;

  @BeforeEach
  void setUp() {
    credentialStore = new InMemoryCredentialStore();
    sessionStore = new InMemorySessionStore();
    recoveryTokenStore = new InMemoryRecoveryTokenStore();
    jwtManager = new JwtManager(JWT_SECRET, "test-issuer", 3600, sessionStore);
    manager = new HofmannOpaqueServerManager(
        server, credentialStore, jwtManager,
        k -> true, k -> true, // permissive rate limiters
        new com.codeheadsystems.hofmann.server.store.InMemoryPendingSessionStore(),
        recoveryChallenger, recoveryTokenStore, k -> true);
  }

  @AfterEach
  void tearDown() {
    manager.shutdown();
  }

  @Nested
  class RecoveryDisabled {
    private HofmannOpaqueServerManager noRecoveryManager;

    @BeforeEach
    void setUp() {
      noRecoveryManager = new HofmannOpaqueServerManager(server, credentialStore, jwtManager);
    }

    @AfterEach
    void tearDown() {
      noRecoveryManager.shutdown();
    }

    @Test
    void recoveryStart_throwsUnsupported() {
      assertThatThrownBy(() -> noRecoveryManager.recoveryStart(new RecoveryStartRequest(ALICE)))
          .isInstanceOf(UnsupportedOperationException.class);
    }

    @Test
    void recoveryVerify_throwsUnsupported() {
      assertThatThrownBy(() -> noRecoveryManager.recoveryVerify(
          new RecoveryVerifyRequest(ALICE, "123456")))
          .isInstanceOf(UnsupportedOperationException.class);
    }

    @Test
    void isRecoveryEnabled_returnsFalse() {
      assertThat(noRecoveryManager.isRecoveryEnabled()).isFalse();
    }
  }

  @Test
  void isRecoveryEnabled_returnsTrue() {
    assertThat(manager.isRecoveryEnabled()).isTrue();
  }

  @Test
  void recoveryStart_delegatesToChallenger() {
    manager.recoveryStart(new RecoveryStartRequest(ALICE));
    verify(recoveryChallenger).sendChallenge(ALICE);
  }

  @Test
  void recoveryVerify_successReturnsToken() {
    when(recoveryChallenger.verifyResponse(ALICE, "123456")).thenReturn(true);

    RecoveryVerifyResponse response = manager.recoveryVerify(
        new RecoveryVerifyRequest(ALICE, "123456"));

    assertThat(response.recoveryToken()).isNotBlank();
  }

  @Test
  void recoveryVerify_failureThrowsSecurityException() {
    when(recoveryChallenger.verifyResponse(any(), any())).thenReturn(false);

    assertThatThrownBy(() -> manager.recoveryVerify(
        new RecoveryVerifyRequest(ALICE, "wrong")))
        .isInstanceOf(SecurityException.class);
  }

  @Test
  void recoveryVerify_tokenCanBeUsedForReRegistration() {
    when(recoveryChallenger.verifyResponse(ALICE, "123456")).thenReturn(true);
    // Store old credential
    RegistrationRecord oldRecord = new RegistrationRecord(
        new byte[33], new byte[32], new Envelope(new byte[32], new byte[32]));
    credentialStore.store(ALICE, oldRecord);
    String oldToken = jwtManager.issueToken(ALICE_B64, "oldSessionKey");

    // Get recovery token
    RecoveryVerifyResponse response = manager.recoveryVerify(
        new RecoveryVerifyRequest(ALICE, "123456"));
    String recoveryToken = response.recoveryToken();

    // Use recovery token to re-register (finish phase)
    RegistrationRecord newRecord = new RegistrationRecord(
        new byte[33], new byte[32], new Envelope(new byte[32], new byte[32]));
    RegistrationFinishRequest finishReq = new RegistrationFinishRequest(ALICE, newRecord);
    manager.registrationFinish(finishReq, recoveryToken);

    // Old JWT should be revoked
    assertThat(jwtManager.verify(oldToken)).isEmpty();
    // Credential should still exist (new one replaced old)
    assertThat(credentialStore.load(ALICE)).isPresent();
  }

  @Test
  void registrationFinish_recoveryTokenIsConsumedOnce() {
    when(recoveryChallenger.verifyResponse(ALICE, "123456")).thenReturn(true);

    RecoveryVerifyResponse response = manager.recoveryVerify(
        new RecoveryVerifyRequest(ALICE, "123456"));
    String recoveryToken = response.recoveryToken();

    RegistrationRecord record = new RegistrationRecord(
        new byte[33], new byte[32], new Envelope(new byte[32], new byte[32]));
    RegistrationFinishRequest finishReq = new RegistrationFinishRequest(ALICE, record);

    // First use succeeds
    manager.registrationFinish(finishReq, recoveryToken);

    // Second use fails (token consumed)
    assertThatThrownBy(() -> manager.registrationFinish(finishReq, recoveryToken))
        .isInstanceOf(SecurityException.class)
        .hasMessageContaining("Invalid or expired");
  }

  @Test
  void registrationFinish_wrongCredentialThrowsSecurityException() {
    when(recoveryChallenger.verifyResponse(ALICE, "123456")).thenReturn(true);

    RecoveryVerifyResponse response = manager.recoveryVerify(
        new RecoveryVerifyRequest(ALICE, "123456"));
    String recoveryToken = response.recoveryToken();

    // Try to use token for a different credential
    byte[] bob = "bob".getBytes();
    RegistrationRecord record = new RegistrationRecord(
        new byte[33], new byte[32], new Envelope(new byte[32], new byte[32]));
    RegistrationFinishRequest finishReq = new RegistrationFinishRequest(bob, record);

    assertThatThrownBy(() -> manager.registrationFinish(finishReq, recoveryToken))
        .isInstanceOf(SecurityException.class)
        .hasMessageContaining("Invalid or expired");
  }

  /**
   * A wrong identifier and a bogus token must be indistinguishable.
   *
   * <p>Now that a wrong-identifier attempt no longer consumes the token, an attacker holding one
   * can probe identifiers repeatedly rather than once. A distinct "does not match credential"
   * would confirm the token is live and only the identifier is wrong — an identifier-confirmation
   * oracle. Both report the same thing; the distinction is logged at DEBUG instead.
   */
  @Test
  void registrationFinish_wrongCredentialAndBogusTokenAreIndistinguishable() {
    when(recoveryChallenger.verifyResponse(ALICE, "123456")).thenReturn(true);

    String recoveryToken = manager.recoveryVerify(
        new RecoveryVerifyRequest(ALICE, "123456")).recoveryToken();
    RegistrationRecord record = new RegistrationRecord(
        new byte[33], new byte[32], new Envelope(new byte[32], new byte[32]));

    String wrongIdentifier = catchThrowable(() -> manager.registrationFinish(
        new RegistrationFinishRequest("bob".getBytes(), record), recoveryToken)).getMessage();
    String bogusToken = catchThrowable(() -> manager.registrationFinish(
        new RegistrationFinishRequest(ALICE, record), "not-a-real-token")).getMessage();

    assertThat(wrongIdentifier).isEqualTo(bogusToken);
  }

  /**
   * A wrong-identifier attempt must leave the token usable.
   *
   * <p>Consuming the token before comparing the identifier meant anyone who observed a token
   * could invalidate it by replaying it with the wrong identifier — the remove succeeded, the
   * comparison then failed, and the legitimate user had to restart recovery from scratch.
   */
  @Test
  void registrationFinish_wrongCredentialDoesNotConsumeTheToken() {
    when(recoveryChallenger.verifyResponse(ALICE, "123456")).thenReturn(true);

    RecoveryVerifyResponse response = manager.recoveryVerify(
        new RecoveryVerifyRequest(ALICE, "123456"));
    String recoveryToken = response.recoveryToken();

    RegistrationRecord record = new RegistrationRecord(
        new byte[33], new byte[32], new Envelope(new byte[32], new byte[32]));

    // An attacker replays the observed token against the wrong identifier.
    assertThatThrownBy(() -> manager.registrationFinish(
        new RegistrationFinishRequest("bob".getBytes(), record), recoveryToken))
        .isInstanceOf(SecurityException.class)
        .hasMessageContaining("Invalid or expired");

    // The legitimate holder can still complete recovery.
    manager.registrationFinish(new RegistrationFinishRequest(ALICE, record), recoveryToken);
    assertThat(credentialStore.load(ALICE)).isPresent();
  }

  /**
   * Single-use must survive concurrency.
   *
   * <p>The check is now peek-compare-remove rather than remove-compare, so the comparison no
   * longer gates on an atomic operation. Both racers pass the comparison; what keeps exactly one
   * of them from mutating the account is that {@code remove()} returns a value only once. This
   * asserts that directly, since it is the property the reordering could plausibly have broken.
   */
  @Test
  void registrationFinish_recoveryTokenIsConsumedOnce_underConcurrency() throws Exception {
    when(recoveryChallenger.verifyResponse(ALICE, "123456")).thenReturn(true);

    for (int round = 0; round < 200; round++) {
      recoveryTokenStore = new InMemoryRecoveryTokenStore();
      manager = new HofmannOpaqueServerManager(
          server, credentialStore, jwtManager,
          k -> true, k -> true,
          new com.codeheadsystems.hofmann.server.store.InMemoryPendingSessionStore(),
          recoveryChallenger, recoveryTokenStore, k -> true);

      String recoveryToken = manager.recoveryVerify(
          new RecoveryVerifyRequest(ALICE, "123456")).recoveryToken();
      RegistrationRecord record = new RegistrationRecord(
          new byte[33], new byte[32], new Envelope(new byte[32], new byte[32]));
      RegistrationFinishRequest finishReq = new RegistrationFinishRequest(ALICE, record);

      int racers = 8;
      java.util.concurrent.CyclicBarrier barrier =
          new java.util.concurrent.CyclicBarrier(racers);
      java.util.concurrent.atomic.AtomicInteger succeeded =
          new java.util.concurrent.atomic.AtomicInteger();
      Thread[] threads = new Thread[racers];
      for (int i = 0; i < racers; i++) {
        threads[i] = new Thread(() -> {
          try {
            barrier.await();
          } catch (Exception e) {
            throw new IllegalStateException(e);
          }
          try {
            manager.registrationFinish(finishReq, recoveryToken);
            succeeded.incrementAndGet();
          } catch (SecurityException expected) {
            // exactly the losers
          }
        });
        threads[i].start();
      }
      for (Thread t : threads) {
        t.join();
      }

      assertThat(succeeded.get())
          .withFailMessage("round %d: %d callers consumed the same single-use recovery token",
              round, succeeded.get())
          .isEqualTo(1);
    }
  }

  @Test
  void registrationFinish_invalidRecoveryTokenThrowsSecurityException() {
    RegistrationRecord record = new RegistrationRecord(
        new byte[33], new byte[32], new Envelope(new byte[32], new byte[32]));
    RegistrationFinishRequest finishReq = new RegistrationFinishRequest(ALICE, record);

    assertThatThrownBy(() -> manager.registrationFinish(finishReq, "bogus-token"))
        .isInstanceOf(SecurityException.class);
  }

  @Test
  void registrationFinish_withoutToken_worksNormally() {
    RegistrationRecord record = new RegistrationRecord(
        new byte[33], new byte[32], new Envelope(new byte[32], new byte[32]));
    RegistrationFinishRequest finishReq = new RegistrationFinishRequest(ALICE, record);

    // No bearer token — normal registration
    manager.registrationFinish(finishReq);
    assertThat(credentialStore.load(ALICE)).isPresent();
  }

  @Test
  void registrationStart_withValidRecoveryToken_succeeds() {
    when(recoveryChallenger.verifyResponse(ALICE, "123456")).thenReturn(true);
    when(server.createRegistrationResponse(any(), any()))
        .thenReturn(new RegistrationResponse(new byte[33], new byte[33]));

    RecoveryVerifyResponse response = manager.recoveryVerify(
        new RecoveryVerifyRequest(ALICE, "123456"));
    String recoveryToken = response.recoveryToken();

    RegistrationStartRequest startReq = new RegistrationStartRequest(ALICE, new RegistrationRequest(new byte[33]));
    // Should not throw
    manager.registrationStart(startReq, recoveryToken);
  }

  @Test
  void registrationStart_withInvalidRecoveryToken_throwsSecurityException() {
    RegistrationStartRequest startReq = new RegistrationStartRequest(ALICE, new RegistrationRequest(new byte[33]));

    assertThatThrownBy(() -> manager.registrationStart(startReq, "bogus-token"))
        .isInstanceOf(SecurityException.class);
  }
}
