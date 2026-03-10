package com.codeheadsystems.hofmann.server.manager;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
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
        .hasMessageContaining("does not match");
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
