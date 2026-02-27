package com.codeheadsystems.hofmann.server.manager;

import static org.assertj.core.api.Assertions.assertThat;

import com.codeheadsystems.hofmann.model.opaque.RegistrationDeleteRequest;
import com.codeheadsystems.hofmann.server.auth.JwtManager;
import com.codeheadsystems.hofmann.server.store.InMemoryCredentialStore;
import com.codeheadsystems.hofmann.server.store.InMemorySessionStore;
import com.codeheadsystems.rfc.opaque.Server;
import java.util.Base64;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

/**
 * Verifies that {@link HofmannOpaqueServerManager#registrationDelete} immediately invalidates
 * all JWT sessions associated with the deleted credential.
 *
 * <p>Regression test for the bug where a JWT obtained before deletion remained valid after the
 * credential was deleted, because {@code registrationDelete} only removed the credential record
 * without revoking any sessions.
 */
@ExtendWith(MockitoExtension.class)
class HofmannOpaqueServerManagerDeleteTest {

  private static final byte[] JWT_SECRET = "test-secret-must-be-at-least-32-bytes!".getBytes();
  private static final byte[] ALICE = "alice".getBytes();
  private static final byte[] BOB = "bob".getBytes();
  private static final String ALICE_B64 = Base64.getEncoder().encodeToString(ALICE);
  private static final String BOB_B64 = Base64.getEncoder().encodeToString(BOB);

  // Server is required by HofmannOpaqueServerManager's constructor but not used by registrationDelete.
  @Mock private Server server;

  private InMemorySessionStore sessionStore;
  private JwtManager jwtManager;
  private HofmannOpaqueServerManager manager;

  /**
   * Sets up.
   */
  @BeforeEach
  void setUp() {
    sessionStore = new InMemorySessionStore();
    jwtManager = new JwtManager(JWT_SECRET, "test-issuer", 3600, sessionStore);
    manager = new HofmannOpaqueServerManager(server, new InMemoryCredentialStore(), jwtManager);
  }

  /**
   * Tear down.
   */
  @AfterEach
  void tearDown() {
    manager.shutdown();
  }

  /**
   * Registration delete revokes all sessions for deleted credential.
   *
   * <p>Both the token used to authorise the delete and any other tokens issued for the same
   * credential before the delete must be rejected immediately after the call returns.
   */
  @Test
  void registrationDelete_revokesAllSessionsForDeletedCredential() {
    String token1 = jwtManager.issueToken(ALICE_B64, "sessionKey1");
    String token2 = jwtManager.issueToken(ALICE_B64, "sessionKey2");

    assertThat(jwtManager.verify(token1)).isPresent();
    assertThat(jwtManager.verify(token2)).isPresent();

    manager.registrationDelete(new RegistrationDeleteRequest(ALICE), token1);

    assertThat(jwtManager.verify(token1)).as("token used for deletion must be revoked").isEmpty();
    assertThat(jwtManager.verify(token2)).as("other token for same credential must be revoked").isEmpty();
  }

  /**
   * Registration delete does not revoke other users sessions.
   *
   * <p>Deleting one credential must not affect sessions belonging to a different credential.
   */
  @Test
  void registrationDelete_doesNotRevokeOtherCredentialsSessions() {
    String aliceToken = jwtManager.issueToken(ALICE_B64, "sessionKeyA");
    String bobToken = jwtManager.issueToken(BOB_B64, "sessionKeyB");

    manager.registrationDelete(new RegistrationDeleteRequest(ALICE), aliceToken);

    assertThat(jwtManager.verify(aliceToken)).as("alice's token must be revoked").isEmpty();
    assertThat(jwtManager.verify(bobToken)).as("bob's token must be unaffected").isPresent();
  }
}
