package com.codeheadsystems.hofmann.server.manager;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

import com.codeheadsystems.hofmann.model.opaque.RecoveryVerifyRequest;
import com.codeheadsystems.hofmann.server.ratelimit.InMemoryRateLimiter;
import com.codeheadsystems.hofmann.server.ratelimit.RateLimitConfigSupplier;
import com.codeheadsystems.hofmann.server.ratelimit.RateLimitExceededException;
import com.codeheadsystems.hofmann.server.ratelimit.RateLimiter;
import com.codeheadsystems.hofmann.server.recovery.RecoveryChallenger;
import com.codeheadsystems.hofmann.server.store.InMemoryCredentialStore;
import com.codeheadsystems.hofmann.server.store.InMemoryPendingSessionStore;
import com.codeheadsystems.hofmann.server.store.InMemoryRecoveryTokenStore;
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
 * Verifies that {@link HofmannOpaqueServerManager#recoveryVerify} is throttled by the recovery
 * rate limiter (issue 7 fix). Without this throttle the out-of-band challenge code could be
 * brute-forced at request rate and the unconditional 250&nbsp;ms latency floor would turn each
 * unthrottled call into a thread-exhaustion DoS.
 */
@ExtendWith(MockitoExtension.class)
class HofmannOpaqueServerManagerRateLimitTest {

  private static final byte[] JWT_SECRET = "test-secret-must-be-at-least-32-bytes!".getBytes();
  private static final byte[] ALICE = "alice".getBytes();

  @Mock private Server server;
  @Mock private RecoveryChallenger recoveryChallenger;

  private RateLimiter recoveryRateLimiter;
  private JwtManager jwtManager;
  private HofmannOpaqueServerManager manager;

  @BeforeEach
  void setUp() {
    // Real token-bucket limiter at the production recovery config (capacity 6).
    recoveryRateLimiter = new InMemoryRateLimiter(
        new RateLimitConfigSupplier.DefaultRateLimitConfigSupplier().recoveryRateLimitConfig());
    jwtManager = new JwtManager(JWT_SECRET, "test-issuer", 3600, new InMemorySessionStore());
    manager = new HofmannOpaqueServerManager(
        server, new InMemoryCredentialStore(), jwtManager,
        k -> true, k -> true, // permissive auth + registration limiters
        new InMemoryPendingSessionStore(),
        recoveryChallenger, new InMemoryRecoveryTokenStore(), recoveryRateLimiter);
  }

  @AfterEach
  void tearDown() {
    manager.shutdown();
  }

  @Test
  void recoveryVerify_exhaustingBucket_throwsRateLimitExceeded() {
    // Each verification attempt draws one token; with verifyResponse=false every attempt that
    // clears the limiter fails authentication. The default capacity is 6, so the first six
    // attempts reach (and are rejected by) the challenger, and the seventh is throttled.
    when(recoveryChallenger.verifyResponse(any(), any())).thenReturn(false);
    RecoveryVerifyRequest req = new RecoveryVerifyRequest(ALICE, "000000");

    for (int i = 0; i < 6; i++) {
      final int attempt = i;
      assertThatThrownBy(() -> manager.recoveryVerify(req))
          .as("attempt %d should reach the challenger, not the rate limiter", attempt)
          .isInstanceOf(SecurityException.class)
          .isNotInstanceOf(RateLimitExceededException.class);
    }

    assertThatThrownBy(() -> manager.recoveryVerify(req))
        .as("seventh attempt must be throttled")
        .isInstanceOf(RateLimitExceededException.class);
  }

  @Test
  void recoveryVerify_bucketKeyedPerCredential_otherCredentialUnaffected() {
    // The throttle is keyed by credential identifier, so exhausting alice's bucket must not
    // throttle a different credential — and rejection depends only on the identifier, never on
    // whether the account exists, so it is not an enumeration oracle.
    when(recoveryChallenger.verifyResponse(any(), any())).thenReturn(false);
    RecoveryVerifyRequest aliceReq = new RecoveryVerifyRequest(ALICE, "000000");
    for (int i = 0; i < 6; i++) {
      assertThatThrownBy(() -> manager.recoveryVerify(aliceReq)).isInstanceOf(SecurityException.class);
    }
    assertThatThrownBy(() -> manager.recoveryVerify(aliceReq))
        .isInstanceOf(RateLimitExceededException.class);

    byte[] bob = "bob".getBytes();
    String bobB64 = Base64.getEncoder().encodeToString(bob);
    // Sanity: bob is a distinct rate-limiter key.
    org.assertj.core.api.Assertions.assertThat(bobB64)
        .isNotEqualTo(Base64.getEncoder().encodeToString(ALICE));
    assertThatThrownBy(() -> manager.recoveryVerify(new RecoveryVerifyRequest(bob, "000000")))
        .as("bob's bucket is independent of alice's")
        .isInstanceOf(SecurityException.class)
        .isNotInstanceOf(RateLimitExceededException.class);
  }
}
