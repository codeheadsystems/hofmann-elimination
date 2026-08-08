package com.codeheadsystems.hofmann.server.manager;

import static org.assertj.core.api.Assertions.assertThat;

import com.codeheadsystems.hofmann.model.opaque.RecoveryVerifyRequest;
import com.codeheadsystems.hofmann.server.ratelimit.RateLimitExceededException;
import com.codeheadsystems.hofmann.server.recovery.RecoveryChallenger;
import com.codeheadsystems.hofmann.server.store.InMemoryCredentialStore;
import com.codeheadsystems.hofmann.server.store.InMemoryPendingSessionStore;
import com.codeheadsystems.hofmann.server.store.InMemoryRecoveryTokenStore;
import com.codeheadsystems.hofmann.server.store.InMemorySessionStore;
import com.codeheadsystems.rfc.opaque.Server;
import com.codeheadsystems.rfc.opaque.config.OpaqueConfig;
import com.codeheadsystems.rfc.opaque.testfixtures.OpaqueTestConfigs;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * {@code recoveryVerify} holds a request thread for 250 ms to keep its response time constant, and
 * the per-origin limiter bounds that only per origin — so it composed linearly: a few hundred
 * sources, well under a single IPv6 /64, parked enough threads to exhaust a servlet pool and take
 * down the whole application rather than just recovery.
 *
 * <p>Concurrency inside the floor is capped, and requests beyond it are refused rather than
 * queued — queueing would consume the very resource being protected.
 */
class RecoveryVerifyConcurrencyTest {

  private static final byte[] ALICE = "alice@example.com".getBytes(StandardCharsets.UTF_8);

  private HofmannOpaqueServerManager manager;
  private AtomicInteger concurrent;
  private AtomicInteger peak;

  @BeforeEach
  void setUp() {
    concurrent = new AtomicInteger();
    peak = new AtomicInteger();
    OpaqueConfig config = OpaqueTestConfigs.forTesting();
    RecoveryChallenger slowChallenger = new RecoveryChallenger() {
      @Override public void sendChallenge(byte[] id) { }

      @Override public boolean verifyResponse(byte[] id, String response) {
        int now = concurrent.incrementAndGet();
        peak.accumulateAndGet(now, Math::max);
        try {
          Thread.sleep(120);
        } catch (InterruptedException e) {
          Thread.currentThread().interrupt();
        } finally {
          concurrent.decrementAndGet();
        }
        return false;
      }
    };
    manager = new HofmannOpaqueServerManager(
        Server.generate(config), new InMemoryCredentialStore(),
        new JwtManager("test-secret-must-be-at-least-32-bytes!".getBytes(StandardCharsets.UTF_8),
            "test-issuer", 3600, new InMemorySessionStore()),
        key -> true, key -> true, new InMemoryPendingSessionStore(),
        slowChallenger, new InMemoryRecoveryTokenStore(), key -> true);
  }

  @AfterEach
  void tearDown() {
    manager.shutdown();
  }

  private int verify() {
    try {
      manager.recoveryVerify(new RecoveryVerifyRequest(ALICE, "000000"));
      return 0;
    } catch (RateLimitExceededException e) {
      return 1;   // refused at the ceiling
    } catch (SecurityException e) {
      return 0;   // verification failed, which is the expected outcome here
    }
  }

  @Test
  void concurrencyInsideTheFloorIsCapped() throws Exception {
    int threads = 64;
    CountDownLatch start = new CountDownLatch(1);
    CountDownLatch done = new CountDownLatch(threads);
    AtomicInteger refused = new AtomicInteger();

    for (int i = 0; i < threads; i++) {
      new Thread(() -> {
        try {
          start.await();
          refused.addAndGet(verify());
        } catch (InterruptedException e) {
          Thread.currentThread().interrupt();
        } finally {
          done.countDown();
        }
      }).start();
    }
    start.countDown();
    assertThat(done.await(30, TimeUnit.SECONDS)).isTrue();

    assertThat(peak.get())
        .as("no more than the ceiling may be inside the floor at once; peak was %d", peak.get())
        .isLessThanOrEqualTo(16);
    assertThat(refused.get())
        .as("excess must be refused rather than queued, or the threads pile up anyway")
        .isGreaterThan(0);
  }

  /** A permit leaked on any failure path would wedge recovery permanently after enough calls. */
  @Test
  void permitsAreReleasedAfterFailedVerifications() {
    for (int i = 0; i < 40; i++) {
      verify();
    }
    assertThat(verify())
        .as("after many failed verifications a fresh call must still be admitted")
        .isZero();
  }
}
