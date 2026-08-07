package com.codeheadsystems.hofmann.server.manager;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.codeheadsystems.hofmann.model.opaque.RecoveryVerifyRequest;
import com.codeheadsystems.hofmann.server.ratelimit.RateLimitExceededException;
import com.codeheadsystems.hofmann.server.ratelimit.RateLimiter;
import com.codeheadsystems.hofmann.server.recovery.RecoveryChallenger;
import com.codeheadsystems.hofmann.server.store.InMemoryCredentialStore;
import com.codeheadsystems.hofmann.server.store.InMemoryPendingSessionStore;
import com.codeheadsystems.hofmann.server.store.InMemoryRecoveryTokenStore;
import com.codeheadsystems.hofmann.server.store.InMemorySessionStore;
import com.codeheadsystems.rfc.opaque.Server;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

/**
 * The targeted account-recovery lockout, and the challenge id that closes it.
 *
 * <p>{@code recoveryVerify} is unauthenticated and used to key its rate limiter on the credential
 * identifier — a value the caller supplies and an attacker knows. A handful of requests naming a
 * victim spent that victim's budget, so the victim could not complete a recovery they had
 * legitimately started, without ever having been involved in the attack.
 *
 * <p>The fix is not a different rate limit. Before a challenge exists there is nothing to key on
 * that an attacker cannot also supply. What breaks it is a value the server generates and delivers
 * out of band: the attacker cannot name it, so they spend their own budget instead.
 */
@ExtendWith(MockitoExtension.class)
class RecoveryLockoutTest {

  private static final byte[] VICTIM = "victim@example.com".getBytes(StandardCharsets.UTF_8);
  private static final byte[] JWT_SECRET =
      "test-secret-must-be-at-least-32-bytes!".getBytes(StandardCharsets.UTF_8);

  @Mock private Server server;

  private HofmannOpaqueServerManager manager;
  private InMemorySessionStore sessionStore;

  /** A limiter with a small per-key budget, so exhaustion is easy to observe. */
  private static final class CountingLimiter implements RateLimiter {
    private final int budget;
    private final ConcurrentHashMap<String, AtomicInteger> spent = new ConcurrentHashMap<>();
    private final List<String> keys = new ArrayList<>();

    CountingLimiter(int budget) {
      this.budget = budget;
    }

    @Override
    public synchronized boolean tryConsume(String key) {
      keys.add(key);
      return spent.computeIfAbsent(key, k -> new AtomicInteger()).incrementAndGet() <= budget;
    }
  }

  /**
   * A challenger that delivers and binds the challenge id.
   *
   * <p>Remembers every id it issued rather than only the newest. A real challenger with several
   * outstanding challenges for one account behaves this way, and keeping only the last one would
   * make an earlier still-valid challenge fail for a reason that has nothing to do with the
   * property under test.
   */
  private static final class BindingChallenger implements RecoveryChallenger {
    private volatile String lastChallengeId;
    private final java.util.Set<String> issued = ConcurrentHashMap.newKeySet();

    @Override
    public void sendChallenge(byte[] credentialIdentifier) {
      throw new AssertionError("the manager must call the challenge-id overload");
    }

    @Override
    public void sendChallenge(byte[] credentialIdentifier, String challengeId) {
      this.lastChallengeId = challengeId;
      this.issued.add(challengeId);
    }

    @Override
    public boolean verifyResponse(byte[] credentialIdentifier, String challengeResponse) {
      throw new AssertionError("the manager must call the challenge-id overload");
    }

    @Override
    public boolean verifyResponse(byte[] credentialIdentifier, String challengeId,
                                  String challengeResponse) {
      return "correct".equals(challengeResponse) && challengeId != null
          && issued.contains(challengeId);
    }

  }

  private HofmannOpaqueServerManager build(RecoveryChallenger challenger, RateLimiter limiter) {
    sessionStore = new InMemorySessionStore();
    return new HofmannOpaqueServerManager(
        server, new InMemoryCredentialStore(),
        new JwtManager(JWT_SECRET, "test-issuer", 3600, sessionStore),
        key -> true, key -> true, new InMemoryPendingSessionStore(),
        challenger, new InMemoryRecoveryTokenStore(), limiter);
  }

  @AfterEach
  void tearDown() {
    if (manager != null) {
      manager.shutdown();
    }
  }

  @Test
  void withAChallengeId_anAttackerFloodingTheVictimsIdentifierCannotLockThemOut() {
    BindingChallenger challenger = new BindingChallenger();
    CountingLimiter limiter = new CountingLimiter(3);
    manager = build(challenger, limiter);

    // The victim starts recovery and receives a challenge id out of band.
    manager.recoveryStart(new com.codeheadsystems.hofmann.model.opaque.RecoveryStartRequest(VICTIM));
    String victimChallengeId = challenger.lastChallengeId;
    assertThat(victimChallengeId).isNotBlank();

    // An attacker hammers recoveryVerify naming the victim, with ids they made up.
    for (int i = 0; i < 20; i++) {
      String attackerId = "attacker-guess-" + i;
      try {
        manager.recoveryVerify(new RecoveryVerifyRequest(VICTIM, "wrong", attackerId));
      } catch (RateLimitExceededException | SecurityException expected) {
        // Either outcome is fine; what matters is whose budget it drew from.
      }
    }

    // The victim completes their recovery. Under identifier keying this threw
    // RateLimitExceededException; the attacker never touched the victim's challenge bucket.
    assertThatCode(() -> manager.recoveryVerify(
        new RecoveryVerifyRequest(VICTIM, "correct", victimChallengeId)))
        .doesNotThrowAnyException();
  }

  @Test
  void withAChallengeId_theLimiterKeysOnItRatherThanTheIdentifier() {
    BindingChallenger challenger = new BindingChallenger();
    CountingLimiter limiter = new CountingLimiter(3);
    manager = build(challenger, limiter);
    manager.recoveryStart(new com.codeheadsystems.hofmann.model.opaque.RecoveryStartRequest(VICTIM));
    String issuedId = challenger.lastChallengeId;

    try {
      manager.recoveryVerify(new RecoveryVerifyRequest(VICTIM, "wrong", issuedId));
    } catch (SecurityException expected) {
      // verification fails; the key is what is under test
    }

    assertThat(limiter.keys).contains("challenge:" + issuedId);
    assertThat(limiter.keys.stream().filter(k -> k.startsWith("verify:")).toList()).isEmpty();
  }

  @Test
  void guessingTheVictimsChallengeIdDoesSpendTheirBudget_whichIsThePointOfItBeingUnguessable() {
    BindingChallenger challenger = new BindingChallenger();
    CountingLimiter limiter = new CountingLimiter(2);
    manager = build(challenger, limiter);
    manager.recoveryStart(new com.codeheadsystems.hofmann.model.opaque.RecoveryStartRequest(VICTIM));
    String victimChallengeId = challenger.lastChallengeId;

    // An attacker who somehow knows the id can still spend that budget — the defence is that the
    // id is a 122-bit value delivered only to the account owner, not that the bucket is immune.
    for (int i = 0; i < 3; i++) {
      try {
        manager.recoveryVerify(new RecoveryVerifyRequest(VICTIM, "wrong", victimChallengeId));
      } catch (RateLimitExceededException | SecurityException expected) {
        // expected
      }
    }

    assertThatThrownBy(() -> manager.recoveryVerify(
        new RecoveryVerifyRequest(VICTIM, "correct", victimChallengeId)))
        .isInstanceOf(RateLimitExceededException.class);
  }

  @Test
  void withoutAChallengeId_theOldIdentifierKeyingApplies() {
    // A challenger that never delivers the id keeps the previous behaviour, residual included:
    // the client cannot present an id, so verification keys on the identifier. Asserted rather
    // than assumed so the fallback cannot silently become something else.
    RecoveryChallenger legacy = new RecoveryChallenger() {
      @Override
      public void sendChallenge(byte[] credentialIdentifier) {
      }

      @Override
      public boolean verifyResponse(byte[] credentialIdentifier, String challengeResponse) {
        return "correct".equals(challengeResponse);
      }
    };
    CountingLimiter limiter = new CountingLimiter(3);
    manager = build(legacy, limiter);

    for (int i = 0; i < 3; i++) {
      try {
        manager.recoveryVerify(new RecoveryVerifyRequest(VICTIM, "wrong"));
      } catch (RateLimitExceededException | SecurityException expected) {
        // expected
      }
    }

    assertThat(limiter.keys).anyMatch(k -> k.startsWith("verify:"));
    assertThatThrownBy(() -> manager.recoveryVerify(new RecoveryVerifyRequest(VICTIM, "correct")))
        .isInstanceOf(RateLimitExceededException.class);
  }

  @Test
  void anUnissuedChallengeId_isRefusedAsALimiterKey() {
    // The whole point of recording issued ids. A fabricated id must not become its own bucket:
    // if it did, an attacker could vary it per request and get an unlimited guessing budget —
    // worse than the lockout being fixed. Unknown ids fall back to identifier keying, which costs
    // a legitimate user nothing because they always present an id the server issued.
    BindingChallenger challenger = new BindingChallenger();
    CountingLimiter limiter = new CountingLimiter(2);
    manager = build(challenger, limiter);

    for (int i = 0; i < 3; i++) {
      try {
        manager.recoveryVerify(new RecoveryVerifyRequest(VICTIM, "wrong", "fabricated-" + i));
      } catch (RateLimitExceededException | SecurityException expected) {
        // expected
      }
    }

    // Every fabricated id landed on the identifier bucket, not one bucket each.
    assertThat(limiter.keys).noneMatch(k -> k.startsWith("challenge:fabricated"));
    assertThatThrownBy(() -> manager.recoveryVerify(
        new RecoveryVerifyRequest(VICTIM, "wrong", "fabricated-99")))
        .isInstanceOf(RateLimitExceededException.class);
  }

  @Test
  void recoveryStartAndRecoveryVerifyDrawFromSeparateBuckets() {
    // Otherwise a flood of starts would still exhaust the budget that verification needs, and the
    // challenge id would have bought nothing.
    BindingChallenger challenger = new BindingChallenger();
    CountingLimiter limiter = new CountingLimiter(2);
    manager = build(challenger, limiter);

    manager.recoveryStart(new com.codeheadsystems.hofmann.model.opaque.RecoveryStartRequest(VICTIM));
    String id = challenger.lastChallengeId;
    for (int i = 0; i < 5; i++) {
      try {
        manager.recoveryStart(
            new com.codeheadsystems.hofmann.model.opaque.RecoveryStartRequest(VICTIM));
      } catch (RateLimitExceededException expected) {
        // start is exhausted, which is the inherent part
      }
    }

    assertThatCode(() -> manager.recoveryVerify(new RecoveryVerifyRequest(VICTIM, "correct", id)))
        .doesNotThrowAnyException();
  }
}
