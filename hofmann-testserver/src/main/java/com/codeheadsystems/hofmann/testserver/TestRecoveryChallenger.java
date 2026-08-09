package com.codeheadsystems.hofmann.testserver;

import com.codeheadsystems.hofmann.server.recovery.RecoveryChallenger;
import java.security.MessageDigest;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Test-only {@link RecoveryChallenger} that always uses "123456" as the challenge code.
 * <p>
 * This implementation is for local development and integration testing only. It logs
 * the credential identifier on each challenge send and uses constant-time comparison
 * for verification.
 * <p>
 * The fixed code "123456" allows automated tests (including TypeScript integration tests)
 * to exercise the full recovery flow without needing a real email/SMS service.
 */
public class TestRecoveryChallenger implements RecoveryChallenger {

  /**
   * Creates a challenger that issues the fixed code to every request.
   */
  public TestRecoveryChallenger() {
  }

  private static final Logger log = LoggerFactory.getLogger(TestRecoveryChallenger.class);
  private static final String FIXED_CODE = "123456";

  private final Map<String, String> pendingChallenges = new ConcurrentHashMap<>();

  @Override
  public void sendChallenge(byte[] credentialIdentifier) {
    String key = new String(credentialIdentifier);
    pendingChallenges.put(key, FIXED_CODE);
    log.info("Recovery challenge sent for '{}' — code is always '{}'", key, FIXED_CODE);
  }

  @Override
  public boolean verifyResponse(byte[] credentialIdentifier, String challengeResponse) {
    String key = new String(credentialIdentifier);
    String stored = pendingChallenges.remove(key);
    if (stored == null) {
      log.debug("No pending challenge for '{}'", key);
      return false;
    }
    boolean match = MessageDigest.isEqual(
        stored.getBytes(), challengeResponse.getBytes());
    log.info("Recovery verify for '{}': {}", key, match ? "SUCCESS" : "FAILED");
    return match;
  }
}
