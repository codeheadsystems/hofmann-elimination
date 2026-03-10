package com.codeheadsystems.hofmann.integration;

import com.codeheadsystems.hofmann.server.recovery.RecoveryChallenger;
import java.security.MessageDigest;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Provides a test-only {@link RecoveryChallenger} bean for integration tests.
 * Always uses "123456" as the challenge code. The presence of this bean triggers
 * {@code HofmannAutoConfiguration} to create the recovery token store and rate limiter,
 * enabling the {@code /opaque/recovery/*} endpoints.
 */
@Configuration
public class TestRecoveryChallengerConfig {

  private static final String FIXED_CODE = "123456";

  @Bean
  public RecoveryChallenger recoveryChallenger() {
    return new TestRecoveryChallenger();
  }

  static class TestRecoveryChallenger implements RecoveryChallenger {

    private final Map<String, String> pendingChallenges = new ConcurrentHashMap<>();

    @Override
    public void sendChallenge(byte[] credentialIdentifier) {
      pendingChallenges.put(new String(credentialIdentifier), FIXED_CODE);
    }

    @Override
    public boolean verifyResponse(byte[] credentialIdentifier, String challengeResponse) {
      String stored = pendingChallenges.remove(new String(credentialIdentifier));
      if (stored == null) {
        return false;
      }
      return MessageDigest.isEqual(stored.getBytes(), challengeResponse.getBytes());
    }
  }
}
