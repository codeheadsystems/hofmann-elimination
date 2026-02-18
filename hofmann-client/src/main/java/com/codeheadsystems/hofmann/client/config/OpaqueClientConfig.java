package com.codeheadsystems.hofmann.client.config;

import com.codeheadsystems.opaque.config.OpaqueConfig;
import com.codeheadsystems.opaque.config.OpaqueCipherSuite;
import java.nio.charset.StandardCharsets;

/**
 * Client-side configuration for the OPAQUE protocol.
 * <p>
 * Wraps the cryptographic {@link OpaqueConfig} from the opaque library.  The context string and
 * KSF parameters must exactly match the server's configuration, or every authentication attempt
 * will fail (the MAC transcript includes the context, and the KSF determines how the password
 * is stretched before blinding).
 * <p>
 * For testing use {@link #forTesting(byte[])} which sets up a P-256/identity-KSF config.
 *
 * @param opaqueConfig the opaque library config holding cipher suite, KSF, and context
 */
public record OpaqueClientConfig(OpaqueConfig opaqueConfig) {

  /**
   * Creates a test-only config with identity KSF (no Argon2), P-256/SHA-256 cipher suite,
   * and the supplied context bytes.  Do not use in production.
   */
  public static OpaqueClientConfig forTesting(byte[] context) {
    return new OpaqueClientConfig(
        new OpaqueConfig(OpaqueCipherSuite.P256_SHA256, 0, 0, 0, context,
            new OpaqueConfig.IdentityKsf()));
  }

  /**
   * Convenience overload accepting a context string in UTF-8.
   */
  public static OpaqueClientConfig forTesting(String context) {
    return forTesting(context.getBytes(StandardCharsets.UTF_8));
  }
}
