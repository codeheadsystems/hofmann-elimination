package com.codeheadsystems.hofmann.client.config;

import com.codeheadsystems.hofmann.model.opaque.OpaqueClientConfigResponse;
import com.codeheadsystems.rfc.opaque.config.OpaqueCipherSuite;
import com.codeheadsystems.rfc.opaque.config.OpaqueConfig;
import com.codeheadsystems.rfc.common.RandomProvider;
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
 * For production use {@link #withArgon2id(String, byte[], int, int, int)} which matches the
 * server's default Argon2id KSF.
 *
 * @param opaqueConfig the opaque library config holding cipher suite, KSF, and context
 */
public record OpaqueClientConfig(OpaqueConfig opaqueConfig) {

  /**
   * Creates a production config with Argon2id KSF and the given cipher suite.
   * The cipher suite name, context, and Argon2id parameters must exactly match the server's.
   * Accepted suite names: {@code "P256_SHA256"} (default), {@code "P384_SHA384"},
   * {@code "P521_SHA512"}.
   *
   * @param cipherSuiteName   the cipher suite name
   * @param context           the context
   * @param argon2MemoryKib   the argon 2 memory kib
   * @param argon2Iterations  the argon 2 iterations
   * @param argon2Parallelism the argon 2 parallelism
   * @return the opaque client config
   */
  public static OpaqueClientConfig withArgon2id(String cipherSuiteName, byte[] context,
                                                int argon2MemoryKib, int argon2Iterations, int argon2Parallelism) {
    OpaqueCipherSuite suite = OpaqueCipherSuite.fromName(cipherSuiteName);
    return new OpaqueClientConfig(
        OpaqueConfig.withArgon2id(suite, context, argon2MemoryKib, argon2Iterations, argon2Parallelism));
  }

  /**
   * Convenience overload accepting a context string in UTF-8.
   *
   * @param cipherSuiteName   the cipher suite name
   * @param context           the context
   * @param argon2MemoryKib   the argon 2 memory kib
   * @param argon2Iterations  the argon 2 iterations
   * @param argon2Parallelism the argon 2 parallelism
   * @return the opaque client config
   */
  public static OpaqueClientConfig withArgon2id(String cipherSuiteName, String context,
                                                int argon2MemoryKib, int argon2Iterations, int argon2Parallelism) {
    return withArgon2id(cipherSuiteName, context.getBytes(StandardCharsets.UTF_8),
        argon2MemoryKib, argon2Iterations, argon2Parallelism);
  }

  /**
   * Creates a test-only config with identity KSF (no Argon2), P-256/SHA-256 cipher suite,
   * and the supplied context bytes.  Do not use in production.
   *
   * @param context the context
   * @return the opaque client config
   */
  public static OpaqueClientConfig forTesting(byte[] context) {
    return new OpaqueClientConfig(
        new OpaqueConfig(OpaqueCipherSuite.P256_SHA256, 0, 0, 0, context,
            new OpaqueConfig.IdentityKsf(), new RandomProvider()));
  }

  /**
   * Convenience overload accepting a context string in UTF-8.
   *
   * @param context the context
   * @return the opaque client config
   */
  public static OpaqueClientConfig forTesting(String context) {
    return forTesting(context.getBytes(StandardCharsets.UTF_8));
  }

  /**
   * Creates an {@link OpaqueClientConfig} from a server-supplied config response.
   * <p>
   * When {@code argon2MemoryKib == 0} the server is using the identity KSF (test/dev only),
   * so {@link #forTesting(String)} is used.  Otherwise {@link #withArgon2id} is used with
   * the exact parameters returned by the server.
   *
   * @param cfg the server config response from GET /opaque/config
   * @return the opaque client config
   */
  public static OpaqueClientConfig fromServerConfig(OpaqueClientConfigResponse cfg) {
    if (cfg.argon2MemoryKib() == 0) {
      return forTesting(cfg.context());
    }
    return withArgon2id(cfg.cipherSuite(), cfg.context(),
        cfg.argon2MemoryKib(), cfg.argon2Iterations(), cfg.argon2Parallelism());
  }
}
