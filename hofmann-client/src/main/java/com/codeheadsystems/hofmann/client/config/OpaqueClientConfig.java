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
   * Creates a test-only config with identity KSF, the specified cipher suite, and the
   * supplied context string.  Do not use in production.
   *
   * @param cipherSuiteName the cipher suite name (e.g. "P384_SHA384")
   * @param context         the context string
   * @return the opaque client config
   */
  public static OpaqueClientConfig forTesting(String cipherSuiteName, String context) {
    OpaqueCipherSuite suite = OpaqueCipherSuite.fromName(cipherSuiteName);
    return new OpaqueClientConfig(
        new OpaqueConfig(suite, 0, 0, 0, context.getBytes(StandardCharsets.UTF_8),
            new OpaqueConfig.IdentityKsf(), new RandomProvider()));
  }

  /**
   * Minimum Argon2id memory cost, in KiB, accepted from a server-supplied config.
   * <p>
   * 19456 KiB (19 MiB) is the OWASP Password Storage Cheat Sheet minimum for Argon2id at
   * {@code t=2, p=1}. The server's own default is 65536 KiB, so this floor leaves room for a
   * deployment that has deliberately tuned downwards while still refusing parameters weak
   * enough to make an offline dictionary attack cheap.
   */
  public static final int MIN_ARGON2_MEMORY_KIB = 19456;

  /** Minimum Argon2id iteration count accepted from a server-supplied config. */
  public static final int MIN_ARGON2_ITERATIONS = 2;

  /**
   * Upper bound on server-requested Argon2id memory, 4 GiB. Not a security floor — it stops a
   * server from inducing a client-side denial of service through an absurd allocation.
   */
  public static final int MAX_ARGON2_MEMORY_KIB = 4194304;

  /**
   * Upper bound on server-requested Argon2id iterations. Argon2id cost is linear in iterations
   * and unbounded, so an absurd value hangs the client on its first registration just as surely
   * as an absurd memory request. OWASP's published parameter sets top out at 4; 10 is generous.
   * Like {@link #MAX_ARGON2_MEMORY_KIB} this is DoS hardening, not a security floor.
   */
  public static final int MAX_ARGON2_ITERATIONS = 10;

  /** Upper bound on server-requested Argon2id parallelism. DoS hardening, not a security floor. */
  public static final int MAX_ARGON2_PARALLELISM = 16;

  /**
   * Creates an {@link OpaqueClientConfig} from a server-supplied config response, refusing
   * key-stretching parameters weaker than {@link #MIN_ARGON2_MEMORY_KIB} /
   * {@link #MIN_ARGON2_ITERATIONS}.
   * <p>
   * In OPAQUE the key-stretching function runs entirely on the client, so these parameters
   * decide how expensive an offline dictionary attack is against the record the server stores.
   * Taking them from the server unchecked lets a malicious, breached, or MITM'd server turn its
   * own users' password hashing off: answering {@code GET /opaque/config} with
   * {@code argon2MemoryKib = 0} selects the identity KSF, which returns the OPRF output
   * unchanged. Registration then stores a record derived from an unstretched password, and
   * because the server keeps serving the same config afterwards, authentication continues to
   * work and nothing looks wrong from either side. The quieter variant — 8 KiB, one iteration —
   * is the same attack with a smaller footprint.
   * <p>
   * The server has an {@code allowIdentityKsf} flag and refuses to start without it; this is
   * the client-side counterpart. To pin configuration locally instead of negotiating it, supply
   * an {@link OpaqueClientConfig} through the overrides map of
   * {@code HofmannOpaqueClientManager} — that path does not consult the server at all.
   *
   * @param cfg the server config response from GET /opaque/config
   * @return the opaque client config
   * @throws IllegalStateException if the server offers the identity KSF or parameters below the
   *                               floor
   */
  public static OpaqueClientConfig fromServerConfig(OpaqueClientConfigResponse cfg) {
    return fromServerConfig(cfg, false);
  }

  /**
   * Variant of {@link #fromServerConfig(OpaqueClientConfigResponse)} that allows the caller to
   * accept weak or absent key stretching.
   * <p>
   * Pass {@code true} only for tests and local development against a server deliberately
   * configured with {@code allowIdentityKsf}. It disables the client's only defence against a
   * server that lowers its users' password-hashing cost, so it must be an explicit local
   * decision — never something a remote host can talk the client into.
   *
   * @param cfg          the server config response from GET /opaque/config
   * @param allowWeakKsf true to accept the identity KSF and below-floor parameters
   * @return the opaque client config
   * @throws IllegalStateException if {@code allowWeakKsf} is false and the parameters are weak
   */
  public static OpaqueClientConfig fromServerConfig(OpaqueClientConfigResponse cfg,
                                                    boolean allowWeakKsf) {
    return fromServerConfig(cfg, allowWeakKsf, null);
  }

  /**
   * Variant that additionally verifies the server's {@code context} against a locally configured
   * value rather than adopting whatever the server sends.
   * <p>
   * USAGE.md specifies that {@code context} is shared out-of-band and must be unique per
   * deployment: it is the binding that stops a transcript from one deployment being replayed
   * against another. Both clients nonetheless read it from {@code GET /opaque/config} — the same
   * channel an attacker in the middle controls — so the anti-replay binding was being negotiated
   * with the party it exists to bind. That matters more than it looks: the client manager passes
   * null for both identities, so {@code context} is the only deployment-distinguishing value in
   * the preamble.
   * <p>
   * Pass the expected context to pin it. A mismatch fails loudly instead of silently producing a
   * transcript bound to someone else's deployment. Pass null to keep the previous behaviour.
   *
   * @param cfg             the server config response
   * @param allowWeakKsf    true to accept the identity KSF and below-floor parameters
   * @param expectedContext the locally configured context, or null to accept the server's
   * @return the opaque client config
   * @throws IllegalStateException if the server's context does not match the expected value
   */
  public static OpaqueClientConfig fromServerConfig(OpaqueClientConfigResponse cfg,
                                                    boolean allowWeakKsf,
                                                    String expectedContext) {
    if (expectedContext != null && !expectedContext.equals(cfg.context())) {
      throw new IllegalStateException(String.format(
          "Server context \"%s\" does not match the expected \"%s\". The context is the binding "
              + "that prevents a transcript from one deployment being replayed against another, "
              + "so it must be shared out-of-band rather than taken from the server.",
          cfg.context(), expectedContext));
    }
    if (!allowWeakKsf) {
      if (cfg.argon2MemoryKib() == 0) {
        throw new IllegalStateException(
            "Server offers the identity KSF (argon2MemoryKib=0), which performs no password "
                + "stretching and leaves the stored record open to an offline dictionary "
                + "attack. Refusing. Use fromServerConfig(cfg, true) to opt in locally, or "
                + "pin an OpaqueClientConfig through the client manager's overrides map.");
      }
      if (cfg.argon2MemoryKib() < MIN_ARGON2_MEMORY_KIB
          || cfg.argon2Iterations() < MIN_ARGON2_ITERATIONS) {
        throw new IllegalStateException(String.format(
            "Server offers Argon2id parameters below the client's minimum: memory=%d KiB "
                + "(minimum %d), iterations=%d (minimum %d). Refusing, because these are the "
                + "parameters that determine offline attack cost against the stored record. "
                + "Use fromServerConfig(cfg, true) to opt in locally.",
            cfg.argon2MemoryKib(), MIN_ARGON2_MEMORY_KIB,
            cfg.argon2Iterations(), MIN_ARGON2_ITERATIONS));
      }
      if (cfg.argon2MemoryKib() > MAX_ARGON2_MEMORY_KIB) {
        throw new IllegalStateException(String.format(
            "Server asks for %d KiB of Argon2id memory, above the client's ceiling of %d KiB. "
                + "Refusing, to avoid a server-induced client DoS.",
            cfg.argon2MemoryKib(), MAX_ARGON2_MEMORY_KIB));
      }
      if (cfg.argon2Iterations() > MAX_ARGON2_ITERATIONS) {
        throw new IllegalStateException(String.format(
            "Server asks for %d Argon2id iterations, above the client's ceiling of %d. Refusing, "
                + "to avoid a server-induced client DoS — Argon2id cost is linear in iterations "
                + "and otherwise unbounded.",
            cfg.argon2Iterations(), MAX_ARGON2_ITERATIONS));
      }
      if (cfg.argon2Parallelism() < 1 || cfg.argon2Parallelism() > MAX_ARGON2_PARALLELISM) {
        throw new IllegalStateException(String.format(
            "Server offers argon2Parallelism=%d; must be between 1 and %d.",
            cfg.argon2Parallelism(), MAX_ARGON2_PARALLELISM));
      }
    }
    if (cfg.argon2MemoryKib() == 0) {
      return forTesting(cfg.cipherSuite(), cfg.context());
    }
    return withArgon2id(cfg.cipherSuite(), cfg.context(),
        cfg.argon2MemoryKib(), cfg.argon2Iterations(), cfg.argon2Parallelism());
  }
}
