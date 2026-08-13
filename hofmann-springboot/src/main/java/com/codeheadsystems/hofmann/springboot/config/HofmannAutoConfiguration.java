package com.codeheadsystems.hofmann.springboot.config;

import com.codeheadsystems.hofmann.model.opaque.OpaqueClientConfigResponse;
import com.codeheadsystems.hofmann.model.oprf.OprfClientConfigResponse;
import com.codeheadsystems.hofmann.server.manager.HofmannOpaqueServerManager;
import com.codeheadsystems.hofmann.server.manager.JwtKeyDetail;
import com.codeheadsystems.hofmann.server.manager.JwtManager;
import com.codeheadsystems.hofmann.server.manager.OpaqueServerKeyDetail;
import com.codeheadsystems.hofmann.server.ratelimit.FixedCapacityRateLimiter;
import com.codeheadsystems.hofmann.server.ratelimit.InMemoryRateLimiter;
import com.codeheadsystems.hofmann.server.ratelimit.RateLimitConfig;
import com.codeheadsystems.hofmann.server.ratelimit.RateLimitConfigSupplier;
import com.codeheadsystems.hofmann.server.ratelimit.RateLimiter;
import com.codeheadsystems.hofmann.server.oprf.VerifiableKeyConfig;
import com.codeheadsystems.hofmann.server.recovery.RecoveryChallenger;
import com.codeheadsystems.hofmann.server.store.CredentialStore;
import com.codeheadsystems.hofmann.server.store.InMemoryCredentialStore;
import com.codeheadsystems.hofmann.server.store.InMemoryPendingSessionStore;
import com.codeheadsystems.hofmann.server.store.InMemoryRecoveryTokenStore;
import com.codeheadsystems.hofmann.server.store.InMemorySessionStore;
import com.codeheadsystems.hofmann.server.store.PendingSessionStore;
import com.codeheadsystems.hofmann.server.store.RecoveryTokenStore;
import com.codeheadsystems.hofmann.server.store.SessionStore;
import com.codeheadsystems.rfc.common.RandomProvider;
import com.codeheadsystems.rfc.opaque.Server;
import com.codeheadsystems.rfc.opaque.config.OpaqueCipherSuite;
import com.codeheadsystems.rfc.opaque.config.OpaqueConfig;
import com.codeheadsystems.hofmann.model.oprf.VerifiableOprfLimits;
import com.codeheadsystems.rfc.oprf.manager.OprfServerManager;
import com.codeheadsystems.rfc.oprf.manager.PoprfServerManager;
import com.codeheadsystems.rfc.oprf.manager.VoprfServerManager;
import com.codeheadsystems.rfc.oprf.model.ServerProcessorDetail;
import com.codeheadsystems.rfc.oprf.model.VerifiableProcessorDetail;
import com.codeheadsystems.rfc.oprf.rfc9497.OprfCipherSuite;
import com.codeheadsystems.rfc.oprf.rfc9497.OprfMode;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Map;
import java.util.HexFormat;
import java.util.function.Supplier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnExpression;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import com.codeheadsystems.hofmann.springboot.controller.OpaqueController;
import com.codeheadsystems.hofmann.springboot.controller.OprfController;
import com.codeheadsystems.hofmann.springboot.health.OpaqueServerHealthIndicator;
import org.springframework.context.annotation.Import;
import org.springframework.context.annotation.Bean;

/**
 * The type Hofmann auto configuration.
 */
@AutoConfiguration
@EnableConfigurationProperties(HofmannProperties.class)
@Import({
    OpaqueController.class,
    OprfController.class,
    OpaqueServerHealthIndicator.class,
    RequestBodyTooLargeAdvice.class,
})
public class HofmannAutoConfiguration {

  private static final Logger log = LoggerFactory.getLogger(HofmannAutoConfiguration.class);

  /**
   * Creates the auto-configuration. Instantiated by Spring Boot; applications do not
   * construct it directly, and override individual {@code @Bean} methods by defining their own
   * bean of the same type or name.
   */
  public HofmannAutoConfiguration() {
  }

  /**
   * Default {@link SecureRandom} instance.  Override this bean to supply a custom implementation
   * (e.g. an HSM-backed or seeded provider for testing):
   * <pre>{@code
   *   @Bean
   *   public SecureRandom secureRandom() {
   *     return SecureRandom.getInstance("NativePRNG");
   *   }
   * }***</pre>
   *
   * @return the secure random
   */
  @Bean
  @ConditionalOnMissingBean
  public SecureRandom secureRandom() {
    return new SecureRandom();
  }

  /**
   * Credential store credential store.
   *
   * @return the credential store
   */
  @Bean
  @ConditionalOnMissingBean
  public CredentialStore credentialStore() {
    log.warn("Using in-memory credential store. All data will be lost on restart. Do not use in production.");
    return new InMemoryCredentialStore();
  }

  /**
   * Session store session store.
   *
   * @return the session store
   */
  @Bean
  @ConditionalOnMissingBean
  public SessionStore sessionStore() {
    log.warn("Using in-memory session store. All data will be lost on restart. Do not use in production.");
    return new InMemorySessionStore();
  }

  /**
   * Opaque config opaque config.
   *
   * @param props        the props
   * @param secureRandom the secure random
   * @return the opaque config
   */
  @Bean
  @ConditionalOnMissingBean
  public OpaqueConfig opaqueConfig(HofmannProperties props, SecureRandom secureRandom) {
    OprfCipherSuite oprfSuite = OprfCipherSuite.builder().withSuite(props.getOpaqueCipherSuite())
        .withRandom(secureRandom).build();
    OpaqueCipherSuite suite = new OpaqueCipherSuite(oprfSuite);
    byte[] context = props.getContext().getBytes(StandardCharsets.UTF_8);
    if (props.getArgon2MemoryKib() == 0) {
      if (!props.isAllowIdentityKsf()) {
        throw new IllegalStateException(
            "Argon2 is disabled (argon2-memory-kib=0) but allow-identity-ksf is false. "
                + "Set hofmann.allow-identity-ksf=true to explicitly allow the identity KSF "
                + "(no key stretching). Do not use identity KSF in production.");
      }
      log.warn("Argon2 disabled — using identity KSF. Do not use in production.");
      return new OpaqueConfig(suite, 0, 0, 0, context, new OpaqueConfig.IdentityKsf(), new RandomProvider(secureRandom));
    }
    // withRandomConfig is not decoration. OpaqueConfig.withArgon2id builds its own
    // `new RandomProvider()` internally, so without this the deployment's SecureRandom reached the
    // identity-KSF branch above and was silently dropped on this one — the production branch. An
    // operator wiring an HSM-backed source got it for OPRF scalars and blinds, and the platform
    // default for every OPAQUE masking nonce, server AKE key seed, server nonce, envelope nonce
    // and client nonce. No symptom; exactly inverted from the intent.
    return OpaqueConfig.withArgon2id(
        suite,
        context,
        props.getArgon2MemoryKib(),
        props.getArgon2Iterations(),
        props.getArgon2Parallelism())
        .withRandomConfig(new RandomProvider(secureRandom));
  }

  /**
   * Server server.
   *
   * @param props        the props
   * @param opaqueConfig the opaque config
   * @return the server
   */
  @Bean
  @ConditionalOnMissingBean
  public Server server(HofmannProperties props, OpaqueConfig opaqueConfig) {
    String keySeedHex = props.getServerKeySeedHex();
    String oprfSeedHex = props.getOprfSeedHex();

    boolean hasKeySeed = keySeedHex != null && !keySeedHex.isEmpty();
    boolean hasOprfSeed = oprfSeedHex != null && !oprfSeedHex.isEmpty();

    if (!hasKeySeed && !hasOprfSeed) {
      requireEphemeralKeysAllowed(props, "server-key-seed-hex and oprf-seed-hex",
          "credentials registered against one node cannot authenticate against another, and a "
              + "restart invalidates every registration");
      log.warn("No server key seed or OPRF seed configured — generating ephemeral ones because "
          + "allow-ephemeral-keys is set. All registrations will be invalidated on restart. "
          + "Do not use in production.");
      return Server.generate(opaqueConfig);
    }

    if (!hasKeySeed || !hasOprfSeed) {
      throw new IllegalStateException(
          "Both serverKeySeedHex and oprfSeedHex must be configured together "
              + "(or both omitted for dev mode).");
    }

    return buildServer(keySeedHex, oprfSeedHex, opaqueConfig);
  }

  /**
   * Default {@link OpaqueServerKeyDetail} supplier that reads the current and optional
   * previous server keys from configuration.
   * <p>
   * Override this bean to implement dynamic key rotation (e.g. from a secrets manager):
   * <pre>{@code
   *   @Bean
   *   public Supplier<OpaqueServerKeyDetail> opaqueServerKeyDetailSupplier() {
   *     return () -> keyRotationService.currentOpaqueKeyDetail();
   *   }
   * }***</pre>
   *
   * @param props        the props
   * @param server       the current server
   * @param opaqueConfig the opaque config
   * @return the supplier
   */
  @Bean
  @ConditionalOnMissingBean
  public Supplier<OpaqueServerKeyDetail> opaqueServerKeyDetailSupplier(HofmannProperties props,
                                                                       Server server,
                                                                       OpaqueConfig opaqueConfig) {
    String prevKeySeedHex = props.getPreviousServerKeySeedHex();
    String prevOprfSeedHex = props.getPreviousOprfSeedHex();

    boolean hasPrevKeySeed = prevKeySeedHex != null && !prevKeySeedHex.isEmpty();
    boolean hasPrevOprfSeed = prevOprfSeedHex != null && !prevOprfSeedHex.isEmpty();

    if (hasPrevKeySeed != hasPrevOprfSeed) {
      throw new IllegalStateException(
          "Both previousServerKeySeedHex and previousOprfSeedHex must be configured together "
              + "(or both omitted when no key rotation is in progress).");
    }

    if (!hasPrevKeySeed) {
      OpaqueServerKeyDetail detail = new OpaqueServerKeyDetail(server);
      return () -> detail;
    }

    Server previousServer = buildServer(prevKeySeedHex, prevOprfSeedHex, opaqueConfig);
    OpaqueServerKeyDetail detail = new OpaqueServerKeyDetail(
        1, server, java.util.Map.of(0, previousServer));
    return () -> detail;
  }

  private Server buildServer(String keySeedHex, String oprfSeedHex, OpaqueConfig opaqueConfig) {
    HexFormat hex = HexFormat.of();
    OpaqueCipherSuite suite = opaqueConfig.cipherSuite();
    byte[] keySeed = hex.parseHex(keySeedHex);
    byte[] oprfSeed = hex.parseHex(oprfSeedHex);

    OpaqueCipherSuite.AkeKeyPair keyPair = suite.deriveAkeKeyPair(keySeed);
    BigInteger sk = keyPair.privateKey();
    byte[] pk = keyPair.publicKeyBytes();

    // Canonical per-suite scalar encoding, matching what Server's constructor decodes:
    // big-endian on the NIST curves, little-endian on ristretto255. See Server's javadoc.
    byte[] skFixed = opaqueConfig.cipherSuite().oprfSuite().groupSpec().serializeScalar(sk);

    return new Server(skFixed, pk, oprfSeed, opaqueConfig);
  }

  /**
   * Default {@link JwtKeyDetail} supplier that reads the signing key (and optional previous
   * key) from configuration.
   * <p>
   * Override this bean to implement dynamic key rotation (e.g. from a secrets manager):
   * <pre>{@code
   *   @Bean
   *   public Supplier<JwtKeyDetail> jwtKeyDetailSupplier() {
   *     return () -> keyRotationService.currentJwtKeyDetail();
   *   }
   * }***</pre>
   *
   * <p><strong>The supplier must be callable at construction time.</strong> {@code JwtManager}
   * calls {@code get()} in its constructor to enforce the minimum key length, so a supplier
   * backed by an external key service (Vault, KMS) must be able to answer at startup, not only
   * at first token issue. It is also called on every {@code issueToken}, so a rotation that
   * introduces a key below the minimum is refused there rather than silently signing with it.
   *
   * @param props        the props
   * @param secureRandom the secure random
   * @return the supplier
   */
  @Bean
  @ConditionalOnMissingBean
  public Supplier<JwtKeyDetail> jwtKeyDetailSupplier(HofmannProperties props,
                                                     SecureRandom secureRandom) {
    String secretHex = props.getJwtSecretHex();
    byte[] secret;
    if (secretHex == null || secretHex.isEmpty()) {
      requireEphemeralKeysAllowed(props, "jwt-secret-hex",
          "tokens minted by one node will be rejected by every other, and a restart invalidates "
              + "every session");
      log.warn("No JWT secret configured — generating an ephemeral one because "
          + "allow-ephemeral-keys is set. Tokens will be invalidated on restart. "
          + "Do not use in production.");
      secret = new byte[32];
      secureRandom.nextBytes(secret);
    } else {
      secret = HexFormat.of().parseHex(secretHex);
    }

    String previousHex = props.getJwtPreviousSecretHex();
    byte[] previousSecret = null;
    if (previousHex != null && !previousHex.isEmpty()) {
      previousSecret = HexFormat.of().parseHex(previousHex);
    }

    JwtKeyDetail detail = new JwtKeyDetail(secret, previousSecret);
    return () -> detail;
  }

  /**
   * Jwt manager jwt manager.
   *
   * @param jwtKeyDetailSupplier the jwt key detail supplier
   * @param props                the props
   * @param sessionStore         the session store
   * @return the jwt manager
   */
  @Bean
  @ConditionalOnMissingBean
  public JwtManager jwtManager(Supplier<JwtKeyDetail> jwtKeyDetailSupplier,
                               HofmannProperties props, SessionStore sessionStore) {
    return new JwtManager(jwtKeyDetailSupplier, props.getJwtIssuer(),
        props.getJwtTtlSeconds(), sessionStore);
  }

  /**
   * Default rate limit config supplier that returns static configs from HofmannProperties.
   * Override this bean to implement dynamic config updates (e.g. from a database or config server).
   *
   * @return the rate limit config supplier
   */
  @Bean
  @ConditionalOnMissingBean(name = "rateLimitConfigSupplier")
  public RateLimitConfigSupplier rateLimiterConfigSupplier() {
    return new RateLimitConfigSupplier.DefaultRateLimitConfigSupplier();
  }

  /**
   * Rate limiter for OPAQUE authentication endpoints (keyed by credential identifier).
   * Override this bean to supply a custom implementation (e.g. Redis-backed).
   *
   * @param rateLimitConfigSupplier the rate limit config supplier
   * @return the auth rate limiter
   */
  @Bean(destroyMethod = "shutdown")
  @ConditionalOnMissingBean(name = "authRateLimiter")
  public RateLimiter authRateLimiter(RateLimitConfigSupplier rateLimitConfigSupplier) {
    return new FixedCapacityRateLimiter(rateLimitConfigSupplier.authRateLimitConfig());
  }

  /**
   * Rate limiter for OPAQUE registration endpoints (keyed by credential identifier).
   * Override this bean to supply a custom implementation (e.g. Redis-backed).
   *
   * @param rateLimitConfigSupplier the rate limit config supplier
   * @return the registration rate limiter
   */
  @Bean(destroyMethod = "shutdown")
  @ConditionalOnMissingBean(name = "registrationRateLimiter")
  public RateLimiter registrationRateLimiter(RateLimitConfigSupplier rateLimitConfigSupplier) {
    return new FixedCapacityRateLimiter(rateLimitConfigSupplier.registrationRateLimitConfig());
  }

  /**
   * Rate limiter for the standalone OPRF endpoint (keyed by client IP).
   * Override this bean to supply a custom implementation (e.g. Redis-backed).
   *
   * @param rateLimitConfigSupplier the rate limit config supplier
   * @return the oprf rate limiter
   */
  @Bean(destroyMethod = "shutdown")
  @ConditionalOnMissingBean(name = "oprfRateLimiter")
  public RateLimiter oprfRateLimiter(RateLimitConfigSupplier rateLimitConfigSupplier) {
    return new FixedCapacityRateLimiter(rateLimitConfigSupplier.oprfRateLimitConfig());
  }

  /**
   * Pending session store for in-flight OPAQUE authentication sessions.
   * <p>
   * Override this bean with a distributed implementation (e.g. Redis-backed) for
   * multi-node cluster deployments where authStart and authFinish may be routed
   * to different nodes.
   *
   * @return the pending session store
   */
  @Bean(destroyMethod = "shutdown")
  @ConditionalOnMissingBean
  public PendingSessionStore pendingSessionStore() {
    log.warn("Using in-memory pending session store. Not suitable for multi-node clusters. Do not use in production.");
    return new InMemoryPendingSessionStore();
  }

  /**
   * Default in-memory recovery token store, created only when a {@link RecoveryChallenger}
   * bean is present. Override this bean with a distributed implementation (e.g. Redis)
   * for multi-node clusters.
   *
   * @return the recovery token store
   */
  @Bean(destroyMethod = "shutdown")
  @ConditionalOnBean(RecoveryChallenger.class)
  @ConditionalOnMissingBean
  public RecoveryTokenStore recoveryTokenStore() {
    log.warn("Using in-memory recovery token store. Not suitable for multi-node clusters.");
    return new InMemoryRecoveryTokenStore();
  }

  /**
   * Rate limiter for recovery endpoints, created only when a {@link RecoveryChallenger}
   * bean is present.
   *
   * @param rateLimitConfigSupplier the rate limit config supplier
   * @return the recovery rate limiter
   */
  @Bean(destroyMethod = "shutdown")
  @ConditionalOnBean(RecoveryChallenger.class)
  @ConditionalOnMissingBean(name = "recoveryRateLimiter")
  public RateLimiter recoveryRateLimiter(RateLimitConfigSupplier rateLimitConfigSupplier) {
    return new FixedCapacityRateLimiter(rateLimitConfigSupplier.recoveryRateLimitConfig());
  }

  /**
   * Opaque server manager hofmann opaque server manager.
   *
   * @param opaqueServerKeyDetailSupplier the opaque server key detail supplier
   * @param credentialStore               the credential store
   * @param jwtManager                    the jwt manager
   * @param authRateLimiter               the auth rate limiter
   * @param registrationRateLimiter       the registration rate limiter
   * @param pendingSessionStore           the pending session store
   * @param recoveryChallenger            optional recovery challenger (null if not configured)
   * @param recoveryTokenStore            optional recovery token store (null if not configured)
   * @param recoveryRateLimiter           optional recovery rate limiter (null if not configured)
   * @return the hofmann opaque server manager
   */
  @Bean(destroyMethod = "shutdown")
  @ConditionalOnMissingBean
  public HofmannOpaqueServerManager opaqueServerManager(Supplier<OpaqueServerKeyDetail> opaqueServerKeyDetailSupplier,
                                                        CredentialStore credentialStore,
                                                        JwtManager jwtManager,
                                                        @Qualifier("authRateLimiter") RateLimiter authRateLimiter,
                                                        @Qualifier("registrationRateLimiter") RateLimiter registrationRateLimiter,
                                                        PendingSessionStore pendingSessionStore,
                                                        @Autowired(required = false) RecoveryChallenger recoveryChallenger,
                                                        @Autowired(required = false) RecoveryTokenStore recoveryTokenStore,
                                                        @Autowired(required = false) @Qualifier("recoveryRateLimiter") RateLimiter recoveryRateLimiter) {
    return new HofmannOpaqueServerManager(opaqueServerKeyDetailSupplier, credentialStore, jwtManager,
        authRateLimiter, registrationRateLimiter, pendingSessionStore,
        recoveryChallenger, recoveryTokenStore, recoveryRateLimiter);
  }

  /**
   * OPRF client config response bean, advertising whichever verifiable modes are enabled.
   *
   * <p>The two managers are optional, and their absence is how a mode is disabled — the same
   * signal {@code OprfController.requireMode} turns into a 404. Delegating to
   * {@link VerifiableKeyConfig#clientConfigResponse} keeps this identical to what the Dropwizard
   * adapter advertises; a client cross-checking a pinned key must get the same answer from both.
   *
   * <p><strong>{@code @ConditionalOnMissingBean} means a consumer-supplied
   * {@code OprfClientConfigResponse} bean wins,</strong> and such a bean will not advertise modes
   * unless the consumer builds it the same way. That only costs the client its mismatch check —
   * the endpoints and their 404s are unaffected — but it is worth knowing before wondering why
   * {@code modes} is missing on a deployment that has keys configured.
   *
   * @param props the props
   * @param voprf the VOPRF manager, absent when the mode is disabled
   * @param poprf the POPRF manager, absent when the mode is disabled
   * @return the oprf client config response
   */
  @Bean
  @ConditionalOnMissingBean
  public OprfClientConfigResponse oprfClientConfig(
      HofmannProperties props,
      @Autowired(required = false) VoprfServerManager voprf,
      @Autowired(required = false) PoprfServerManager poprf) {
    return VerifiableKeyConfig.clientConfigResponse(props.getOprfCipherSuite(), voprf, poprf);
  }

  /**
   * Request body size limit filter. Rejects request bodies larger than
   * {@code hofmann.max-request-body-bytes} (default 64 KiB), mirroring the Dropwizard adapter and
   * guarding the OPAQUE/OPRF endpoints against large-payload memory-amplification DoS.
   *
   * @param props the props
   * @return the body size limit filter
   */
  @Bean
  @ConditionalOnMissingBean
  public BodySizeLimitFilter bodySizeLimitFilter(HofmannProperties props) {
    // The batched verifiable endpoints get a tighter, cap-derived limit. The generic limit bounds
    // memory but not element count: at 64 KiB it admits roughly 470 hex-encoded P-521 elements
    // against a configured batch cap of 64, and every one of them is parsed before the manager
    // rejects the batch. See VerifiableOprfLimits.
    long verifiableLimit = VerifiableOprfLimits.maxRequestBodyBytes(
        VoprfServerManager.DEFAULT_MAX_BATCH_SIZE);
    return new BodySizeLimitFilter(props.getMaxRequestBodyBytes(), Map.of(
        "/oprf/verifiable", verifiableLimit,
        "/oprf/partially-oblivious", verifiableLimit));
  }

  /**
   * OPAQUE client config response bean.
   *
   * @param props the props
   * @return the opaque client config response
   */
  @Bean
  @ConditionalOnMissingBean
  public OpaqueClientConfigResponse opaqueClientConfig(HofmannProperties props) {
    return new OpaqueClientConfigResponse(
        props.getOpaqueCipherSuite(),
        props.getContext(),
        props.getArgon2MemoryKib(),
        props.getArgon2Iterations(),
        props.getArgon2Parallelism());
  }

  /**
   * Default {@link ServerProcessorDetail} supplier that reads the master key and processor ID
   * from configuration.  {@code oprfMasterKeyHex} must be set — no random fallback.
   * <p>
   * Override this bean in your application context to implement key rotation or any other
   * custom key-management strategy:
   * <pre>{@code
   *   @Bean
   *   public Supplier<ServerProcessorDetail> serverProcessorDetailSupplier() {
   *     return () -> keyRotationService.currentDetail();
   *   }
   * }***</pre>
   *
   * @param props the props
   * @return the supplier
   */
  /**
   * Origin-keyed limiter in front of the unauthenticated OPAQUE endpoints.
   * <p>
   * The manager's limiters key on the credential identifier, which an attacker varies freely;
   * this is the only dimension that bounds a flood of distinct identifiers, and therefore the
   * only thing between that flood and exhaustion of the limiter's bucket map and the
   * pending-session store.
   *
   * @param supplier the rate limit config supplier
   * @return the origin rate limiter
   */
  @Bean
  @ConditionalOnMissingBean(name = "opaqueOriginRateLimiter")
  @Qualifier("opaqueOriginRateLimiter")
  public RateLimiter opaqueOriginRateLimiter(RateLimitConfigSupplier supplier) {
    RateLimitConfig config = supplier.originRateLimitConfig();
    // Deliberately NOT InMemoryRateLimiter: its capacity is exhaustible by varying the key, which
    // is what this limiter defends against, so using it here would put a second copy of the
    // vulnerability in front of every endpoint. Null disables origin limiting; a no-op limiter is
    // returned rather than a null bean so constructor injection stays simple.
    return config == null ? key -> true : new FixedCapacityRateLimiter(config);
  }

  /**
   * Refuses to start when key material is missing, unless the deployment has explicitly opted in
   * to ephemeral keys. Mirrors the treatment {@code oprfMasterKeyHex} and {@code allowIdentityKsf}
   * already receive.
   */
  private void requireEphemeralKeysAllowed(HofmannProperties props, String setting,
                                           String consequence) {
    if (!props.isAllowEphemeralKeys()) {
      throw new IllegalStateException(
          "hofmann." + setting + " is not configured. Generating key material at startup means "
              + consequence + ". Configure it (openssl rand -hex 32), or set "
              + "hofmann.allow-ephemeral-keys=true to accept ephemeral keys — appropriate for "
              + "local development, not for production.");
    }
  }

  /**
   * Supplies the OPRF master key and processor id for the standalone OPRF endpoint.
   *
   * <p>The returned supplier is fixed at startup: the key is read from
   * {@code hofmann.oprf-master-key-hex}, normalized modulo the group order, and handed out
   * unchanged thereafter. Define your own {@code Supplier<ServerProcessorDetail>} bean to source
   * the key from elsewhere — a KMS, a rotating secret store — and this backs off.
   *
   * @param props the Hofmann properties, supplying the master key, the processor id and the
   *              cipher suite the key is normalized against
   * @return a supplier of the server's OPRF processor detail
   * @throws IllegalStateException if no master key is configured and
   *                               {@code hofmann.allow-ephemeral-keys} is not set. Starting
   *                               without one would produce OPRF outputs that change on every
   *                               restart, silently invalidating every stored hash
   */
  @Bean
  @ConditionalOnMissingBean
  public Supplier<ServerProcessorDetail> serverProcessorDetailSupplier(HofmannProperties props) {
    String masterKeyHex = props.getOprfMasterKeyHex();
    if ((masterKeyHex == null || masterKeyHex.isEmpty()) && props.isAllowEphemeralKeys()) {
      // allowEphemeralKeys has to cover every piece of key material or it is not an escape hatch.
      log.warn("No OPRF master key configured — generating an ephemeral one because "
          + "allow-ephemeral-keys is set. OPRF outputs will not be stable across restarts. "
          + "Do not use in production.");
      OprfCipherSuite suite =
          OprfCipherSuite.builder().withSuite(props.getOprfCipherSuite()).build();
      ServerProcessorDetail ephemeral =
          new ServerProcessorDetail(suite.randomScalar(), props.getOprfProcessorId());
      return () -> ephemeral;
    }
    if (masterKeyHex == null || masterKeyHex.isEmpty()) {
      throw new IllegalStateException(
          "hofmann.oprfMasterKeyHex must be configured for the OPRF endpoint. "
              + "Generate a value with: openssl rand -hex 32. "
              + "Alternatively, provide a custom Supplier<ServerProcessorDetail> bean.");
    }
    BigInteger masterKey = new BigInteger(masterKeyHex, 16);
    // Fail at startup rather than silently running with an unusable key: a key congruent to
    // zero modulo the group order makes every OPRF evaluation return the identity element, and
    // on ristretto255 that decodes cleanly, so the deployment would look healthy while having
    // no effective key at all. Normalizing also folds a key at or above the order into range —
    // the documented `openssl rand -hex 32` exceeds ristretto255's order about 94% of the time
    // — so two configs differing by a multiple of the order stop looking like distinct keys.
    // This changes no output: scalar multiplication reduces modulo the order regardless.
    masterKey = OprfCipherSuite.builder().withSuite(props.getOprfCipherSuite()).build()
        .normalizeSecretKey(masterKey);
    String processorId = props.getOprfProcessorId();
    ServerProcessorDetail detail = new ServerProcessorDetail(masterKey, processorId);
    return () -> detail;
  }

  /**
   * Oprf server manager oprf server manager.
   *
   * @param props                         the props
   * @param secureRandom                  the secure random
   * @param serverProcessorDetailSupplier the server processor detail supplier
   * @return the oprf server manager
   */
  @Bean
  @ConditionalOnMissingBean
  public OprfServerManager oprfServerManager(HofmannProperties props, SecureRandom secureRandom,
                                             Supplier<ServerProcessorDetail> serverProcessorDetailSupplier) {
    OprfCipherSuite oprfSuite = OprfCipherSuite.builder().withSuite(props.getOprfCipherSuite())
        .withRandom(secureRandom).build();
    return new OprfServerManager(oprfSuite, serverProcessorDetailSupplier);
  }

  /**
   * VOPRF (RFC 9497 mode 0x01) manager, present only when {@code hofmann.voprf-master-key-hex}
   * is configured.
   *
   * <p>Conditional rather than always-on, and there is no ephemeral fallback the way there is for
   * the OPAQUE server keys. The point of a verifiable mode is that clients pin the server's public
   * key and check proofs against it; a key regenerated at every restart makes every previously
   * pinned key wrong, so a deployment that has not decided on a key is better off with the
   * endpoint returning 404 than with one that silently changes identity.
   *
   * @param props        the props
   * @param secureRandom the secure random
   * @return the voprf server manager
   */
  @Bean
  @ConditionalOnMissingBean
  @ConditionalOnExpression("!'${hofmann.voprf-master-key-hex:}'.isEmpty()")
  public VoprfServerManager voprfServerManager(HofmannProperties props, SecureRandom secureRandom) {
    OprfCipherSuite suite = VerifiableKeyConfig.suiteFor(
        props.getOprfCipherSuite(), OprfMode.VOPRF, secureRandom);
    VerifiableProcessorDetail detail = VerifiableKeyConfig.detailFrom(
        suite, props.getVoprfMasterKeyHex(), props.getOprfProcessorId() + "-voprf",
        "hofmann.voprf-master-key-hex");
    return new VoprfServerManager(suite, () -> detail);
  }

  /**
   * POPRF (RFC 9497 mode 0x02) manager, present only when {@code hofmann.poprf-master-key-hex}
   * is configured. See {@link #voprfServerManager} for why this is conditional.
   *
   * @param props        the props
   * @param secureRandom the secure random
   * @return the poprf server manager
   */
  @Bean
  @ConditionalOnMissingBean
  @ConditionalOnExpression("!'${hofmann.poprf-master-key-hex:}'.isEmpty()")
  public PoprfServerManager poprfServerManager(HofmannProperties props, SecureRandom secureRandom) {
    OprfCipherSuite suite = VerifiableKeyConfig.suiteFor(
        props.getOprfCipherSuite(), OprfMode.POPRF, secureRandom);
    VerifiableProcessorDetail detail = VerifiableKeyConfig.detailFrom(
        suite, props.getPoprfMasterKeyHex(), props.getOprfProcessorId() + "-poprf",
        "hofmann.poprf-master-key-hex");
    return new PoprfServerManager(suite, () -> detail);
  }
}
