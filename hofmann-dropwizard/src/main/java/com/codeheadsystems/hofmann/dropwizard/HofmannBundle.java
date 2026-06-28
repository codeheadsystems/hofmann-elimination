package com.codeheadsystems.hofmann.dropwizard;

import com.codeheadsystems.hofmann.dropwizard.auth.HofmannAuthenticator;
import com.codeheadsystems.hofmann.dropwizard.auth.HofmannPrincipal;
import com.codeheadsystems.hofmann.dropwizard.health.OpaqueServerHealthCheck;
import com.codeheadsystems.hofmann.model.opaque.OpaqueClientConfigResponse;
import com.codeheadsystems.hofmann.model.oprf.OprfClientConfigResponse;
import com.codeheadsystems.hofmann.server.manager.HofmannOpaqueServerManager;
import com.codeheadsystems.hofmann.server.manager.JwtKeyDetail;
import com.codeheadsystems.hofmann.server.manager.JwtManager;
import com.codeheadsystems.hofmann.server.manager.OpaqueServerKeyDetail;
import com.codeheadsystems.hofmann.server.ratelimit.InMemoryRateLimiter;
import com.codeheadsystems.hofmann.server.ratelimit.RateLimitConfigSupplier;
import com.codeheadsystems.hofmann.server.ratelimit.RateLimitConfig;
import com.codeheadsystems.hofmann.server.ratelimit.RateLimiter;
import com.codeheadsystems.hofmann.server.resource.OpaqueResource;
import com.codeheadsystems.hofmann.server.resource.OprfResource;
import com.codeheadsystems.hofmann.server.recovery.RecoveryChallenger;
import com.codeheadsystems.hofmann.server.store.CredentialStore;
import com.codeheadsystems.hofmann.server.store.InMemoryCredentialStore;
import com.codeheadsystems.hofmann.server.store.InMemoryPendingSessionStore;
import com.codeheadsystems.hofmann.server.store.InMemoryRecoveryTokenStore;
import com.codeheadsystems.hofmann.server.store.InMemorySessionStore;
import com.codeheadsystems.hofmann.server.store.PendingSessionStore;
import com.codeheadsystems.hofmann.server.store.RecoveryTokenStore;
import com.codeheadsystems.hofmann.server.store.SessionStore;
import com.codeheadsystems.rfc.common.ByteUtils;
import com.codeheadsystems.rfc.common.RandomProvider;
import com.codeheadsystems.rfc.opaque.Server;
import com.codeheadsystems.rfc.opaque.config.OpaqueCipherSuite;
import com.codeheadsystems.rfc.opaque.config.OpaqueConfig;
import com.codeheadsystems.rfc.oprf.manager.OprfServerManager;
import com.codeheadsystems.rfc.oprf.model.ServerProcessorDetail;
import com.codeheadsystems.rfc.oprf.rfc9497.CurveHashSuite;
import com.codeheadsystems.rfc.oprf.rfc9497.OprfCipherSuite;
import io.dropwizard.auth.AuthDynamicFeature;
import io.dropwizard.auth.AuthValueFactoryProvider;
import io.dropwizard.auth.oauth.OAuthCredentialAuthFilter;
import io.dropwizard.core.ConfiguredBundle;
import io.dropwizard.core.setup.Bootstrap;
import io.dropwizard.core.setup.Environment;
import io.dropwizard.servlets.assets.AssetServlet;
import jakarta.inject.Inject;
import jakarta.inject.Singleton;
import jakarta.ws.rs.WebApplicationException;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.container.ContainerRequestFilter;
import jakarta.ws.rs.core.Response;
import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.function.Function;
import java.util.function.Supplier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Dropwizard bundle that wires the Hofmann OPAQUE server into an existing Dropwizard application.
 * <p>
 * Registers the OPAQUE JAX-RS resource, health check, and JWT authentication filter.
 * Requires a {@link HofmannConfiguration} block in the application's YAML config.
 * <p>
 * Embed in your application with in-memory stores (dev/test only):
 * <pre>{@code
 *   bootstrap.addBundle(new HofmannBundle<>());
 * }**</pre>
 * <p>
 * Or supply persistent stores (requires {@code oprfMasterKeyHex} in config):
 * <pre>{@code
 *   bootstrap.addBundle(new HofmannBundle<>(myCredentialStore, mySessionStore, null));
 * }**</pre>
 * <p>
 * To implement key rotation or custom key management for the OPRF endpoint:
 * <pre>{@code
 *   bootstrap.addBundle(new HofmannBundle<>(credentialStore, sessionStore,
 *       () -> keyRotationService.currentDetail()));
 * }**</pre>
 * <p>
 * To supply a custom {@link SecureRandom} (e.g., HSM-backed), use the fluent setter:
 * <pre>{@code
 *   bootstrap.addBundle(new HofmannBundle<>().withSecureRandom(mySecureRandom));
 * }**</pre>
 *
 * @param <C> the type parameter
 */
@Singleton
public class HofmannBundle<C extends HofmannConfiguration> implements ConfiguredBundle<C> {

  private static final Logger log = LoggerFactory.getLogger(HofmannBundle.class);

  private final CredentialStore credentialStore;
  private final SessionStore sessionStore;
  private final PendingSessionStore pendingSessionStore;
  private final Supplier<ServerProcessorDetail> processorDetailSupplier;
  private final RateLimitConfigSupplier rateLimitConfigSupplier;
  private final Function<RateLimitConfig, RateLimiter> rateLimiterFunction;
  private final boolean ephemeralKey;
  private SecureRandom secureRandom = new SecureRandom();
  private Supplier<JwtKeyDetail> jwtKeyDetailSupplier;
  private Supplier<OpaqueServerKeyDetail> opaqueServerKeyDetailSupplier;
  private RecoveryChallenger recoveryChallenger;
  private RecoveryTokenStore recoveryTokenStore;

  /**
   * Creates a bundle backed by in-memory stores and an ephemeral random OPRF master key.
   * <p>
   * For dev/test only — all credentials, sessions, and OPRF outputs will be lost on restart.
   * In production supply persistent stores and either a configured {@code oprfMasterKeyHex}
   * or a custom {@code Supplier<ServerProcessorDetail>}.
   */
  public HofmannBundle() {
    this.credentialStore = new InMemoryCredentialStore();
    this.sessionStore = new InMemorySessionStore();
    this.pendingSessionStore = new InMemoryPendingSessionStore();
    this.processorDetailSupplier = null;
    this.ephemeralKey = true;
    this.rateLimitConfigSupplier = new RateLimitConfigSupplier.DefaultRateLimitConfigSupplier();
    this.rateLimiterFunction = InMemoryRateLimiter::new;
    log.warn("""
        #################################################################
        # WARNING: Using ephemeral in-memory stores and a random OPRF  #
        # master key. All data will be lost on restart.                 #
        # Do not use in production.                                     #
        #################################################################
        """);
  }


  /**
   * Creates a bundle backed by the supplied stores and an optional custom OPRF key supplier.
   * Uses a default in-memory pending session store.
   * <p>
   * When {@code processorDetailSupplier} is non-null it is called on every OPRF request,
   * allowing key rotation — and {@code oprfMasterKeyHex} in the configuration is ignored.
   * When {@code null}, {@code oprfMasterKeyHex} must be set in the configuration.
   *
   * @param credentialStore         the credential store
   * @param sessionStore            the session store
   * @param processorDetailSupplier the processor detail supplier
   */
  @Inject
  public HofmannBundle(CredentialStore credentialStore,
                       SessionStore sessionStore,
                       Supplier<ServerProcessorDetail> processorDetailSupplier) {
    this(credentialStore, sessionStore, new InMemoryPendingSessionStore(), processorDetailSupplier,
        new RateLimitConfigSupplier.DefaultRateLimitConfigSupplier(), InMemoryRateLimiter::new);
  }

  /**
   * Creates a bundle backed by the supplied stores and an optional custom OPRF key supplier.
   * <p>
   * When {@code processorDetailSupplier} is non-null it is called on every OPRF request,
   * allowing key rotation — and {@code oprfMasterKeyHex} in the configuration is ignored.
   * When {@code null}, {@code oprfMasterKeyHex} must be set in the configuration.
   *
   * @param credentialStore         the credential store
   * @param sessionStore            the session store
   * @param pendingSessionStore     the pending session store
   * @param processorDetailSupplier the processor detail supplier
   * @param rateLimitConfigSupplier the rate limit config supplier
   * @param rateLimiterFunction the function to create rate limiters from configs
   */
  @Inject
  public HofmannBundle(CredentialStore credentialStore,
                       SessionStore sessionStore,
                       PendingSessionStore pendingSessionStore,
                       Supplier<ServerProcessorDetail> processorDetailSupplier,
                       RateLimitConfigSupplier rateLimitConfigSupplier,
                       Function<RateLimitConfig, RateLimiter> rateLimiterFunction) {
    this.credentialStore = credentialStore;
    this.sessionStore = sessionStore;
    this.pendingSessionStore = pendingSessionStore;
    this.processorDetailSupplier = processorDetailSupplier;
    this.rateLimitConfigSupplier = rateLimitConfigSupplier;
    this.rateLimiterFunction = rateLimiterFunction;
    this.ephemeralKey = false;
  }

  /**
   * Sets a custom {@link SecureRandom} to use for all random scalar generation
   * (OPRF blinding, ephemeral AKE keys, JWT secret generation when not configured).
   * If not called, a default {@link SecureRandom} is used.
   * <p>
   * Call this before the application starts (i.e., during {@code bootstrap.addBundle(...)}):
   * <pre>{@code
   *   bootstrap.addBundle(new HofmannBundle<>().withSecureRandom(mySecureRandom));
   * }**</pre>
   *
   * @param secureRandom the secure random
   * @return {@code this}, for fluent chaining
   */
  public HofmannBundle<C> withSecureRandom(SecureRandom secureRandom) {
    this.secureRandom = secureRandom;
    return this;
  }

  /**
   * Sets a custom {@link Supplier Supplier&lt;JwtKeyDetail&gt;} for dynamic JWT key rotation.
   * When set, the supplier is called on every sign/verify operation, allowing key rotation
   * without server restart — and {@code jwtSecretHex} / {@code jwtPreviousSecretHex} in the
   * configuration are ignored.
   * <p>
   * Call this before the application starts (i.e., during {@code bootstrap.addBundle(...)}):
   * <pre>{@code
   *   bootstrap.addBundle(new HofmannBundle<>()
   *       .withJwtKeyDetailSupplier(() -> keyRotationService.currentJwtKeyDetail()));
   * }**</pre>
   *
   * @param jwtKeyDetailSupplier the jwt key detail supplier
   * @return {@code this}, for fluent chaining
   */
  public HofmannBundle<C> withJwtKeyDetailSupplier(Supplier<JwtKeyDetail> jwtKeyDetailSupplier) {
    this.jwtKeyDetailSupplier = jwtKeyDetailSupplier;
    return this;
  }

  /**
   * Sets a custom {@link Supplier Supplier&lt;OpaqueServerKeyDetail&gt;} for OPAQUE server
   * key rotation. When set, credentials registered under older key versions are authenticated
   * using the corresponding old keys, and the {@code keyRotationRequired} flag in the auth
   * response triggers client-side re-registration.
   * <p>
   * When set, {@code serverKeySeedHex}, {@code oprfSeedHex}, {@code previousServerKeySeedHex},
   * and {@code previousOprfSeedHex} in the configuration are ignored.
   *
   * @param opaqueServerKeyDetailSupplier the opaque server key detail supplier
   * @return {@code this}, for fluent chaining
   */
  public HofmannBundle<C> withOpaqueServerKeyDetailSupplier(
      Supplier<OpaqueServerKeyDetail> opaqueServerKeyDetailSupplier) {
    this.opaqueServerKeyDetailSupplier = opaqueServerKeyDetailSupplier;
    return this;
  }

  /**
   * Enables account recovery with the given {@link RecoveryChallenger} and a default
   * in-memory {@link RecoveryTokenStore}.
   *
   * @param recoveryChallenger the recovery challenger implementation
   * @return {@code this}, for fluent chaining
   */
  public HofmannBundle<C> withRecovery(RecoveryChallenger recoveryChallenger) {
    return withRecovery(recoveryChallenger, new InMemoryRecoveryTokenStore());
  }

  /**
   * Enables account recovery with the given {@link RecoveryChallenger} and a custom
   * {@link RecoveryTokenStore}.
   *
   * @param recoveryChallenger the recovery challenger implementation
   * @param recoveryTokenStore the recovery token store implementation
   * @return {@code this}, for fluent chaining
   */
  public HofmannBundle<C> withRecovery(RecoveryChallenger recoveryChallenger,
                                       RecoveryTokenStore recoveryTokenStore) {
    this.recoveryChallenger = recoveryChallenger;
    this.recoveryTokenStore = recoveryTokenStore;
    return this;
  }

  @Override
  public void initialize(Bootstrap<?> bootstrap) {
    // No additional bootstrapping needed
  }

  @Override
  public void run(C configuration, Environment environment) {
    // Serve OpenAPI specs and Swagger UI at /api-docs/
    environment.servlets()
        .addServlet("api-docs", new AssetServlet(
            "/META-INF/resources/api-docs", "/api-docs", "index.html", StandardCharsets.UTF_8))
        .addMapping("/api-docs", "/api-docs/*");

    environment.jersey().register(new SecurityHeadersFilter());
    environment.jersey().register(new CorsFilter(new HashSet<>(configuration.getCorsAllowedOrigins())));
    registerSizeLimitFilter(configuration, environment);
    OpaqueConfig opaqueConfig = buildOpaqueConfig(configuration);
    Server server = buildServer(configuration, opaqueConfig);
    JwtManager jwtManager = buildJwtManager(configuration);
    Supplier<OpaqueServerKeyDetail> keySupplier = buildOpaqueServerKeyDetailSupplier(
        configuration, server, opaqueConfig);

    OpaqueClientConfigResponse opaqueClientConfig = new OpaqueClientConfigResponse(
        configuration.getOpaqueCipherSuite(),
        configuration.getContext(),
        configuration.getArgon2MemoryKib(),
        configuration.getArgon2Iterations(),
        configuration.getArgon2Parallelism());

    RateLimiter authRateLimiter = rateLimiterFunction.apply(rateLimitConfigSupplier.authRateLimitConfig());
    RateLimiter registrationRateLimiter = rateLimiterFunction.apply(rateLimitConfigSupplier.registrationRateLimitConfig());
    RateLimiter recoveryRateLimiter = recoveryChallenger != null
        ? rateLimiterFunction.apply(rateLimitConfigSupplier.recoveryRateLimitConfig()) : null;
    HofmannOpaqueServerManager hofmannOpaqueServerManager = new HofmannOpaqueServerManager(
        keySupplier, credentialStore, jwtManager, authRateLimiter, registrationRateLimiter, pendingSessionStore,
        recoveryChallenger, recoveryTokenStore, recoveryRateLimiter);
    environment.jersey().register(new OpaqueResource(hofmannOpaqueServerManager, opaqueClientConfig));
    environment.healthChecks().register("opaque-server", new OpaqueServerHealthCheck(server));

    // JWT auth filter
    HofmannAuthenticator authenticator = new HofmannAuthenticator(jwtManager);
    environment.jersey().register(new AuthDynamicFeature(
        new OAuthCredentialAuthFilter.Builder<HofmannPrincipal>()
            .setAuthenticator(authenticator)
            .setPrefix("Bearer")
            .buildAuthFilter()));
    environment.jersey().register(new AuthValueFactoryProvider.Binder<>(HofmannPrincipal.class));

    // OPRF endpoint
    OprfCipherSuite oprfSuite = OprfCipherSuite.builder().withSuite(configuration.getOprfCipherSuite())
        .withRandom(secureRandom).build();
    Supplier<ServerProcessorDetail> oprfSupplier;
    if (processorDetailSupplier != null) {
      oprfSupplier = processorDetailSupplier;
    } else if (ephemeralKey) {
      oprfSupplier = buildEphemeralProcessorSupplier(configuration.getOprfProcessorId());
    } else {
      oprfSupplier = buildDefaultProcessorSupplier(configuration);
    }
    OprfClientConfigResponse oprfClientConfig = new OprfClientConfigResponse(
        configuration.getOprfCipherSuite());
    OprfServerManager oprfServerManager = new OprfServerManager(oprfSuite, oprfSupplier);
    RateLimiter oprfRateLimiter = rateLimiterFunction.apply(rateLimitConfigSupplier.oprfRateLimitConfig());
    environment.jersey().register(new OprfResource(oprfServerManager, oprfClientConfig, oprfRateLimiter,
        configuration.isTrustForwardedHeaders()));

    // Shutdown lifecycle for manager and rate limiters
    environment.lifecycle().manage(new io.dropwizard.lifecycle.Managed() {
      @Override
      public void start() {
      }

      @Override
      public void stop() {
        hofmannOpaqueServerManager.shutdown();
        oprfRateLimiter.shutdown();
      }
    });
  }

  private void registerSizeLimitFilter(C configuration, Environment environment) {
    long maxBytes = configuration.getMaxRequestBodyBytes();
    ContainerRequestFilter filter = (ContainerRequestContext ctx) -> {
      long length = ctx.getLength();
      if (length > maxBytes) {
        ctx.abortWith(Response.status(Response.Status.REQUEST_ENTITY_TOO_LARGE)
            .entity("Request body exceeds maximum allowed size")
            .build());
        return;
      }
      // Content-Length is -1 for chunked transfer encoding, so the check above does not catch a
      // streamed oversized body. Bound the entity stream as well so the limit is enforced as the
      // body is read regardless of how it is framed.
      ctx.setEntityStream(new BoundedInputStream(ctx.getEntityStream(), maxBytes));
    };
    environment.jersey().register(filter);
  }

  /**
   * Wraps an entity stream and aborts with HTTP 413 once more than {@code maxBytes} have been
   * read, defending against oversized chunked request bodies that carry no Content-Length.
   */
  private static final class BoundedInputStream extends FilterInputStream {
    private final long maxBytes;
    private long count;

    BoundedInputStream(InputStream in, long maxBytes) {
      super(in);
      this.maxBytes = maxBytes;
    }

    @Override
    public int read() throws IOException {
      int b = super.read();
      if (b != -1) {
        increment(1);
      }
      return b;
    }

    @Override
    public int read(byte[] b, int off, int len) throws IOException {
      int n = super.read(b, off, len);
      if (n > 0) {
        increment(n);
      }
      return n;
    }

    private void increment(int read) {
      count += read;
      if (count > maxBytes) {
        throw new WebApplicationException(
            Response.status(Response.Status.REQUEST_ENTITY_TOO_LARGE)
                .entity("Request body exceeds maximum allowed size")
                .build());
      }
    }
  }

  private JwtManager buildJwtManager(C configuration) {
    Supplier<JwtKeyDetail> supplier;
    if (jwtKeyDetailSupplier != null) {
      supplier = jwtKeyDetailSupplier;
    } else {
      String secretHex = configuration.getJwtSecretHex();
      byte[] secret;
      if (secretHex == null || secretHex.isEmpty()) {
        log.warn("No JWT secret configured — generating randomly. "
            + "Tokens will be invalidated on restart. Do not use in production.");
        secret = new byte[32];
        secureRandom.nextBytes(secret);
      } else {
        secret = HexFormat.of().parseHex(secretHex);
      }

      String previousHex = configuration.getJwtPreviousSecretHex();
      byte[] previousSecret = null;
      if (previousHex != null && !previousHex.isEmpty()) {
        previousSecret = HexFormat.of().parseHex(previousHex);
      }

      JwtKeyDetail detail = new JwtKeyDetail(secret, previousSecret);
      supplier = () -> detail;
    }
    return new JwtManager(supplier, configuration.getJwtIssuer(),
        configuration.getJwtTtlSeconds(), sessionStore);
  }

  private Supplier<OpaqueServerKeyDetail> buildOpaqueServerKeyDetailSupplier(
      C configuration, Server currentServer, OpaqueConfig opaqueConfig) {
    if (opaqueServerKeyDetailSupplier != null) {
      return opaqueServerKeyDetailSupplier;
    }

    String prevKeySeedHex = configuration.getPreviousServerKeySeedHex();
    String prevOprfSeedHex = configuration.getPreviousOprfSeedHex();

    boolean hasPrevKeySeed = prevKeySeedHex != null && !prevKeySeedHex.isEmpty();
    boolean hasPrevOprfSeed = prevOprfSeedHex != null && !prevOprfSeedHex.isEmpty();

    if (hasPrevKeySeed != hasPrevOprfSeed) {
      throw new IllegalStateException(
          "Both previousServerKeySeedHex and previousOprfSeedHex must be configured together "
              + "(or both omitted when no key rotation is in progress).");
    }

    if (!hasPrevKeySeed) {
      OpaqueServerKeyDetail detail = new OpaqueServerKeyDetail(currentServer);
      return () -> detail;
    }

    Server previousServer = buildServerFromSeeds(prevKeySeedHex, prevOprfSeedHex, opaqueConfig);
    OpaqueServerKeyDetail detail = new OpaqueServerKeyDetail(
        1, currentServer, java.util.Map.of(0, previousServer));
    return () -> detail;
  }

  private Server buildServerFromSeeds(String keySeedHex, String oprfSeedHex, OpaqueConfig opaqueConfig) {
    HexFormat hex = HexFormat.of();
    OpaqueCipherSuite suite = opaqueConfig.cipherSuite();
    byte[] keySeed = hex.parseHex(keySeedHex);
    byte[] oprfSeed = hex.parseHex(oprfSeedHex);
    OpaqueCipherSuite.AkeKeyPair keyPair = suite.deriveAkeKeyPair(keySeed);
    BigInteger sk = keyPair.privateKey();
    byte[] pk = keyPair.publicKeyBytes();
    byte[] skFixed = ByteUtils.scalarToFixedBytes(sk, opaqueConfig.Nsk());
    return new Server(skFixed, pk, oprfSeed, opaqueConfig);
  }

  private OpaqueConfig buildOpaqueConfig(C configuration) {
    OprfCipherSuite oprfSuite = OprfCipherSuite.builder().withSuite(configuration.getOpaqueCipherSuite())
        .withRandom(secureRandom).build();
    OpaqueCipherSuite suite = new OpaqueCipherSuite(oprfSuite);
    byte[] context = configuration.getContext().getBytes(StandardCharsets.UTF_8);
    if (configuration.getArgon2MemoryKib() == 0) {
      if (!configuration.isAllowIdentityKsf()) {
        throw new IllegalStateException(
            "Argon2 is disabled (argon2MemoryKib=0) but allowIdentityKsf is false. "
                + "Set allowIdentityKsf: true to explicitly allow the identity KSF "
                + "(no key stretching). Do not use identity KSF in production.");
      }
      log.warn("Argon2 disabled — using identity KSF. Do not use in production.");
      return new OpaqueConfig(suite, 0, 0, 0, context, new OpaqueConfig.IdentityKsf(), new RandomProvider(secureRandom));
    }
    return OpaqueConfig.withArgon2id(
        suite,
        context,
        configuration.getArgon2MemoryKib(),
        configuration.getArgon2Iterations(),
        configuration.getArgon2Parallelism());
  }

  private Server buildServer(C configuration, OpaqueConfig opaqueConfig) {
    String keySeedHex = configuration.getServerKeySeedHex();
    String oprfSeedHex = configuration.getOprfSeedHex();

    boolean hasKeySeed = keySeedHex != null && !keySeedHex.isEmpty();
    boolean hasOprfSeed = oprfSeedHex != null && !oprfSeedHex.isEmpty();

    if (!hasKeySeed && !hasOprfSeed) {
      log.warn("No server key seed or OPRF seed configured — generating randomly. "
          + "All registrations will be invalidated on restart. Do not use in production.");
      return Server.generate(opaqueConfig);
    }

    if (!hasKeySeed || !hasOprfSeed) {
      throw new IllegalStateException(
          "Both serverKeySeedHex and oprfSeedHex must be configured together "
              + "(or both omitted for dev mode).");
    }

    HexFormat hex = HexFormat.of();
    OpaqueCipherSuite suite = opaqueConfig.cipherSuite();
    byte[] keySeed = hex.parseHex(keySeedHex);
    byte[] oprfSeed = hex.parseHex(oprfSeedHex);

    OpaqueCipherSuite.AkeKeyPair keyPair = suite.deriveAkeKeyPair(keySeed);
    BigInteger sk = keyPair.privateKey();
    byte[] pk = keyPair.publicKeyBytes();

    byte[] skFixed = ByteUtils.scalarToFixedBytes(sk, opaqueConfig.Nsk());

    return new Server(skFixed, pk, oprfSeed, opaqueConfig);
  }

  private Supplier<ServerProcessorDetail> buildEphemeralProcessorSupplier(String processorId) {
    // randomScalar() via the configured SecureRandom is intentional — ephemeral mode is dev/test only.
    BigInteger masterKey = OprfCipherSuite.builder()
        .withRandomProvider(new RandomProvider(secureRandom))
        .withSuite(CurveHashSuite.P256_SHA256)
        .build().randomScalar();
    ServerProcessorDetail detail = new ServerProcessorDetail(masterKey, processorId);
    return () -> detail;
  }

  private Supplier<ServerProcessorDetail> buildDefaultProcessorSupplier(C configuration) {
    String masterKeyHex = configuration.getOprfMasterKeyHex();
    if (masterKeyHex == null || masterKeyHex.isEmpty()) {
      throw new IllegalStateException(
          "oprfMasterKeyHex must be configured for the OPRF endpoint. "
              + "Generate a value with: openssl rand -hex 32. "
              + "Alternatively, supply a custom Supplier<ServerProcessorDetail> to the HofmannBundle constructor.");
    }
    BigInteger masterKey = new BigInteger(masterKeyHex, 16);
    String processorId = configuration.getOprfProcessorId();
    ServerProcessorDetail detail = new ServerProcessorDetail(masterKey, processorId);
    return () -> detail;
  }
}
