package com.codeheadsystems.hofmann.dropwizard;

import com.codeheadsystems.hofmann.dropwizard.auth.HofmannAuthenticator;
import com.codeheadsystems.hofmann.dropwizard.auth.HofmannPrincipal;
import com.codeheadsystems.hofmann.dropwizard.health.OpaqueServerHealthCheck;
import com.codeheadsystems.hofmann.model.opaque.OpaqueClientConfigResponse;
import com.codeheadsystems.hofmann.model.oprf.OprfClientConfigResponse;
import com.codeheadsystems.hofmann.server.auth.JwtManager;
import com.codeheadsystems.hofmann.server.manager.HofmannOpaqueServerManager;
import com.codeheadsystems.hofmann.server.resource.OpaqueResource;
import com.codeheadsystems.hofmann.server.resource.OprfResource;
import com.codeheadsystems.hofmann.server.store.CredentialStore;
import com.codeheadsystems.hofmann.server.store.InMemoryCredentialStore;
import com.codeheadsystems.hofmann.server.store.InMemorySessionStore;
import com.codeheadsystems.hofmann.server.store.SessionStore;
import com.codeheadsystems.rfc.opaque.Server;
import com.codeheadsystems.rfc.opaque.config.OpaqueCipherSuite;
import com.codeheadsystems.rfc.opaque.config.OpaqueConfig;
import com.codeheadsystems.rfc.common.RandomProvider;
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
import jakarta.inject.Inject;
import jakarta.inject.Singleton;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.container.ContainerRequestFilter;
import jakarta.ws.rs.core.Response;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.HexFormat;
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
  private final Supplier<ServerProcessorDetail> processorDetailSupplier;
  private final boolean ephemeralKey;
  private SecureRandom secureRandom = new SecureRandom();

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
    this.processorDetailSupplier = null;
    this.ephemeralKey = true;
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
    this.credentialStore = credentialStore;
    this.sessionStore = sessionStore;
    this.processorDetailSupplier = processorDetailSupplier;
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

  @Override
  public void initialize(Bootstrap<?> bootstrap) {
    // No additional bootstrapping needed
  }

  @Override
  public void run(C configuration, Environment environment) {
    registerSizeLimitFilter(configuration, environment);
    OpaqueConfig opaqueConfig = buildOpaqueConfig(configuration);
    Server server = buildServer(configuration, opaqueConfig);
    JwtManager jwtManager = buildJwtManager(configuration);

    OpaqueClientConfigResponse opaqueClientConfig = new OpaqueClientConfigResponse(
        configuration.getOpaqueCipherSuite(),
        configuration.getContext(),
        configuration.getArgon2MemoryKib(),
        configuration.getArgon2Iterations(),
        configuration.getArgon2Parallelism());

    HofmannOpaqueServerManager hofmannOpaqueServerManager = new HofmannOpaqueServerManager(server, credentialStore, jwtManager);
    environment.lifecycle().manage(new io.dropwizard.lifecycle.Managed() {
      @Override
      public void start() {
      }

      @Override
      public void stop() {
        hofmannOpaqueServerManager.shutdown();
      }
    });
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
    environment.jersey().register(new OprfResource(oprfServerManager, oprfClientConfig));
  }

  private void registerSizeLimitFilter(C configuration, Environment environment) {
    long maxBytes = configuration.getMaxRequestBodyBytes();
    ContainerRequestFilter filter = (ContainerRequestContext ctx) -> {
      long length = ctx.getLength();
      if (length > maxBytes) {
        ctx.abortWith(Response.status(Response.Status.REQUEST_ENTITY_TOO_LARGE)
            .entity("Request body exceeds maximum allowed size")
            .build());
      }
    };
    environment.jersey().register(filter);
  }

  private JwtManager buildJwtManager(C configuration) {
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
    return new JwtManager(secret, configuration.getJwtIssuer(),
        configuration.getJwtTtlSeconds(), sessionStore);
  }

  private OpaqueConfig buildOpaqueConfig(C configuration) {
    OprfCipherSuite oprfSuite = OprfCipherSuite.builder().withSuite(configuration.getOpaqueCipherSuite())
        .withRandom(secureRandom).build();
    OpaqueCipherSuite suite = new OpaqueCipherSuite(oprfSuite);
    byte[] context = configuration.getContext().getBytes(StandardCharsets.UTF_8);
    if (configuration.getArgon2MemoryKib() == 0) {
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

    int nsk = opaqueConfig.Nsk();
    byte[] skBytes = sk.toByteArray();
    byte[] skFixed = new byte[nsk];
    if (skBytes.length > nsk) {
      System.arraycopy(skBytes, skBytes.length - nsk, skFixed, 0, nsk);
    } else {
      System.arraycopy(skBytes, 0, skFixed, nsk - skBytes.length, skBytes.length);
    }

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
