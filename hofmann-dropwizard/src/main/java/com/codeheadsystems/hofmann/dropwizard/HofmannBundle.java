package com.codeheadsystems.hofmann.dropwizard;

import com.codeheadsystems.hofmann.dropwizard.auth.HofmannAuthenticator;
import com.codeheadsystems.hofmann.dropwizard.auth.HofmannPrincipal;
import com.codeheadsystems.hofmann.dropwizard.health.OpaqueServerHealthCheck;
import com.codeheadsystems.hofmann.server.auth.JwtManager;
import com.codeheadsystems.hofmann.server.resource.OpaqueResource;
import com.codeheadsystems.hofmann.server.resource.OprfResource;
import com.codeheadsystems.hofmann.server.store.CredentialStore;
import com.codeheadsystems.hofmann.server.store.InMemoryCredentialStore;
import com.codeheadsystems.hofmann.server.store.InMemorySessionStore;
import com.codeheadsystems.hofmann.server.store.SessionStore;
import com.codeheadsystems.opaque.Server;
import com.codeheadsystems.opaque.config.OpaqueCipherSuite;
import com.codeheadsystems.opaque.config.OpaqueConfig;
import com.codeheadsystems.opaque.internal.OpaqueCrypto;
import com.codeheadsystems.oprf.manager.OprfServerManager;
import com.codeheadsystems.oprf.model.ServerProcessorDetail;
import io.dropwizard.auth.AuthDynamicFeature;
import io.dropwizard.auth.AuthValueFactoryProvider;
import io.dropwizard.auth.oauth.OAuthCredentialAuthFilter;
import io.dropwizard.core.ConfiguredBundle;
import io.dropwizard.core.setup.Bootstrap;
import io.dropwizard.core.setup.Environment;
import jakarta.inject.Inject;
import jakarta.inject.Singleton;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.HexFormat;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Dropwizard bundle that wires the Hofmann OPAQUE server into an existing Dropwizard application.
 * <p>
 * Registers the OPAQUE JAX-RS resource, health check, and JWT authentication filter.
 * Requires a {@link HofmannConfiguration}
 * block in the application's YAML config.
 * <p>
 * Embed in your application with in-memory stores (dev/test only):
 * <pre>{@code
 *   bootstrap.addBundle(new HofmannBundle<>());
 * }</pre>
 * <p>
 * Or supply persistent stores:
 * <pre>{@code
 *   bootstrap.addBundle(new HofmannBundle<>(myCredentialStore, mySessionStore));
 * }</pre>
 */
@Singleton
public class HofmannBundle<C extends HofmannConfiguration> implements ConfiguredBundle<C> {

  private static final Logger log = LoggerFactory.getLogger(HofmannBundle.class);

  private final CredentialStore credentialStore;
  private final SessionStore sessionStore;

  /**
   * Creates a bundle backed by in-memory stores (dev/test only).
   */
  public HofmannBundle() {
    this(new InMemoryCredentialStore(), new InMemorySessionStore());
    log.warn("""
        #################################################################
        # WARNING: Using in-memory stores for credentials and sessions. #
        # All data will be lost on restart. Do not use in production.   #
        #################################################################
        """);
  }

  /**
   * Creates a bundle backed by the supplied stores.
   */
  @Inject
  public HofmannBundle(CredentialStore credentialStore, SessionStore sessionStore) {
    this.credentialStore = credentialStore;
    this.sessionStore = sessionStore;
  }

  @Override
  public void initialize(Bootstrap<?> bootstrap) {
    // No additional bootstrapping needed
  }

  @Override
  public void run(C configuration, Environment environment) {
    OpaqueConfig opaqueConfig = buildOpaqueConfig(configuration);
    Server server = buildServer(configuration, opaqueConfig);
    JwtManager jwtManager = buildJwtManager(configuration);

    environment.jersey().register(
        new OpaqueResource(server, credentialStore, jwtManager));
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
    ServerProcessorDetail serverProcessorDetail = buildProcessorDetail(configuration, opaqueConfig);
    OprfServerManager oprfServerManager = new OprfServerManager(opaqueConfig.cipherSuite().oprfSuite(), () -> serverProcessorDetail);
    environment.jersey().register(new OprfResource(oprfServerManager));
  }

  private JwtManager buildJwtManager(C configuration) {
    String secretHex = configuration.getJwtSecretHex();
    byte[] secret;
    if (secretHex == null || secretHex.isEmpty()) {
      log.warn("No JWT secret configured — generating randomly. "
          + "Tokens will be invalidated on restart. Do not use in production.");
      secret = new byte[32];
      new SecureRandom().nextBytes(secret);
    } else {
      secret = HexFormat.of().parseHex(secretHex);
    }
    return new JwtManager(secret, configuration.getJwtIssuer(),
        configuration.getJwtTtlSeconds(), sessionStore);
  }

  private OpaqueConfig buildOpaqueConfig(C configuration) {
    byte[] context = configuration.getContext().getBytes(StandardCharsets.UTF_8);
    if (configuration.getArgon2MemoryKib() == 0) {
      log.warn("Argon2 disabled — using identity KSF. Do not use in production.");
      return new OpaqueConfig(OpaqueCipherSuite.P256_SHA256, 0, 0, 0, context, new OpaqueConfig.IdentityKsf());
    }
    return OpaqueConfig.withArgon2id(
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

    OpaqueCrypto.AkeKeyPair keyPair = OpaqueCrypto.deriveAkeKeyPair(suite, keySeed);
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

  private ServerProcessorDetail buildProcessorDetail(C configuration, OpaqueConfig opaqueConfig) {
    String masterKeyHex = configuration.getOprfMasterKeyHex();
    String processorId = configuration.getOprfProcessorId();

    if (masterKeyHex == null || masterKeyHex.isEmpty()) {
      log.warn("No OPRF master key configured — generating randomly. "
          + "OPRF outputs will change on restart. Do not use in production.");
      BigInteger masterKey = opaqueConfig.cipherSuite().oprfSuite().randomScalar();
      return new ServerProcessorDetail(masterKey, processorId);
    }

    BigInteger masterKey = new BigInteger(masterKeyHex, 16);
    return new ServerProcessorDetail(masterKey, processorId);
  }
}
