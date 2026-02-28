package com.codeheadsystems.hofmann.springboot.config;

import com.codeheadsystems.hofmann.model.opaque.OpaqueClientConfigResponse;
import com.codeheadsystems.hofmann.model.oprf.OprfClientConfigResponse;
import com.codeheadsystems.hofmann.server.auth.JwtManager;
import com.codeheadsystems.hofmann.server.manager.HofmannOpaqueServerManager;
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
import com.codeheadsystems.rfc.oprf.rfc9497.OprfCipherSuite;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.HexFormat;
import java.util.function.Supplier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;

/**
 * The type Hofmann auto configuration.
 */
@AutoConfiguration
@EnableConfigurationProperties(HofmannProperties.class)
public class HofmannAutoConfiguration {

  private static final Logger log = LoggerFactory.getLogger(HofmannAutoConfiguration.class);

  /**
   * Default {@link SecureRandom} instance.  Override this bean to supply a custom implementation
   * (e.g. an HSM-backed or seeded provider for testing):
   * <pre>{@code
   *   @Bean
   *   public SecureRandom secureRandom() {
   *     return SecureRandom.getInstance("NativePRNG");
   *   }
   * }**</pre>
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
      log.warn("Argon2 disabled — using identity KSF. Do not use in production.");
      return new OpaqueConfig(suite, 0, 0, 0, context, new OpaqueConfig.IdentityKsf(), new RandomProvider(secureRandom));
    }
    return OpaqueConfig.withArgon2id(
        suite,
        context,
        props.getArgon2MemoryKib(),
        props.getArgon2Iterations(),
        props.getArgon2Parallelism());
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

  /**
   * Jwt manager jwt manager.
   *
   * @param props        the props
   * @param sessionStore the session store
   * @param secureRandom the secure random
   * @return the jwt manager
   */
  @Bean
  @ConditionalOnMissingBean
  public JwtManager jwtManager(HofmannProperties props, SessionStore sessionStore,
                               SecureRandom secureRandom) {
    String secretHex = props.getJwtSecretHex();
    byte[] secret;
    if (secretHex == null || secretHex.isEmpty()) {
      log.warn("No JWT secret configured — generating randomly. "
          + "Tokens will be invalidated on restart. Do not use in production.");
      secret = new byte[32];
      secureRandom.nextBytes(secret);
    } else {
      secret = HexFormat.of().parseHex(secretHex);
    }
    return new JwtManager(secret, props.getJwtIssuer(), props.getJwtTtlSeconds(), sessionStore);
  }

  /**
   * Opaque server manager hofmann opaque server manager.
   *
   * @param server          the server
   * @param credentialStore the credential store
   * @param jwtManager      the jwt manager
   * @return the hofmann opaque server manager
   */
  @Bean(destroyMethod = "shutdown")
  @ConditionalOnMissingBean
  public HofmannOpaqueServerManager opaqueServerManager(Server server, CredentialStore credentialStore,
                                                        JwtManager jwtManager) {
    return new HofmannOpaqueServerManager(server, credentialStore, jwtManager);
  }

  /**
   * OPRF client config response bean.
   *
   * @param props the props
   * @return the oprf client config response
   */
  @Bean
  @ConditionalOnMissingBean
  public OprfClientConfigResponse oprfClientConfig(HofmannProperties props) {
    return new OprfClientConfigResponse(props.getOprfCipherSuite());
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
   * }**</pre>
   *
   * @param props the props
   * @return the supplier
   */
  @Bean
  @ConditionalOnMissingBean
  public Supplier<ServerProcessorDetail> serverProcessorDetailSupplier(HofmannProperties props) {
    String masterKeyHex = props.getOprfMasterKeyHex();
    if (masterKeyHex == null || masterKeyHex.isEmpty()) {
      throw new IllegalStateException(
          "hofmann.oprfMasterKeyHex must be configured for the OPRF endpoint. "
              + "Generate a value with: openssl rand -hex 32. "
              + "Alternatively, provide a custom Supplier<ServerProcessorDetail> bean.");
    }
    BigInteger masterKey = new BigInteger(masterKeyHex, 16);
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
}
