package com.codeheadsystems.hofmann.springboot.config;

import com.codeheadsystems.hofmann.server.auth.JwtManager;
import com.codeheadsystems.hofmann.server.manager.HofmannOpaqueServerManager;
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
import com.codeheadsystems.oprf.rfc9497.OprfCipherSuite;
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
   * }</pre>
   */
  @Bean
  @ConditionalOnMissingBean
  public SecureRandom secureRandom() {
    return new SecureRandom();
  }

  @Bean
  @ConditionalOnMissingBean
  public CredentialStore credentialStore() {
    log.warn("Using in-memory credential store. All data will be lost on restart. Do not use in production.");
    return new InMemoryCredentialStore();
  }

  @Bean
  @ConditionalOnMissingBean
  public SessionStore sessionStore() {
    log.warn("Using in-memory session store. All data will be lost on restart. Do not use in production.");
    return new InMemorySessionStore();
  }

  @Bean
  @ConditionalOnMissingBean
  public OpaqueConfig opaqueConfig(HofmannProperties props, SecureRandom secureRandom) {
    OprfCipherSuite oprfSuite = OprfCipherSuite.fromName(props.getOpaqueCipherSuite())
        .withRandom(secureRandom);
    OpaqueCipherSuite suite = new OpaqueCipherSuite(oprfSuite);
    byte[] context = props.getContext().getBytes(StandardCharsets.UTF_8);
    if (props.getArgon2MemoryKib() == 0) {
      log.warn("Argon2 disabled — using identity KSF. Do not use in production.");
      return new OpaqueConfig(suite, 0, 0, 0, context, new OpaqueConfig.IdentityKsf());
    }
    return OpaqueConfig.withArgon2id(
        suite,
        context,
        props.getArgon2MemoryKib(),
        props.getArgon2Iterations(),
        props.getArgon2Parallelism());
  }

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

  @Bean(destroyMethod = "shutdown")
  @ConditionalOnMissingBean
  public HofmannOpaqueServerManager opaqueServerManager(Server server, CredentialStore credentialStore,
                                                        JwtManager jwtManager) {
    return new HofmannOpaqueServerManager(server, credentialStore, jwtManager);
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
   * }</pre>
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

  @Bean
  @ConditionalOnMissingBean
  public OprfServerManager oprfServerManager(HofmannProperties props, SecureRandom secureRandom,
                                             Supplier<ServerProcessorDetail> serverProcessorDetailSupplier) {
    OprfCipherSuite oprfSuite = OprfCipherSuite.fromName(props.getOprfCipherSuite())
        .withRandom(secureRandom);
    return new OprfServerManager(oprfSuite, serverProcessorDetailSupplier);
  }
}
