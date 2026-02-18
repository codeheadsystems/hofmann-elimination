package com.codeheadsystems.hofmann.dropwizard;

import com.codeheadsystems.hofmann.dropwizard.health.OpaqueServerHealthCheck;
import com.codeheadsystems.hofmann.server.manager.OprfManager;
import com.codeheadsystems.hofmann.server.model.ProcessorDetail;
import com.codeheadsystems.hofmann.server.resource.OpaqueResource;
import com.codeheadsystems.hofmann.server.resource.OprfResource;
import com.codeheadsystems.hofmann.server.store.CredentialStore;
import com.codeheadsystems.hofmann.server.store.InMemoryCredentialStore;
import com.codeheadsystems.opaque.Server;
import com.codeheadsystems.opaque.config.OpaqueConfig;
import com.codeheadsystems.opaque.config.OpaqueCipherSuite;
import com.codeheadsystems.opaque.internal.OpaqueCrypto;
import com.codeheadsystems.oprf.curve.Curve;
import io.dropwizard.core.ConfiguredBundle;
import io.dropwizard.core.setup.Bootstrap;
import io.dropwizard.core.setup.Environment;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.HexFormat;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Dropwizard bundle that wires the Hofmann OPAQUE server into an existing Dropwizard application.
 * <p>
 * Registers the OPAQUE JAX-RS resource and health check. Requires a
 * {@link HofmannConfiguration} block in the application's YAML config.
 * <p>
 * Embed in your application with an in-memory credential store (dev/test only):
 * <pre>{@code
 *   bootstrap.addBundle(new HofmannBundle<>());
 * }</pre>
 *
 * Or supply a persistent {@link CredentialStore} implementation:
 * <pre>{@code
 *   bootstrap.addBundle(new HofmannBundle<>(myDatabaseCredentialStore));
 * }</pre>
 */
public class HofmannBundle<C extends HofmannConfiguration> implements ConfiguredBundle<C> {

  private static final Logger log = LoggerFactory.getLogger(HofmannBundle.class);

  private final CredentialStore credentialStore;

  /** Creates a bundle backed by an {@link InMemoryCredentialStore} (dev/test only). */
  public HofmannBundle() {
    this(new InMemoryCredentialStore());
  }

  /** Creates a bundle backed by the supplied persistent {@link CredentialStore}. */
  public HofmannBundle(CredentialStore credentialStore) {
    this.credentialStore = credentialStore;
  }

  @Override
  public void initialize(Bootstrap<?> bootstrap) {
    // No additional bootstrapping needed
  }

  @Override
  public void run(C configuration, Environment environment) {
    OpaqueConfig opaqueConfig = buildOpaqueConfig(configuration);
    Server server = buildServer(configuration, opaqueConfig);

    environment.jersey().register(new OpaqueResource(server, opaqueConfig, credentialStore));
    environment.healthChecks().register("opaque-server", new OpaqueServerHealthCheck(server));

    ProcessorDetail processorDetail = buildProcessorDetail(configuration);
    OprfManager oprfManager = new OprfManager(() -> processorDetail);
    environment.jersey().register(new OprfResource(oprfManager, Curve.P256_CURVE));
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

  private ProcessorDetail buildProcessorDetail(C configuration) {
    String masterKeyHex = configuration.getOprfMasterKeyHex();
    String processorId = configuration.getOprfProcessorId();

    if (masterKeyHex == null || masterKeyHex.isEmpty()) {
      log.warn("No OPRF master key configured — generating randomly. "
          + "OPRF outputs will change on restart. Do not use in production.");
      BigInteger masterKey = Curve.P256_CURVE.randomScalar();
      return new ProcessorDetail(masterKey, processorId);
    }

    BigInteger masterKey = new BigInteger(masterKeyHex, 16);
    return new ProcessorDetail(masterKey, processorId);
  }
}
