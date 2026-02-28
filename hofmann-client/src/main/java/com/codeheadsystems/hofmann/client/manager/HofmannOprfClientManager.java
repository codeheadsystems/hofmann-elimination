package com.codeheadsystems.hofmann.client.manager;

import com.codeheadsystems.hofmann.client.accessor.HofmannOprfAccessor;
import com.codeheadsystems.hofmann.client.config.OprfClientConfig;
import com.codeheadsystems.hofmann.client.model.HofmannHashResult;
import com.codeheadsystems.hofmann.client.model.ServerIdentifier;
import com.codeheadsystems.hofmann.model.oprf.OprfRequest;
import com.codeheadsystems.hofmann.model.oprf.OprfResponse;
import com.codeheadsystems.rfc.oprf.manager.OprfClientManager;
import com.codeheadsystems.rfc.oprf.model.BlindedRequest;
import com.codeheadsystems.rfc.oprf.model.ClientHashingContext;
import com.codeheadsystems.rfc.oprf.model.EvaluatedResponse;
import com.codeheadsystems.rfc.oprf.model.HashResult;
import java.util.Collections;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Function;
import javax.inject.Inject;
import javax.inject.Singleton;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * The type Hofmann oprf client manager.
 */
@Singleton
public class HofmannOprfClientManager {
  private static final Logger log = LoggerFactory.getLogger(HofmannOprfClientManager.class);

  private final HofmannOprfAccessor hofmannOprfAccessor;
  private final Function<ServerIdentifier, OprfClientManager> managerFactory;

  /**
   * Production constructor — auto-fetches config from each server on first use.
   *
   * @param hofmannOprfAccessor the hofmann oprf accessor
   */
  @Inject
  public HofmannOprfClientManager(final HofmannOprfAccessor hofmannOprfAccessor) {
    this(hofmannOprfAccessor, Collections.emptyMap());
  }

  /**
   * CLI / override constructor — uses the supplied per-server config overrides; falls back to
   * auto-fetching for servers not present in the map.
   *
   * @param hofmannOprfAccessor the hofmann oprf accessor
   * @param overrides           per-server config overrides (may be empty)
   */
  public HofmannOprfClientManager(final HofmannOprfAccessor hofmannOprfAccessor,
                                   final Map<ServerIdentifier, OprfClientConfig> overrides) {
    log.info("HofmannOprfClientManager({}, overrides={})", hofmannOprfAccessor, overrides.size());
    this.hofmannOprfAccessor = hofmannOprfAccessor;
    ConcurrentHashMap<ServerIdentifier, OprfClientManager> cache = new ConcurrentHashMap<>();
    this.managerFactory = id -> cache.computeIfAbsent(id, k -> {
      OprfClientConfig cfg = overrides.getOrDefault(k, null);
      if (cfg == null) {
        cfg = OprfClientConfig.fromServerConfig(hofmannOprfAccessor.getOprfConfig(k));
      }
      return new OprfClientManager(cfg.suite());
    });
  }

  /**
   * Package-private test constructor — uses the supplied fixed manager for every server.
   *
   * @param hofmannOprfAccessor the hofmann oprf accessor
   * @param fixedManager        manager returned for every server identifier
   */
  HofmannOprfClientManager(final HofmannOprfAccessor hofmannOprfAccessor,
                            final OprfClientManager fixedManager) {
    log.info("HofmannOprfClientManager({}, fixedManager)", hofmannOprfAccessor);
    this.hofmannOprfAccessor = hofmannOprfAccessor;
    this.managerFactory = ignored -> fixedManager;
  }

  /**
   * Performs the OPRF hashing process using the server as the OPRF provider.
   *
   * @param sensitiveData    sensitive data to be hashed.
   * @param serverIdentifier the server identifier
   * @return the RFC 9387 compliant OPRF hash of the input, using the server as the OPRF provider.
   */
  public HofmannHashResult performHash(String sensitiveData, ServerIdentifier serverIdentifier) {
    final OprfClientManager clientManager = managerFactory.apply(serverIdentifier);
    final ClientHashingContext context = clientManager.hashingContext(sensitiveData);
    log.trace("performHashing(requestId={}, serverIdentifier={})", context.requestId(), serverIdentifier);
    final BlindedRequest blindedRequest = clientManager.eliminationRequest(context);
    final OprfRequest oprfRequest = new OprfRequest(blindedRequest);
    final OprfResponse oprfResponse = hofmannOprfAccessor.handleRequest(serverIdentifier, oprfRequest);
    final EvaluatedResponse evaluatedResponse = oprfResponse.evaluatedResponse();
    final HashResult hashResult = clientManager.hashResult(evaluatedResponse, context);
    return new HofmannHashResult(serverIdentifier, hashResult.processIdentifier(), context.requestId(), hashResult.hash());
  }

}
