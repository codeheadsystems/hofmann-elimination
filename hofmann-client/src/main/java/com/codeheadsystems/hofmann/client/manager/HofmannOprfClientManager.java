package com.codeheadsystems.hofmann.client.manager;

import com.codeheadsystems.hofmann.client.accessor.HofmannOprfAccessor;
import com.codeheadsystems.hofmann.client.model.HofmannHashResult;
import com.codeheadsystems.hofmann.client.model.ServerIdentifier;
import com.codeheadsystems.hofmann.model.oprf.OprfRequest;
import com.codeheadsystems.hofmann.model.oprf.OprfResponse;
import com.codeheadsystems.oprf.manager.OprfClientManager;
import com.codeheadsystems.oprf.model.BlindedRequest;
import com.codeheadsystems.oprf.model.ClientHashingContext;
import com.codeheadsystems.oprf.model.EvaluatedResponse;
import com.codeheadsystems.oprf.model.HashResult;
import javax.inject.Inject;
import javax.inject.Singleton;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Singleton
public class HofmannOprfClientManager {
  private static final Logger log = LoggerFactory.getLogger(HofmannOprfClientManager.class);

  private final HofmannOprfAccessor hofmannOprfAccessor;
  private final OprfClientManager clientManager;


  @Inject
  public HofmannOprfClientManager(final HofmannOprfAccessor hofmannOprfAccessor,
                                  final OprfClientManager clientManager) {
    log.info("HofmannOprfManager({},{})", hofmannOprfAccessor, clientManager);
    this.hofmannOprfAccessor = hofmannOprfAccessor;
    this.clientManager = clientManager;
  }

  /**
   * Performs the OPRF hashing process using the server as the OPRF provider.
   *
   * @param sensitiveData sensitive data to be hashed.
   * @return the RFC 9387 compliant OPRF hash of the input, using the server as the OPRF provider.
   */
  public HofmannHashResult performHash(String sensitiveData, ServerIdentifier serverIdentifier) {
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
