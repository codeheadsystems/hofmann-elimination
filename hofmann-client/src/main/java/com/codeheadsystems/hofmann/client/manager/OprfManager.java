package com.codeheadsystems.hofmann.client.manager;

import com.codeheadsystems.hofmann.client.accessor.OprfAccessor;
import com.codeheadsystems.hofmann.client.config.OprfConfig;
import com.codeheadsystems.hofmann.client.model.HashResult;
import com.codeheadsystems.hofmann.client.model.ServerIdentifier;
import com.codeheadsystems.oprf.rfc9497.OprfCipherSuite;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.UUID;
import javax.inject.Inject;
import javax.inject.Singleton;
import org.bouncycastle.math.ec.ECPoint;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Singleton
public class OprfManager {
  private static final Logger log = LoggerFactory.getLogger(OprfManager.class);

  private final OprfCipherSuite suite;
  private final OprfAccessor oprfAccessor;

  @Inject
  public OprfManager(final OprfAccessor oprfAccessor,
                     final OprfConfig oprfConfig) {
    log.info("OprfManager({},{})", oprfAccessor, oprfConfig);
    this.oprfAccessor = oprfAccessor;
    this.suite = oprfConfig.suite();
  }

  /**
   * Performs the OPRF hashing process using the server as the OPRF provider.
   *
   * @param sensitiveData sensitive data to be hashed.
   * @return the RFC 9387 compliant OPRF hash of the input, using the server as the OPRF provider.
   */
  public HashResult performHash(String sensitiveData, ServerIdentifier serverIdentifier) {
    final String requestId = UUID.randomUUID().toString();
    log.trace("performHashing(requestId={}, serverIdentifier={})", requestId, serverIdentifier);
    final BigInteger blindingFactor = suite.curve().randomScalar();
    final byte[] input = sensitiveData.getBytes(StandardCharsets.UTF_8);
    final ECPoint hashedEcPoint = suite.hashToCurve().hashToCurve(input, suite.hashToGroupDst());
    final ECPoint blindedPoint = hashedEcPoint.multiply(blindingFactor).normalize();
    final OprfAccessor.Response response = oprfAccessor.handleRequest(serverIdentifier, requestId, blindedPoint);
    final byte[] finalHash = suite.finalize(input, blindingFactor, response.evaluatedPoint());
    return new HashResult(serverIdentifier, response.processIdentifier(), requestId, finalHash);
  }

}
