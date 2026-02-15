package com.codeheadsystems.hofmann.client.manager;

import com.codeheadsystems.hofmann.client.accessor.OprfAccessor;
import com.codeheadsystems.hofmann.client.config.OprfConfig;
import com.codeheadsystems.hofmann.client.model.HashResult;
import com.codeheadsystems.hofmann.client.model.ServerIdentifier;
import com.codeheadsystems.oprf.curve.Curve;
import com.codeheadsystems.oprf.rfc9380.HashToCurve;
import com.codeheadsystems.oprf.rfc9497.OprfSuite;
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

  private final Curve curve;
  private final HashToCurve hashToCurve;
  private final OprfAccessor oprfAccessor;

  @Inject
  public OprfManager(final OprfAccessor oprfAccessor,
                     final OprfConfig oprfConfig) {
    log.info("OprfManager({},{})", oprfAccessor, oprfConfig);
    this.oprfAccessor = oprfAccessor;
    this.curve = oprfConfig.curve();
    this.hashToCurve = oprfConfig.hashToCurve();
  }

  /**
   * This process manages the OPRF hashing process that uses the server to provide a secret, via the OPRF protocol.
   *
   * @param sensitiveData sensitive data to be hashed.
   * @return the RFC 9387 compliant OPRF hash of the input, using the server as the OPRF provider.
   */
  public HashResult performHash(String sensitiveData, ServerIdentifier serverIdentifier) {
    final String requestId = UUID.randomUUID().toString();
    log.trace("performHashing(requestId={}, serverIdentifier={})", requestId, serverIdentifier);
    final BigInteger blindingFactor = curve.randomScalar();
    final byte[] input = sensitiveData.getBytes(StandardCharsets.UTF_8);
    final ECPoint hashedEcPoint = hashToCurve.hashToCurve(input, OprfSuite.HASH_TO_GROUP_DST);
    final ECPoint blindedPoint = hashedEcPoint.multiply(blindingFactor).normalize();
    final OprfAccessor.Response response = oprfAccessor.handleRequest(serverIdentifier, requestId, blindedPoint);
    final byte[] finalHash = OprfSuite.finalize(input, blindingFactor, response.evaluatedPoint());
    return new HashResult(serverIdentifier, response.processIdentifier(), requestId, finalHash);
  }

}
