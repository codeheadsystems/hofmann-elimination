package com.codeheadsystems.rfc.oprf.manager;

import com.codeheadsystems.rfc.ellipticcurve.rfc9380.GroupSpec;
import com.codeheadsystems.rfc.oprf.model.BlindedRequest;
import com.codeheadsystems.rfc.oprf.model.ClientHashingContext;
import com.codeheadsystems.rfc.oprf.model.EvaluatedResponse;
import com.codeheadsystems.rfc.oprf.model.HashResult;
import com.codeheadsystems.rfc.oprf.rfc9497.OprfCipherSuite;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.UUID;
import org.bouncycastle.util.encoders.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * The type Oprf client manager.
 */
public class OprfClientManager {

  private static final Logger log = LoggerFactory.getLogger(OprfClientManager.class);

  private final OprfCipherSuite suite;
  private final GroupSpec groupSpec;

  /**
   * Instantiates a new Oprf client manager.
   *
   * @param suite the suite
   */
  public OprfClientManager(OprfCipherSuite suite) {
    log.info("OprfClientManager({})", suite.hashAlgorithm());
    this.suite = suite;
    this.groupSpec = suite.groupSpec();
  }

  /**
   * This method generates the necessary components for the OPRF hashing process. It creates a unique request ID,
   * generates a random blinding factor, and converts the sensitive data into a byte array format. The resulting
   * context is used for the start and completion of the hashing process.
   *
   * @param sensitiveData the sensitive data you want to hash.
   * @return a hashing context.
   */
  public ClientHashingContext hashingContext(final String sensitiveData) {
    final String requestId = UUID.randomUUID().toString();
    log.trace("performHashing(requestId={})", requestId);
    final BigInteger blindingFactor = suite.randomScalar();
    final byte[] input = sensitiveData.getBytes(StandardCharsets.UTF_8);
    return new ClientHashingContext(requestId, blindingFactor, input);
  }

  /**
   * Creates a elimination request for the hashing context. This is largely deterministic based on the hashing context.
   *
   * @param clientHashingContext to generate the elimination request from.
   * @return an elimination request that can be sent to the OPRF server manager.
   */
  public BlindedRequest eliminationRequest(final ClientHashingContext clientHashingContext) {
    log.trace("eliminationRequest(requestId={})", clientHashingContext.requestId());
    final byte[] hashedElement = groupSpec.hashToGroup(clientHashingContext.input(), suite.hashToGroupDst());
    final byte[] blindedElement = groupSpec.scalarMultiply(clientHashingContext.blindingFactor(), hashedElement);
    final String blindedPointHex = Hex.toHexString(blindedElement);
    return new BlindedRequest(blindedPointHex, clientHashingContext.requestId());
  }

  /**
   * Takes the elimination response from the server and the original hashing context to produce the final hash result.
   * This involves unblinding the evaluated element from the server and applying the finalization step as defined in RFC 9497.
   *
   * @param evaluatedResponse    the response from the OPRF server manager after processing the elimination request.
   * @param clientHashingContext the original context that was used to generate the elimination request, which contains the necessary information for finalizing the hash.
   * @return a string that represents the final hash result.
   */
  public HashResult hashResult(final EvaluatedResponse evaluatedResponse, final ClientHashingContext clientHashingContext) {
    log.trace("hashResult(requestId={})", clientHashingContext.requestId());
    final byte[] evaluatedElement = Hex.decode(evaluatedResponse.evaluatedPoint());
    final byte[] finalHash = suite.finalize(clientHashingContext.input(), clientHashingContext.blindingFactor(), evaluatedElement);
    return new HashResult(finalHash, evaluatedResponse.processIdentifier());
  }

}
