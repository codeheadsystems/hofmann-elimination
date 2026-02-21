package com.codeheadsystems.oprf.manager;

import com.codeheadsystems.oprf.model.EliminationRequest;
import com.codeheadsystems.oprf.model.EliminationResponse;
import com.codeheadsystems.ellipticcurve.rfc9380.GroupSpec;
import com.codeheadsystems.oprf.model.ClientHashingContext;
import com.codeheadsystems.oprf.rfc9497.OprfCipherSuite;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.UUID;
import org.bouncycastle.util.encoders.Hex;

public class OprfClientManager {

  private final OprfCipherSuite suite;
  private final GroupSpec groupSpec;

  public OprfClientManager() {
    this(OprfCipherSuite.P256_SHA256);
  }

  public OprfClientManager(OprfCipherSuite suite) {
    this.suite = suite;
    this.groupSpec = suite.groupSpec();
  }

  /**
   * This method generates the necessary components for the OPRF hashing process. It creates a unique request ID,
   * generates a random blinding factor, and converts the sensitive data into a byte array format. The resulting
   * context is used for the start and completion of the hashing process.
   * @param sensitiveData the sensitive data you want to hash.
   * @return a hashing context.
   */
  public ClientHashingContext hashingContext(final String sensitiveData) {
    final String requestId = UUID.randomUUID().toString();
    final BigInteger blindingFactor = suite.randomScalar();
    final byte[] input = sensitiveData.getBytes(StandardCharsets.UTF_8);
    return new ClientHashingContext(requestId, blindingFactor, input);
  }

  /**
   * Creates a elimination request for the hashing context. This is largely deterministic based on the hashing context.
   * @param clientHashingContext to generate the elimination request from.
   * @return an elimination request that can be sent to the OPRF server manager.
   */
  public EliminationRequest eliminationRequest(final ClientHashingContext clientHashingContext) {
    final byte[] hashedElement = groupSpec.hashToGroup(clientHashingContext.input(), suite.hashToGroupDst());
    final byte[] blindedElement = groupSpec.scalarMultiply(clientHashingContext.blindingFactor(), hashedElement);
    final String blindedPointHex = Hex.toHexString(blindedElement);
    return new EliminationRequest(blindedPointHex, clientHashingContext.requestId());
  }

  /**
   * Takes the elimination response from the server and the original hashing context to produce the final hash result.
   * This involves unblinding the evaluated element from the server and applying the finalization step as defined in RFC 9497.
   * @param eliminationResponse the response from the OPRF server manager after processing the elimination request.
   * @param clientHashingContext the original context that was used to generate the elimination request, which contains the necessary information for finalizing the hash.
   * @return a string that represents the final hash result.
   */
  public String hashResult(final EliminationResponse eliminationResponse, final ClientHashingContext clientHashingContext) {
    final byte[] evaluatedElement = Hex.decode(eliminationResponse.hexCodedEcPoint());
    final byte[] finalHash = suite.finalize(clientHashingContext.input(), clientHashingContext.blindingFactor(), evaluatedElement);
    return eliminationResponse.processIdentifier() + ":" + Hex.toHexString(finalHash);
  }

}
