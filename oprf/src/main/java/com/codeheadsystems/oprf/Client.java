package com.codeheadsystems.oprf;

import com.codeheadsystems.oprf.model.EliminationRequest;
import com.codeheadsystems.oprf.model.EliminationResponse;
import com.codeheadsystems.oprf.rfc9380.GroupSpec;
import com.codeheadsystems.oprf.rfc9497.OprfCipherSuite;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.UUID;
import org.bouncycastle.util.encoders.Hex;

public class Client {

  private final OprfCipherSuite suite;
  private final GroupSpec groupSpec;

  public Client() {
    this(OprfCipherSuite.P256_SHA256);
  }

  public Client(OprfCipherSuite suite) {
    this.suite = suite;
    this.groupSpec = suite.groupSpec();
  }

  /**
   * Defines the steps the client takes to convert sensitive data into a key that can be used for elimination.
   * Implements RFC 9497 OPRF mode 0 (OPRF).
   *
   * @param server        The server that provides the elimination process.
   * @param sensitiveData The sensitive data that we want to convert into a key for elimination.
   * @return an identity key that represents the original sensitive data after processing through the elimination protocol.
   */
  public String convertToIdentityKey(final Server server,
                                     final String sensitiveData) {
    final String requestId = UUID.randomUUID().toString();
    final BigInteger blindingFactor = groupSpec.randomScalar();

    final byte[] input = sensitiveData.getBytes(StandardCharsets.UTF_8);

    final byte[] hashedElement = groupSpec.hashToGroup(input, suite.hashToGroupDst());
    final byte[] blindedElement = groupSpec.scalarMultiply(blindingFactor, hashedElement);
    final String blindedPointHex = Hex.toHexString(blindedElement);

    final EliminationRequest eliminationRequest = new EliminationRequest(blindedPointHex, requestId);
    final EliminationResponse eliminationResponse = server.process(eliminationRequest);

    final byte[] evaluatedElement = Hex.decode(eliminationResponse.hexCodedEcPoint());
    final byte[] finalHash = suite.finalize(input, blindingFactor, evaluatedElement);
    return eliminationResponse.processIdentifier() + ":" + Hex.toHexString(finalHash);
  }

}
