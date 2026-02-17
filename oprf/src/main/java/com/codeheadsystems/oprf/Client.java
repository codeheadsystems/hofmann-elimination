package com.codeheadsystems.oprf;

import com.codeheadsystems.oprf.curve.Curve;
import com.codeheadsystems.oprf.curve.OctetStringUtils;
import com.codeheadsystems.oprf.model.EliminationRequest;
import com.codeheadsystems.oprf.model.EliminationResponse;
import com.codeheadsystems.oprf.rfc9380.HashToCurve;
import com.codeheadsystems.oprf.rfc9497.OprfCipherSuite;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.UUID;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.encoders.Hex;

public class Client {

  private final Curve curve;
  private final HashToCurve hashToCurve;
  private final OprfCipherSuite suite;

  public Client() {
    this(OprfCipherSuite.P256_SHA256);
  }

  public Client(OprfCipherSuite suite) {
    this.suite = suite;
    this.curve = suite.curve();
    this.hashToCurve = suite.hashToCurve();
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
    final BigInteger blindingFactor = curve.randomScalar();

    final byte[] input = sensitiveData.getBytes(StandardCharsets.UTF_8);

    final ECPoint hashedEcPoint = hashToCurve.hashToCurve(input, suite.hashToGroupDst());

    final String blindedPointHex = OctetStringUtils.toHex(hashedEcPoint.multiply(blindingFactor).normalize());

    final EliminationRequest eliminationRequest = new EliminationRequest(blindedPointHex, requestId);
    final EliminationResponse eliminationResponse = server.process(eliminationRequest);

    final ECPoint evaluatedElement = OctetStringUtils.toEcPoint(curve, eliminationResponse.hexCodedEcPoint());

    final byte[] finalHash = suite.finalize(input, blindingFactor, evaluatedElement);
    return eliminationResponse.processIdentifier() + ":" + Hex.toHexString(finalHash);
  }

}
