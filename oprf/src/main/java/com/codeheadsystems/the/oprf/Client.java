package com.codeheadsystems.the.oprf;

import com.codeheadsystems.the.oprf.curve.Curve;
import com.codeheadsystems.the.oprf.curve.OctetStringUtils;
import com.codeheadsystems.the.oprf.model.EliminationRequest;
import com.codeheadsystems.the.oprf.model.EliminationResponse;
import com.codeheadsystems.the.oprf.rfc9380.HashToCurve;
import com.codeheadsystems.the.oprf.rfc9497.OprfSuite;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.UUID;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.encoders.Hex;

public class Client {

  private final Curve curve;
  private final HashToCurve hashToCurve;

  public Client() {
    curve = Curve.P256_CURVE;
    hashToCurve = HashToCurve.forP256();
  }

  /**
   * Defines the steps the client takes to convert sensitive data into a key that can be used for elimination.
   * Implements RFC 9497 OPRF(P-256, SHA-256) mode 0 (OPRF).
   *
   * @param server        The server that provides the elimination process.
   * @param sensitiveData The sensitive data that we want to convert into a key for elimination.
   * @return an identity key that represents the original sensitive data after processing through the elimination protocol.
   */
  public String convertToIdentityKey(final Server server,
                                     final String sensitiveData) {
    // Generate our request-unique data. This is for debug tracking
    final String requestId = UUID.randomUUID().toString();
    // We generate a random blinding factor, which is a random scalar value mod to the points on the curve.
    // This blinding factor is used to blind the hashed data point before sending it to the server. The blinding process
    // ensures that the server cannot learn anything about the original data or the hashed point, as it only sees a
    // blinded version of the point.
    final BigInteger blindingFactor = curve.randomScalar();

    // Use raw UTF-8 bytes as input (RFC 9497 passes input directly to HashToGroup)
    final byte[] input = sensitiveData.getBytes(StandardCharsets.UTF_8);

    // Map the input bytes to a point on the P-256 curve using RFC 9497 HashToGroup DST
    final ECPoint hashedEcPoint = hashToCurve.hashToCurve(input, OprfSuite.HASH_TO_GROUP_DST);

    // We blind the EC point so the server cannot learn anything about the original data or the hashed point, as it only
    // sees a blinded version of the point. Then convert it to hex.
    final String blindedPointHex = OctetStringUtils.toHex(hashedEcPoint.multiply(blindingFactor).normalize());

    // Send the request to the server.
    final EliminationRequest eliminationRequest = new EliminationRequest(blindedPointHex, requestId);
    final EliminationResponse eliminationResponse = server.process(eliminationRequest);

    // Get the server's evaluated element (still blinded)
    final ECPoint evaluatedElement = OctetStringUtils.toEcPoint(curve, eliminationResponse.hexCodedEcPoint());

    // RFC 9497 Finalize: unblind and produce the OPRF output
    final byte[] finalHash = OprfSuite.finalize(input, blindingFactor, evaluatedElement);
    return eliminationResponse.processIdentifier() + ":" + Hex.toHexString(finalHash);
  }

}
