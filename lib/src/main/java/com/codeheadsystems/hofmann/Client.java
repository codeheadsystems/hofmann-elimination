package com.codeheadsystems.hofmann;

import static com.codeheadsystems.hofmann.EcUtilities.BYTES_TO_HEX;
import static com.codeheadsystems.hofmann.EcUtilities.ECPOINT_TO_HEX;
import static com.codeheadsystems.hofmann.EcUtilities.HEX_TO_ECPOINT;

import com.codeheadsystems.hofmann.rfc9380.HashToCurve;
import com.codeheadsystems.hofmann.rfc9497.OprfSuite;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.UUID;
import org.bouncycastle.math.ec.ECPoint;

public class Client {

  public Client() {
  }

  /**
   * Defines the steps the client takes to convert sensitive data into a key that can be used for elimination.
   * Implements RFC 9497 OPRF(P-256, SHA-256) mode 0 (OPRF).
   *
   * @param server        The server that provides the elimination process.
   * @param sensitiveData The sensitive data that we want to convert into a key for elimination.
   * @return an identity key that represents the original sensitive data after processing through the elimination protocol.
   */
  public String covertToIdentityKey(final Server server,
                                    final String sensitiveData) {
    // Generate our request-unique data. This is for debug tracking
    final String requestId = UUID.randomUUID().toString();
    // We generate a random blinding factor, which is a random scalar value mod to the points on the curve.
    // This blinding factor is used to blind the hashed data point before sending it to the server. The blinding process
    // ensures that the server cannot learn anything about the original data or the hashed point, as it only sees a
    // blinded version of the point.
    final BigInteger blindingFactor = Curve.P256_CURVE.randomScaler();

    // Use raw UTF-8 bytes as input (RFC 9497 passes input directly to HashToGroup)
    final byte[] input = sensitiveData.getBytes(StandardCharsets.UTF_8);

    // Map the input bytes to a point on the P-256 curve using RFC 9497 HashToGroup DST
    final ECPoint hashedEcPoint = hashToCurve(input);

    // Blind the hashed point and convert to hex for the server.
    final String blindedPointHex = blindEcPointToHex(hashedEcPoint, blindingFactor);

    // Send the request to the server.
    final EliminationRequest eliminationRequest = new EliminationRequest(blindedPointHex, requestId);
    final EliminationResponse eliminationResponse = server.process(eliminationRequest);

    // Get the server's evaluated element (still blinded)
    final ECPoint evaluatedElement = HEX_TO_ECPOINT(eliminationResponse.hexCodedEcPoint());

    // RFC 9497 Finalize: unblind and produce the OPRF output
    final byte[] finalHash = OprfSuite.finalize(input, blindingFactor, evaluatedElement);
    return eliminationResponse.processIdentifier() + ":" + BYTES_TO_HEX(finalHash);
  }

  /**
   * We blind the EC point so the server cannot learn anything about the original data or the hashed point, as it only
   * sees a blinded version of the point. Then convert it to hex.
   *
   * @param hashedData      The EC Point resulting from the hashing process.
   * @param blindingFactor  The random scalar we will use to bind the request.
   * @return A hex-encoded string representation of the blinded EC point, which can be sent to the server for processing.
   */
  private String blindEcPointToHex(final ECPoint hashedData, final BigInteger blindingFactor) {
    final ECPoint blindedPoint = hashedData.multiply(blindingFactor).normalize();
    return ECPOINT_TO_HEX(blindedPoint);
  }

  /**
   * Maps the input bytes to a point on P-256 using RFC 9497 HashToGroup.
   * Uses the RFC 9497 P256-SHA256 DST for domain separation.
   *
   * @param input The raw input bytes to map to a curve point.
   * @return An ECPoint on P-256.
   */
  private ECPoint hashToCurve(byte[] input) {
    return HashToCurve.forP256(Curve.P256_CURVE.params()).hashToCurve(input, OprfSuite.HASH_TO_GROUP_DST);
  }

}
