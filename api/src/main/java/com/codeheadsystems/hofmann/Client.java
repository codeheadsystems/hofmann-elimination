package com.codeheadsystems.hofmann;

import static com.codeheadsystems.hofmann.Curve.BYTES_TO_HEX;
import static com.codeheadsystems.hofmann.Curve.ECPOINT_TO_HEX;
import static com.codeheadsystems.hofmann.Curve.HASH;
import static com.codeheadsystems.hofmann.Curve.HEX_TO_ECPOINT;

import com.codeheadsystems.hofmann.rfc9380.HashToCurve;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.UUID;
import org.bouncycastle.math.ec.ECPoint;

public class Client {

  private final String customerId;

  public Client(final String customerId) {
    this.customerId = customerId;
  }

  public ClientKey generateClientKey(final Server server) {
    return server.generateClientKey(customerId);
  }

  /**
   * Defines the steps the client takes to convert sensitive data into a key that can be used for elimination.
   *
   * @param server        The server that provides the elimination process.
   * @param clientKey     A client key that contains the client's unique identifier and the scalar value used in the blinding process. The server knows this key as well
   * @param sensitiveData The sensitive data that we want to convert into a key for elimination.
   * @return an identity key that represents the original sensitive data after processing through the elimination protocol.
   */
  public String covertToIdentityKey(final Server server,
                                    final ClientKey clientKey,
                                    final String sensitiveData) {
    // Generate our request-unique data. This is for debug tracking
    final String requestId = UUID.randomUUID().toString();
    // We generate a random blinding factor, which is a random scalar value mod to the points on the curve.
    // This blinding factor is used to blind the hashed data point before sending it to the server. The blinding process
    // ensures that the server cannot learn anything about the original data or the hashed point, as it only sees a
    // blinded version of the point.
    final BigInteger blindingFactor = Curve.RANDOM_SCALER();

    // First we hash the sensitive data to create a fixed-length representation. The additional security here is nominal,
    // as this step does not protect from rainbow table attacks or preimage attacks on the original data.
    final byte[] hashedBytes = HASH(sensitiveData.getBytes(StandardCharsets.UTF_8));

    // Next, we map the hashed bytes to a point on the elliptic curve. This is done using a deterministic method that
    // ensures the same input bytes will always produce the same curve point.
    final ECPoint hashedEcPoint = hashToCurve(hashedBytes);

    // Blind the hashed point and convert to hex for the server.
    final String blindedPointHex = blindEcPointToHex(hashedEcPoint, blindingFactor, clientKey.clientScalar());

    // Send the request to the server.
    final EliminationRequest eliminationRequest = new EliminationRequest(clientKey.keyIdentifier(), blindedPointHex, requestId);
    final EliminationResponse eliminationResponse = server.process(eliminationRequest);

    // Unblind the hex-encoded point returned by the server.
    ECPoint unblindedPoint = unblindEcPointFromHex(eliminationResponse.hexCodedEcPoint(), blindingFactor);

    // Finally, we convert the unblinded point to bytes and hash it again to produce the final key. We generate the
    // final identify key from this and the process identifier provided by the server, which allows us to trace back the
    // final key to the specific server process that generated it.
    final byte[] unblindedBytes = unblindedPoint.getEncoded(false);
    final byte[] finalHash = HASH(unblindedBytes);
    return eliminationResponse.processIdentifier() + ":" + BYTES_TO_HEX(finalHash);
  }

  /**
   * We convert the hex-encoded point returned by the server back to an ECPoint and unblind it using the inverse of the
   * blinding factor.
   *
   * @param hex            The hex-encoded elliptic curve point returned by the server after applying the server process.
   * @param blindingFactor The random scalar we used to bind the request, which we will use to unblind the point
   *                       returned by the server.
   * @return The original ECPoint that resulted from the server processing, without revealing any information about the
   * original data to the server.
   */
  private ECPoint unblindEcPointFromHex(final String hex, final BigInteger blindingFactor) {
    // Convert the response back to an ECPoint and unblind it using the inverse of the blinding factor. This step
    // retrieves the original point that resulted from the server processed, without revealing any information about
    // the original data to the server.
    final ECPoint eliminationPoint = HEX_TO_ECPOINT(hex);
    final BigInteger inverseBlindingFactor = blindingFactor.modInverse(Curve.DEFAULT_CURVE.getN());
    return eliminationPoint.multiply(inverseBlindingFactor);
  }

  /**
   * We blind the EC point so the server cannot learn anything about the original data or the hashed point, as it only
   * sees a blinded version of the point. Then convert it to hex.
   *
   * @param hashedData      The EC Point resulting from the hashing process.
   * @param blindingFactor  The random scalar we will use to bind the request.
   * @param clientKeyScalar The client key scalar needed for the blinding process.
   * @return A hex-encoded string representation of the blinded EC point, which can be sent to the server for processing.
   */
  private String blindEcPointToHex(final ECPoint hashedData, final BigInteger blindingFactor, final BigInteger clientKeyScalar) {
    // This blinding factor is used to blind the hashed data point before sending it to the server. The blinding process
    // ensures that the server cannot learn anything about the original data or the hashed point, as it only sees a
    // blinded version of the point.
    final ECPoint blindedPoint = hashedData.multiply(blindingFactor).normalize().multiply(clientKeyScalar).normalize();

    // We convert the blinded point to a hexadecimal string representation to send to the server. The server will process
    // this blinded point and return an elimination point, which is also represented as a hexadecimal string.
    return ECPOINT_TO_HEX(blindedPoint);
  }

  /**
   * Maps the hashed bytes to a point on the elliptic curve using RFC 9380 compliant hash-to-curve.
   * <p>
   * This implementation follows RFC 9380 Section 8.7 (secp256k1_XMD:SHA-256_SSWU_RO_) which provides:
   * <ol>
   * <li> Uniform distribution of points across the curve (random oracle property)</li>
   * <li> Deterministic mapping - same input always produces the same output</li>
   * <li> Cryptographic security properties required for OPRF-like protocols</li>
   * </ol>
   * <p>
   * The mapping uses:
   * - hash_to_field: Expands input to field elements using SHA-256
   * - Simplified SWU: Maps field elements to an isogenous curve
   * - 3-isogeny: Transforms points to secp256k1
   *
   * @param hash The input bytes that have been hashed and need to be mapped to a curve point.
   * @return An ECPoint representing the hashed data on the elliptic curve, uniformly distributed and
   *         cryptographically secure.
   */
  private ECPoint hashToCurve(byte[] hash) {
    // Use application-specific domain separation tag
    String dst = "HOFMANN-ELIMINATION-V1-CS01";
    return HashToCurve.hash(hash, dst, Curve.DEFAULT_CURVE);
  }

  private ECPoint hashToCurveApproximation(byte[] hash) {
    BigInteger scalar = new BigInteger(1, hash)
        .mod(Curve.DEFAULT_CURVE.getN().subtract(BigInteger.ONE))
        .add(BigInteger.ONE);

    // Multiply the generator point by the scalar to get a point on the curve
    return Curve.DEFAULT_CURVE.getG().multiply(scalar).normalize();
  }

}
