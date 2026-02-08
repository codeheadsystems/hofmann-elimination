package com.codeheadsystems.hofman;

import static java.util.UUID.randomUUID;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.math.ec.ECPoint;

public interface Client {

  ECDomainParameters DOMAIN = Curve.DEFAULT_CURVE;

  /**
   * Defines the steps the client takes to convert sensitive data into a key that can be used for elimination.
   *
   * @param server        The server that provides the elimination process.
   * @param clientKey     A client key that contains the client's unique identifier and the scalar value used in the blinding process. The server knows this key as well
   * @param sensitiveData The sensitive data that we want to convert into a key for elimination.
   * @return an identity key that represents the original sensitive data after processing through the elimination protocol.
   */
  default String covertToIdentityKey(final Server server,
                                     final ClientKey clientKey,
                                     final String sensitiveData) {
    // Generate our request-unique data. This is for debug tracking
    final String requestId = randomUUID().toString();
    // We generate a random blinding factor, which is a random scalar value mod to the points on the curve.
    // This blinding factor is used to blind the hashed data point before sending it to the server. The blinding process
    // ensures that the server cannot learn anything about the original data or the hashed point, as it only sees a
    // blinded version of the point.
    final BigInteger blindingFactor = randomScalar();

    // First we hash the sensitive data to create a fixed-length representation. The additional security here is nominal,
    // as this step does not protect from rainbow table attacks or preimage attacks on the original data.
    final byte[] hashedBytes = generateHashString(sensitiveData.getBytes(StandardCharsets.UTF_8));

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
    final byte[] finalHash = generateHashString(unblindedBytes);
    return eliminationResponse.processIdentifier() + ":" + bytesToHex(finalHash);
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
  default ECPoint unblindEcPointFromHex(final String hex, final BigInteger blindingFactor) {
    // Convert the response back to an ECPoint and unblind it using the inverse of the blinding factor. This step
    // retrieves the original point that resulted from the server processed, without revealing any information about
    // the original data to the server.
    final ECPoint eliminationPoint = hexToEcPoint(hex);
    final BigInteger inverseBlindingFactor = blindingFactor.modInverse(DOMAIN.getN());
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
  default String blindEcPointToHex(final ECPoint hashedData, final BigInteger blindingFactor, final BigInteger clientKeyScalar) {
    // This blinding factor is used to blind the hashed data point before sending it to the server. The blinding process
    // ensures that the server cannot learn anything about the original data or the hashed point, as it only sees a
    // blinded version of the point.
    final ECPoint blindedPoint = hashedData.multiply(blindingFactor).normalize().multiply(clientKeyScalar).normalize();

    // We convert the blinded point to a hexadecimal string representation to send to the server. The server will process
    // this blinded point and return an elimination point, which is also represented as a hexadecimal string.
    return ecPointToHex(blindedPoint);
  }

  /**
   * Hashes the input bytes using a secure hash function to produce a fixed-length output. We use the BLAKE3 hash function
   * with an output length of 32 bytes (256 bits) to ensure a strong and unique hash for the input data.
   *
   * @param bytes The input data to be hashed.
   * @return A byte array containing the hash of the input data.
   */
  byte[] generateHashString(byte[] bytes);

  /**
   * Maps the hashed bytes to a point on the elliptic curve. This is done using a deterministic method that ensures the
   * same input bytes will always produce the same curve point. The curve we use is secp256k1, which is widely used in
   * cryptographic applications. The mapping should ensure that the resulting point is valid and lies on the curve.
   *
   * @param sensitiveBytes The input bytes that have been hashed and need to be mapped to a curve point.
   * @return An ECPoint representing the hashed data on the elliptic curve, which can be used in subsequent
   * cryptographic operations.
   */
  ECPoint hashToCurve(byte[] sensitiveBytes);

  /**
   * Generates a random scalar value that can be used as a blinding factor in the protocol. The scalar should be a
   * random integer in the range [1, n-1], where n is the order of the elliptic curve group.
   *
   * @return A random BigInteger that can be used as a blinding factor in the protocol.
   */
  BigInteger randomScalar();

  /**
   * Converts an ECPoint to a hexadecimal string representation.
   *
   * @param blindedPoint The ECPoint that we want to convert to a hex string.
   * @return A hex-encoded string representation of the given ECPoint.
   */
  String ecPointToHex(ECPoint blindedPoint);

  /**
   * Converts a hexadecimal string representation of an ECPoint back to an ECPoint object.
   *
   * @param hex The hex-encoded elliptic curve point.
   * @return An ECPoint object representing the point encoded in the given hexadecimal string.
   */
  ECPoint hexToEcPoint(String hex);

  /**
   * Converts a byte array to a hexadecimal string representation.
   *
   * @param bytes The byte array that we want to convert to a hex string.
   * @return A hex-encoded string representation of the given byte array.
   */
  String bytesToHex(byte[] bytes);

}
