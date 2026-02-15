package com.codeheadsystems.the.oprf.rfc9497;

import com.codeheadsystems.the.oprf.curve.Curve;
import com.codeheadsystems.the.oprf.curve.OctetStringUtils;
import com.codeheadsystems.the.oprf.rfc9380.HashToField;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import org.bouncycastle.math.ec.ECPoint;

/**
 * RFC 9497 P256-SHA256 OPRF cipher suite implementation (mode 0 = OPRF).
 * <p>
 * Cipher suite: OPRF(P-256, SHA-256)
 * contextString = "OPRFV1-" || I2OSP(0, 1) || "-P256-SHA256"
 */
public class OprfSuite {

  // contextString = "OPRFV1-\x00-P256-SHA256"
  public static final byte[] CONTEXT_STRING = buildContextString();

  public static final byte[] HASH_TO_GROUP_DST = OctetStringUtils.concat(
      "HashToGroup-".getBytes(StandardCharsets.UTF_8), CONTEXT_STRING);

  public static final byte[] HASH_TO_SCALAR_DST = OctetStringUtils.concat(
      "HashToScalar-".getBytes(StandardCharsets.UTF_8), CONTEXT_STRING);

  public static final byte[] DERIVE_KEY_PAIR_DST = OctetStringUtils.concat(
      "DeriveKeyPair".getBytes(StandardCharsets.UTF_8), CONTEXT_STRING);

  private static byte[] buildContextString() {
    // "OPRFV1-" + 0x00 + "-P256-SHA256"
    return OctetStringUtils.concat(
        "OPRFV1-".getBytes(StandardCharsets.UTF_8),
        new byte[]{0x00},
        "-P256-SHA256".getBytes(StandardCharsets.UTF_8)
    );
  }

  /**
   * Hashes input to a scalar modulo the P-256 group order.
   * Implements HashToScalar from RFC 9497 §2.1 using hash_to_field with group order n.
   *
   * @param input message bytes
   * @param dst   domain separation tag
   * @return scalar in [0, n-1]
   */
  public static BigInteger hashToScalar(byte[] input, byte[] dst) {
    HashToField h2f = HashToField.forP256Scalar();
    BigInteger[] result = h2f.hashToField(input, dst, 1);
    return result[0];
  }

  /**
   * Derives a server private key from a seed and info string per RFC 9497 §3.2.1.
   *
   * @param seed 32-byte random seed
   * @param info application-specific info string
   * @return skS — the derived private key scalar
   */
  public static BigInteger deriveKeyPair(byte[] seed, byte[] info) {
    // deriveInput = seed || I2OSP(len(info), 2) || info
    byte[] deriveInput = OctetStringUtils.concat(seed, OctetStringUtils.I2OSP(info.length, 2), info);

    int counter = 0;
    BigInteger skS = BigInteger.ZERO;
    while (skS.equals(BigInteger.ZERO)) {
      if (counter > 255) {
        throw new RuntimeException("DeriveKeyPair: exceeded counter limit");
      }
      byte[] counterInput = OctetStringUtils.concat(deriveInput, OctetStringUtils.I2OSP(counter, 1));
      skS = hashToScalar(counterInput, DERIVE_KEY_PAIR_DST);
      counter++;
    }
    return skS;
  }

  /**
   * RFC 9497 §3.3.1 Finalize: unblind the evaluated element and produce the OPRF output.
   * <p>
   * Output = SHA-256(I2OSP(len(input),2) || input || I2OSP(33,2) || SerializeElement(N) || "Finalize")
   * where N = blind^(-1) * evaluatedElement
   *
   * @param input            original client input bytes
   * @param blind            the blinding scalar used by the client
   * @param evaluatedElement the server's response point (skS * blind * H(input))
   * @return 32-byte OPRF output
   */
  public static byte[] finalize(byte[] input, BigInteger blind, ECPoint evaluatedElement) {
    // Unblind: N = blind^(-1) * evaluatedElement = skS * H(input)
    BigInteger n = Curve.P256_CURVE.n();
    BigInteger inverseBlind = blind.modInverse(n);
    ECPoint N = evaluatedElement.multiply(inverseBlind).normalize();

    // SerializeElement: 33-byte compressed SEC 1 encoding
    byte[] unblindedElement = N.getEncoded(true);

    // hashInput = I2OSP(len(input),2) || input || I2OSP(len(unblindedElement),2) || unblindedElement || "Finalize"
    byte[] finalizeLabel = "Finalize".getBytes(StandardCharsets.UTF_8);
    byte[] hashInput = OctetStringUtils.concat(
        OctetStringUtils.I2OSP(input.length, 2),
        input,
        OctetStringUtils.I2OSP(unblindedElement.length, 2),
        unblindedElement,
        finalizeLabel
    );

    try {
      MessageDigest digest = MessageDigest.getInstance("SHA-256");
      return digest.digest(hashInput);
    } catch (NoSuchAlgorithmException e) {
      throw new RuntimeException("SHA-256 not available", e);
    }
  }

}
