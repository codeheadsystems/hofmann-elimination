package com.codeheadsystems.oprf.rfc9497;

import com.codeheadsystems.oprf.curve.Curve;
import com.codeheadsystems.oprf.curve.OctetStringUtils;
import com.codeheadsystems.oprf.rfc9380.HashToField;
import com.codeheadsystems.oprf.rfc9380.HashToCurve;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.math.ec.ECPoint;

/**
 * Central cipher suite abstraction for RFC 9497 OPRF.
 * <p>
 * Supports:
 * <ul>
 *   <li>P256-SHA256 (RFC 9497 §4.1)</li>
 *   <li>P384-SHA384 (RFC 9497 §4.2)</li>
 *   <li>P521-SHA512 (RFC 9497 §4.3)</li>
 * </ul>
 */
public class OprfCipherSuite {

  public static final OprfCipherSuite P256_SHA256 = buildP256Sha256();
  public static final OprfCipherSuite P384_SHA384 = buildP384Sha384();
  public static final OprfCipherSuite P521_SHA512 = buildP521Sha512();

  private final String identifier;
  private final byte[] contextString;
  private final byte[] hashToGroupDst;
  private final byte[] hashToScalarDst;
  private final byte[] deriveKeyPairDst;
  private final Curve curve;
  private final HashToCurve hashToCurve;
  private final HashToField hashToScalarField;
  private final String hashAlgorithm;
  private final int hashOutputLength; // Nh
  private final int elementSize;      // Noe = Npk (compressed point size)

  private OprfCipherSuite(String identifier, String contextSuffix,
                           Curve curve, HashToCurve hashToCurve,
                           HashToField hashToScalarField,
                           String hashAlgorithm, int hashOutputLength, int elementSize) {
    this.identifier = identifier;
    this.contextString = buildContextString(contextSuffix);
    this.hashToGroupDst = OctetStringUtils.concat(
        "HashToGroup-".getBytes(StandardCharsets.UTF_8), this.contextString);
    this.hashToScalarDst = OctetStringUtils.concat(
        "HashToScalar-".getBytes(StandardCharsets.UTF_8), this.contextString);
    this.deriveKeyPairDst = OctetStringUtils.concat(
        "DeriveKeyPair".getBytes(StandardCharsets.UTF_8), this.contextString);
    this.curve = curve;
    this.hashToCurve = hashToCurve;
    this.hashToScalarField = hashToScalarField;
    this.hashAlgorithm = hashAlgorithm;
    this.hashOutputLength = hashOutputLength;
    this.elementSize = elementSize;
  }

  private static byte[] buildContextString(String suffix) {
    // "OPRFV1-" + 0x00 + "-" + suffix
    return OctetStringUtils.concat(
        "OPRFV1-".getBytes(StandardCharsets.UTF_8),
        new byte[]{0x00},
        ("-" + suffix).getBytes(StandardCharsets.UTF_8)
    );
  }

  private static OprfCipherSuite buildP256Sha256() {
    return new OprfCipherSuite(
        "P256-SHA256",
        "P256-SHA256",
        Curve.P256_CURVE,
        HashToCurve.forP256(),
        HashToField.forP256Scalar(),
        "SHA-256", 32, 33
    );
  }

  private static OprfCipherSuite buildP384Sha384() {
    return new OprfCipherSuite(
        "P384-SHA384",
        "P384-SHA384",
        Curve.P384_CURVE,
        HashToCurve.forP384(),
        HashToField.forP384Scalar(),
        "SHA-384", 48, 49
    );
  }

  private static OprfCipherSuite buildP521Sha512() {
    return new OprfCipherSuite(
        "P521-SHA512",
        "P521-SHA512",
        Curve.P521_CURVE,
        HashToCurve.forP521(),
        HashToField.forP521Scalar(),
        "SHA-512", 64, 67
    );
  }

  // ─── Accessors ──────────────────────────────────────────────────────────────

  public String identifier() { return identifier; }
  public byte[] contextString() { return contextString; }
  public byte[] hashToGroupDst() { return hashToGroupDst; }
  public byte[] hashToScalarDst() { return hashToScalarDst; }
  public byte[] deriveKeyPairDst() { return deriveKeyPairDst; }
  public Curve curve() { return curve; }
  public HashToCurve hashToCurve() { return hashToCurve; }
  public String hashAlgorithm() { return hashAlgorithm; }
  public int hashOutputLength() { return hashOutputLength; }
  public int elementSize() { return elementSize; }

  // ─── Crypto operations ───────────────────────────────────────────────────────

  /**
   * Hashes input to a scalar modulo the group order.
   * Implements HashToScalar from RFC 9497 §2.1.
   *
   * @param input message bytes
   * @param dst   domain separation tag
   * @return scalar in [0, n-1]
   */
  public BigInteger hashToScalar(byte[] input, byte[] dst) {
    BigInteger[] result = hashToScalarField.hashToField(input, dst, 1);
    return result[0];
  }

  /**
   * Derives a server private key from a seed and info string per RFC 9497 §3.2.1.
   *
   * @param seed 32+ byte random seed
   * @param info application-specific info bytes
   * @return skS — the derived private key scalar
   */
  public BigInteger deriveKeyPair(byte[] seed, byte[] info) {
    byte[] deriveInput = OctetStringUtils.concat(seed, OctetStringUtils.I2OSP(info.length, 2), info);

    int counter = 0;
    BigInteger skS = BigInteger.ZERO;
    while (skS.equals(BigInteger.ZERO)) {
      if (counter > 255) {
        throw new RuntimeException("DeriveKeyPair: exceeded counter limit");
      }
      byte[] counterInput = OctetStringUtils.concat(deriveInput, OctetStringUtils.I2OSP(counter, 1));
      skS = hashToScalar(counterInput, deriveKeyPairDst);
      counter++;
    }
    return skS;
  }

  /**
   * RFC 9497 §3.3.1 Finalize: unblind the evaluated element and produce the OPRF output.
   *
   * @param input            original client input bytes
   * @param blind            the blinding scalar used by the client
   * @param evaluatedElement the server's response point (skS * blind * H(input))
   * @return Nh-byte OPRF output
   */
  public byte[] finalize(byte[] input, BigInteger blind, ECPoint evaluatedElement) {
    BigInteger n = curve.n();
    BigInteger inverseBlind = blind.modInverse(n);
    ECPoint N = evaluatedElement.multiply(inverseBlind).normalize();

    // SerializeElement: compressed SEC1 encoding
    byte[] unblindedElement = N.getEncoded(true);

    byte[] finalizeLabel = "Finalize".getBytes(StandardCharsets.UTF_8);
    byte[] hashInput = OctetStringUtils.concat(
        OctetStringUtils.I2OSP(input.length, 2),
        input,
        OctetStringUtils.I2OSP(unblindedElement.length, 2),
        unblindedElement,
        finalizeLabel
    );

    return hash(hashInput);
  }

  /**
   * Computes Hash(data) using the suite's hash algorithm.
   *
   * @param data input bytes
   * @return hash output
   */
  public byte[] hash(byte[] data) {
    try {
      return MessageDigest.getInstance(hashAlgorithm).digest(data);
    } catch (NoSuchAlgorithmException e) {
      throw new RuntimeException(hashAlgorithm + " not available", e);
    }
  }

  /**
   * Computes HMAC(key, data) using the suite's hash algorithm.
   *
   * @param key  HMAC key
   * @param data input bytes
   * @return HMAC output
   */
  public byte[] hmac(byte[] key, byte[] data) {
    try {
      String macAlg = "Hmac" + hashAlgorithm.replace("-", "");
      Mac mac = Mac.getInstance(macAlg);
      mac.init(new SecretKeySpec(key, macAlg));
      return mac.doFinal(data);
    } catch (Exception e) {
      throw new RuntimeException("HMAC with " + hashAlgorithm + " not available", e);
    }
  }
}
