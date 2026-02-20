package com.codeheadsystems.oprf.rfc9497;

import com.codeheadsystems.ellipticcurve.curve.OctetStringUtils;
import com.codeheadsystems.ellipticcurve.rfc9380.GroupSpec;
import com.codeheadsystems.ellipticcurve.rfc9380.Ristretto255GroupSpec;
import com.codeheadsystems.ellipticcurve.rfc9380.WeierstrassGroupSpec;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * Central cipher suite abstraction for RFC 9497 OPRF.
 * <p>
 * Supports:
 * <ul>
 *   <li>P256-SHA256 (RFC 9497 §4.1)</li>
 *   <li>P384-SHA384 (RFC 9497 §4.2)</li>
 *   <li>P521-SHA512 (RFC 9497 §4.3)</li>
 *   <li>ristretto255-SHA512 (RFC 9497 §4.4)</li>
 * </ul>
 */
public class OprfCipherSuite {

  public static final OprfCipherSuite P256_SHA256 = buildP256Sha256();
  public static final OprfCipherSuite P384_SHA384 = buildP384Sha384();
  public static final OprfCipherSuite P521_SHA512 = buildP521Sha512();
  public static final OprfCipherSuite RISTRETTO255_SHA512 = buildRistretto255Sha512();

  private final String identifier;
  private final byte[] contextString;
  private final byte[] hashToGroupDst;
  private final byte[] hashToScalarDst;
  private final byte[] deriveKeyPairDst;
  private final GroupSpec groupSpec;
  private final String hashAlgorithm;
  private final int hashOutputLength; // Nh

  OprfCipherSuite(String identifier, String contextSuffix,
                  GroupSpec groupSpec,
                  String hashAlgorithm, int hashOutputLength) {
    this.identifier = identifier;
    this.contextString = buildContextString(contextSuffix);
    this.hashToGroupDst = OctetStringUtils.concat(
        "HashToGroup-".getBytes(StandardCharsets.UTF_8), this.contextString);
    this.hashToScalarDst = OctetStringUtils.concat(
        "HashToScalar-".getBytes(StandardCharsets.UTF_8), this.contextString);
    this.deriveKeyPairDst = OctetStringUtils.concat(
        "DeriveKeyPair".getBytes(StandardCharsets.UTF_8), this.contextString);
    this.groupSpec = groupSpec;
    this.hashAlgorithm = hashAlgorithm;
    this.hashOutputLength = hashOutputLength;
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
        WeierstrassGroupSpec.P256_SHA256,
        "SHA-256", 32
    );
  }

  private static OprfCipherSuite buildP384Sha384() {
    return new OprfCipherSuite(
        "P384-SHA384",
        "P384-SHA384",
        WeierstrassGroupSpec.P384_SHA384,
        "SHA-384", 48
    );
  }

  private static OprfCipherSuite buildP521Sha512() {
    return new OprfCipherSuite(
        "P521-SHA512",
        "P521-SHA512",
        WeierstrassGroupSpec.P521_SHA512,
        "SHA-512", 64
    );
  }

  private static OprfCipherSuite buildRistretto255Sha512() {
    return new OprfCipherSuite(
        "ristretto255-SHA512",
        "ristretto255-SHA512",
        Ristretto255GroupSpec.INSTANCE,
        "SHA-512", 64
    );
  }

  // ─── Accessors ──────────────────────────────────────────────────────────────

  public String identifier() { return identifier; }
  public byte[] contextString() { return contextString; }
  public byte[] hashToGroupDst() { return hashToGroupDst; }
  public byte[] hashToScalarDst() { return hashToScalarDst; }
  public byte[] deriveKeyPairDst() { return deriveKeyPairDst; }
  public GroupSpec groupSpec() { return groupSpec; }
  public String hashAlgorithm() { return hashAlgorithm; }
  public int hashOutputLength() { return hashOutputLength; }
  public int elementSize() { return groupSpec.elementSize(); }

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
    return groupSpec.hashToScalar(input, dst);
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
   * @param evaluatedElement the server's response as a serialized group element
   * @return Nh-byte OPRF output
   */
  public byte[] finalize(byte[] input, BigInteger blind, byte[] evaluatedElement) {
    BigInteger inverseBlind = blind.modInverse(groupSpec.groupOrder());
    byte[] unblindedElement = groupSpec.scalarMultiply(inverseBlind, evaluatedElement);

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
