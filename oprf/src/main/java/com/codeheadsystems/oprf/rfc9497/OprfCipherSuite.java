package com.codeheadsystems.oprf.rfc9497;

import com.codeheadsystems.ellipticcurve.curve.OctetStringUtils;
import com.codeheadsystems.ellipticcurve.rfc9380.GroupSpec;
import com.codeheadsystems.ellipticcurve.rfc9380.WeierstrassGroupSpecImpl;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
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
  private final GroupSpec groupSpec;
  private final String hashAlgorithm;
  private final int hashOutputLength; // Nh
  private final SecureRandom random;
  OprfCipherSuite(String identifier,
                  String contextSuffix,
                  GroupSpec groupSpec,
                  String hashAlgorithm,
                  int hashOutputLength) {
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
    this.random = new SecureRandom();
  }

  /**
   * Copy constructor used by {@link #withRandom(SecureRandom)}.
   */
  private OprfCipherSuite(OprfCipherSuite source, SecureRandom random) {
    this.identifier = source.identifier;
    this.contextString = source.contextString;
    this.hashToGroupDst = source.hashToGroupDst;
    this.hashToScalarDst = source.hashToScalarDst;
    this.deriveKeyPairDst = source.deriveKeyPairDst;
    this.groupSpec = source.groupSpec;
    this.hashAlgorithm = source.hashAlgorithm;
    this.hashOutputLength = source.hashOutputLength;
    this.random = random;
  }

  /**
   * Returns the cipher suite for the given name.  Accepted names: {@code "P256_SHA256"},
   * {@code "P384_SHA384"}, {@code "P521_SHA512"}.
   *
   * @throws IllegalArgumentException for unrecognised names
   */
  public static OprfCipherSuite fromName(String name) {
    return switch (name) {
      case "P256_SHA256" -> P256_SHA256;
      case "P384_SHA384" -> P384_SHA384;
      case "P521_SHA512" -> P521_SHA512;
      default -> throw new IllegalArgumentException("Unknown OPRF cipher suite: " + name
          + ". Valid values: P256_SHA256, P384_SHA384, P521_SHA512");
    };
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
        WeierstrassGroupSpecImpl.P256_SHA256,
        "SHA-256", 32
    );
  }

  private static OprfCipherSuite buildP384Sha384() {
    return new OprfCipherSuite(
        "P384-SHA384",
        "P384-SHA384",
        WeierstrassGroupSpecImpl.P384_SHA384,
        "SHA-384", 48
    );
  }

  private static OprfCipherSuite buildP521Sha512() {
    return new OprfCipherSuite(
        "P521-SHA512",
        "P521-SHA512",
        WeierstrassGroupSpecImpl.P521_SHA512,
        "SHA-512", 64
    );
  }

  /**
   * Returns a new {@code OprfCipherSuite} identical to this one but using the given
   * {@link SecureRandom} for all scalar generation. Use this to inject a custom or
   * deterministic random source (e.g. in tests or DI frameworks).
   *
   * @param random the {@link SecureRandom} to use
   * @return a new suite with the provided random source
   */
  public OprfCipherSuite withRandom(SecureRandom random) {
    return new OprfCipherSuite(this, random);
  }

  // ─── Accessors ──────────────────────────────────────────────────────────────

  public String identifier() {
    return identifier;
  }

  public byte[] contextString() {
    return contextString;
  }

  public byte[] hashToGroupDst() {
    return hashToGroupDst;
  }

  public byte[] hashToScalarDst() {
    return hashToScalarDst;
  }

  public byte[] deriveKeyPairDst() {
    return deriveKeyPairDst;
  }

  public GroupSpec groupSpec() {
    return groupSpec;
  }

  public String hashAlgorithm() {
    return hashAlgorithm;
  }

  public int hashOutputLength() {
    return hashOutputLength;
  }

  public int elementSize() {
    return groupSpec.elementSize();
  }

  // ─── Crypto operations ───────────────────────────────────────────────────────

  /**
   * Returns a random scalar uniformly sampled from [1, n-1] using this suite's
   * {@link SecureRandom}. Call {@link #withRandom(SecureRandom)} to inject a
   * custom random source.
   *
   * @return random scalar in [1, n-1]
   */
  public BigInteger randomScalar() {
    BigInteger n = groupSpec.groupOrder();
    BigInteger k;
    do {
      k = new BigInteger(n.bitLength(), random);
    } while (k.compareTo(BigInteger.ONE) < 0 || k.compareTo(n) >= 0);
    return k;
  }

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
    // Fermat inversion: blind^(n-2) mod n ≡ blind^(-1) mod n (n is prime).
    // modPow with a fixed-length exponent (n-2 has the same bit-length as n) runs
    // in time proportional to the exponent length and is significantly more constant-time
    // than the Extended Euclidean Algorithm used by BigInteger.modInverse().
    BigInteger n = groupSpec.groupOrder();
    BigInteger inverseBlind = blind.modPow(n.subtract(BigInteger.TWO), n);
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
