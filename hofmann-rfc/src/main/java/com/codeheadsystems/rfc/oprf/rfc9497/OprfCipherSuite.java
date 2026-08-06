package com.codeheadsystems.rfc.oprf.rfc9497;

import com.codeheadsystems.rfc.common.ByteUtils;
import com.codeheadsystems.rfc.common.RandomProvider;
import com.codeheadsystems.rfc.ellipticcurve.rfc9380.GroupSpec;
import com.codeheadsystems.rfc.ellipticcurve.rfc9380.Ristretto255GroupSpec;
import com.codeheadsystems.rfc.ellipticcurve.rfc9380.WeierstrassGroupSpecImpl;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
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

  private static final Logger log = LoggerFactory.getLogger(OprfCipherSuite.class);

  private final String identifier;
  private final byte[] contextString;
  private final byte[] hashToGroupDst;
  private final byte[] hashToScalarDst;
  private final byte[] deriveKeyPairDst;
  private final GroupSpec groupSpec;
  private final String hashAlgorithm;
  private final int hashOutputLength; // Nh
  private final RandomProvider randomProvider;

  /**
   * Copy constructor used by {@link #withRandom(SecureRandom)} and {@link #withRandom(RandomProvider)}.
   */
  private OprfCipherSuite(OprfCipherSuite source, RandomProvider randomProvider) {
    this.identifier = source.identifier;
    this.contextString = source.contextString;
    this.hashToGroupDst = source.hashToGroupDst;
    this.hashToScalarDst = source.hashToScalarDst;
    this.deriveKeyPairDst = source.deriveKeyPairDst;
    this.groupSpec = source.groupSpec;
    this.hashAlgorithm = source.hashAlgorithm;
    this.hashOutputLength = source.hashOutputLength;
    this.randomProvider = randomProvider;
  }

  private OprfCipherSuite(String identifier,
                          String contextSuffix,
                          GroupSpec groupSpec,
                          String hashAlgorithm,
                          int hashOutputLength,
                          RandomProvider randomProvider) {
    this.identifier = identifier;
    this.contextString = buildContextString(contextSuffix);
    this.hashToGroupDst = ByteUtils.concat(
        "HashToGroup-".getBytes(StandardCharsets.UTF_8), this.contextString);
    this.hashToScalarDst = ByteUtils.concat(
        "HashToScalar-".getBytes(StandardCharsets.UTF_8), this.contextString);
    this.deriveKeyPairDst = ByteUtils.concat(
        "DeriveKeyPair".getBytes(StandardCharsets.UTF_8), this.contextString);
    this.groupSpec = groupSpec;
    this.hashAlgorithm = hashAlgorithm;
    this.hashOutputLength = hashOutputLength;
    this.randomProvider = randomProvider;
  }

  private static byte[] buildContextString(String suffix) {
    // "OPRFV1-" + 0x00 + "-" + suffix
    return ByteUtils.concat(
        "OPRFV1-".getBytes(StandardCharsets.UTF_8),
        new byte[]{0x00},
        ("-" + suffix).getBytes(StandardCharsets.UTF_8)
    );
  }

  /**
   * Builder builder.
   *
   * @return the builder
   */
  public static Builder builder() {
    return new Builder();
  }

  /**
   * Returns a new {@code OprfCipherSuite} identical to this one but using the given
   * {@link SecureRandom} for all scalar and random byte generation. Use this to inject
   * a custom or deterministic random source (e.g. in tests or DI frameworks).
   *
   * @param random the {@link SecureRandom} to use
   * @return a new suite with the provided random source
   */
  public OprfCipherSuite withRandom(SecureRandom random) {
    return new OprfCipherSuite(this, new RandomProvider(random));
  }

  /**
   * Returns a new {@code OprfCipherSuite} identical to this one but using the given
   * {@link RandomProvider} for all random generation.
   *
   * @param randomProvider the {@link RandomProvider} to use
   * @return a new suite with the provided random config
   */
  public OprfCipherSuite withRandom(RandomProvider randomProvider) {
    return new OprfCipherSuite(this, randomProvider);
  }

  /**
   * Identifier string.
   *
   * @return the string
   */
  public String identifier() {
    return identifier;
  }

  // ─── Accessors ──────────────────────────────────────────────────────────────

  /**
   * Context string byte [ ].
   *
   * @return the byte [ ]
   */
  public byte[] contextString() {
    return contextString;
  }

  /**
   * Hash to group dst byte [ ].
   *
   * @return the byte [ ]
   */
  public byte[] hashToGroupDst() {
    return hashToGroupDst;
  }

  /**
   * Hash to scalar dst byte [ ].
   *
   * @return the byte [ ]
   */
  public byte[] hashToScalarDst() {
    return hashToScalarDst;
  }

  /**
   * Derive key pair dst byte [ ].
   *
   * @return the byte [ ]
   */
  public byte[] deriveKeyPairDst() {
    return deriveKeyPairDst;
  }

  /**
   * Group spec group spec.
   *
   * @return the group spec
   */
  public GroupSpec groupSpec() {
    return groupSpec;
  }

  /**
   * Hash algorithm string.
   *
   * @return the string
   */
  public String hashAlgorithm() {
    return hashAlgorithm;
  }

  /**
   * Hash output length int.
   *
   * @return the int
   */
  public int hashOutputLength() {
    return hashOutputLength;
  }

  /**
   * Random config random provider.
   *
   * @return the random provider
   */
  public RandomProvider randomConfig() {
    return randomProvider;
  }

  /**
   * Element size int.
   *
   * @return the int
   */
  public int elementSize() {
    return groupSpec.elementSize();
  }

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
      k = new BigInteger(n.bitLength(), randomProvider.random());
    } while (k.compareTo(BigInteger.ONE) < 0 || k.compareTo(n) >= 0);
    return k;
  }

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
    byte[] deriveInput = ByteUtils.concat(seed, ByteUtils.I2OSP(info.length, 2), info);

    int counter = 0;
    BigInteger skS = BigInteger.ZERO;
    while (skS.equals(BigInteger.ZERO)) {
      if (counter > 255) {
        throw new RuntimeException("DeriveKeyPair: exceeded counter limit");
      }
      byte[] counterInput = ByteUtils.concat(deriveInput, ByteUtils.I2OSP(counter, 1));
      skS = hashToScalar(counterInput, deriveKeyPairDst);
      counter++;
    }
    return skS;
  }

  /**
   * Rejects an OPRF secret key that cannot function as one.
   * <p>
   * The only genuinely fatal value is a key congruent to zero modulo the group order:
   * {@code BlindEvaluate} then returns the identity for every request, and on ristretto255 the
   * identity is a decodable encoding, so a deployment configured with
   * {@code oprfMasterKeyHex: "00"} would serve traffic normally while having no effective key
   * at all.
   * <p>
   * Deliberately does <em>not</em> reject {@code k >= n}. Scalar multiplication reduces modulo
   * the order anyway, so such a key already works and is simply a spelling of {@code k mod n} —
   * and the documented way to generate one, {@code openssl rand -hex 32}, produces a value above
   * ristretto255's order roughly 94% of the time. Refusing them would break existing deployments
   * whose stored OPRF outputs can only be reproduced by that exact key. Use
   * {@link #normalizeSecretKey(BigInteger)} at configuration time instead, which folds the key
   * into range without changing a single output.
   *
   * @param key the secret scalar
   * @throws IllegalArgumentException if the key is null, negative, or congruent to 0 mod n
   */
  public void validateSecretKey(final BigInteger key) {
    if (key == null) {
      throw new IllegalArgumentException("OPRF secret key is required");
    }
    if (key.signum() < 0) {
      throw new IllegalArgumentException("OPRF secret key must not be negative");
    }
    if (key.mod(groupSpec.groupOrder()).signum() == 0) {
      throw new IllegalArgumentException(
          "OPRF secret key is congruent to zero modulo the group order for " + identifier
              + "; every evaluation would return the identity element, leaving the deployment "
              + "with no effective key");
    }
  }

  /**
   * Folds a configured secret key into the canonical range {@code [1, n-1]}.
   * <p>
   * Behaviour-preserving by construction — {@code k} and {@code k mod n} produce byte-identical
   * output, because scalar multiplication reduces first. Normalizing at configuration time makes
   * that equivalence explicit rather than latent, so two configs differing by a multiple of the
   * order no longer look like distinct keys that a rotation could appear to move between while
   * changing nothing.
   *
   * @param key the configured secret scalar
   * @return the equivalent key in {@code [1, n-1]}
   * @throws IllegalArgumentException if the key is null, negative, or congruent to 0 mod n
   */
  public BigInteger normalizeSecretKey(final BigInteger key) {
    validateSecretKey(key);
    BigInteger n = groupSpec.groupOrder();
    if (key.compareTo(n) >= 0) {
      // Not an error — the key works and reducing it changes nothing — but it does mean the
      // operator's key-generation recipe does not match their curve. `openssl rand -hex 32`,
      // which the configuration docs recommend, exceeds ristretto255's order about 94% of the
      // time, so the effective key has roughly four fewer bits of entropy than intended. This
      // warning is the only channel by which they would find that out.
      log.warn("Configured OPRF secret key is >= the group order for {} and has been reduced "
              + "modulo it. This does not change any output, but it means the key was generated "
              + "for a wider range than this suite uses — consider generating keys in [1, n-1].",
          identifier);
    }
    return key.mod(n);
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
    // A blind congruent to 0 mod n inverts to 0, and 0 * anything is the identity, which
    // collapses the output to H(len||input||len||identity||"Finalize") — the same
    // key-independent value an identity evaluated element would produce, reached from the
    // caller's side instead of the server's. randomScalar() samples from [1, n-1] so no
    // in-tree path can hit this, but finalize() is public API and a caller supplying its own
    // blind must not be able to silently disable the OPRF.
    if (blind.mod(n).signum() == 0) {
      throw new IllegalArgumentException("Blind must be a non-zero scalar mod the group order");
    }
    BigInteger inverseBlind = blind.modPow(n.subtract(BigInteger.TWO), n);
    // Before using Fermat's inversion, the above was this:
    // BigInteger inverseBlind = blind.modInverse(groupSpec.groupOrder());

    byte[] unblindedElement = groupSpec.scalarMultiply(inverseBlind, evaluatedElement);

    byte[] finalizeLabel = "Finalize".getBytes(StandardCharsets.UTF_8);
    byte[] hashInput = ByteUtils.concat(
        ByteUtils.I2OSP(input.length, 2),
        input,
        ByteUtils.I2OSP(unblindedElement.length, 2),
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

  /**
   * The type Builder.
   */
  public static class Builder {

    private CurveHashSuite curveHashSuite = CurveHashSuite.P256_SHA256;
    private RandomProvider random = new RandomProvider();

    /**
     * With suite builder.
     *
     * @param curveHashSuite the curve hash suite
     * @return the builder
     */
    public Builder withSuite(CurveHashSuite curveHashSuite) {
      this.curveHashSuite = curveHashSuite;
      return this;
    }

    /**
     * With suite builder.
     *
     * @param name the name
     * @return the builder
     */
    public Builder withSuite(String name) {
      return withSuite(CurveHashSuite.valueOf(name.toUpperCase()));
    }

    /**
     * With random builder.
     *
     * @param random the random
     * @return the builder
     */
    public Builder withRandom(SecureRandom random) {
      this.random = new RandomProvider(random);
      return this;
    }

    /**
     * With random provider builder.
     *
     * @param random the random
     * @return the builder
     */
    public Builder withRandomProvider(RandomProvider random) {
      this.random = random;
      return this;
    }

    /**
     * Build oprf cipher suite.
     *
     * @return the oprf cipher suite
     */
    public OprfCipherSuite build() {
      return switch (curveHashSuite) {
        case P256_SHA256 -> new OprfCipherSuite(
            "P256-SHA256",
            "P256-SHA256",
            WeierstrassGroupSpecImpl.P256_SHA256,
            "SHA-256",
            32,
            random
        );
        case P384_SHA384 -> new OprfCipherSuite(
            "P384-SHA384",
            "P384-SHA384",
            WeierstrassGroupSpecImpl.P384_SHA384,
            "SHA-384",
            48,
            random
        );
        case P521_SHA512 -> new OprfCipherSuite(
            "P521-SHA512",
            "P521-SHA512",
            WeierstrassGroupSpecImpl.P521_SHA512,
            "SHA-512",
            64,
            random
        );
        case RISTRETTO255_SHA512 -> new OprfCipherSuite(
            "ristretto255-SHA512",
            "ristretto255-SHA512",
            Ristretto255GroupSpec.INSTANCE,
            "SHA-512",
            64,
            random
        );
      };
    }

  }
}
