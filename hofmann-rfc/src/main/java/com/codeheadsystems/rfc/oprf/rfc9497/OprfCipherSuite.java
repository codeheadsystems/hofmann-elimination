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
import java.util.Arrays;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * Central cipher suite abstraction for RFC 9497 OPRF.
 * <p>
 * Supports:
 * <ul>
 *   <li>ristretto255-SHA512 (RFC 9497 §4.1)</li>
 *   <li>P256-SHA256 (RFC 9497 §4.3)</li>
 *   <li>P384-SHA384 (RFC 9497 §4.4)</li>
 *   <li>P521-SHA512 (RFC 9497 §4.5)</li>
 * </ul>
 */
public class OprfCipherSuite {

  private static final Logger log = LoggerFactory.getLogger(OprfCipherSuite.class);

  private final String identifier;
  private final OprfMode mode;
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
    this.mode = source.mode;
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
                          OprfMode mode,
                          GroupSpec groupSpec,
                          String hashAlgorithm,
                          int hashOutputLength,
                          RandomProvider randomProvider) {
    this.identifier = identifier;
    this.mode = mode;
    this.contextString = buildContextString(mode, contextSuffix);
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

  private static byte[] buildContextString(OprfMode mode, String suffix) {
    // RFC 9497 §3.1: "OPRFV1-" || I2OSP(mode, 1) || "-" || identifier
    return ByteUtils.concat(
        "OPRFV1-".getBytes(StandardCharsets.UTF_8),
        new byte[]{mode.value()},
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
   * {@link SecureRandom} for all scalar and random byte generation.
   *
   * <p><strong>Stays public, but not for the reason first given here.</strong> A security review
   * grouped this with the deterministic test-vector APIs that are now package-private. I declined,
   * writing that "all three framework integrations call it". They do not: {@code HofmannBundle},
   * {@code HofmannAutoConfiguration} and {@code VerifiableKeyConfig} all call
   * {@link Builder#withRandom(SecureRandom)}, the builder method, and a repo-wide search finds no
   * production caller of this instance method at all. A second reviewer checked and the claim was
   * specific enough to be wrong.
   *
   * <p>The decision survives on better evidence. {@code Builder.withRandom} is unambiguously
   * production API and load-bearing — it is how an operator installs an HSM-backed or otherwise
   * policy-constrained source instead of the platform default — and the same reviewer replayed an
   * entire OPAQUE exchange by handing a stub {@link SecureRandom} to that builder. Restricting
   * this copy-with variant would close nothing while removing a capability. It is kept for
   * symmetry with the builder, with no current production caller.
   *
   * <p>The residual is inherent to accepting a {@link SecureRandom} at all — nothing can
   * distinguish a hardware source from a fixed-output stub — and it is the caller's to get right.
   * That is a different situation from a method whose entire purpose is to fix a nonce.
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
   * The RFC 9497 protocol mode this suite is configured for.
   *
   * @return the mode
   */
  public OprfMode mode() {
    return mode;
  }

  /**
   * Fails unless this suite is configured for one of the given modes.
   * <p>
   * Called from the constructor of every mode-specific manager. Without it, handing a base-mode
   * suite to a VOPRF manager is silent: every operation still computes, it just computes a
   * different function under a different set of domain-separation tags, and the mistake surfaces
   * as an interop failure or an unverifiable stored hash rather than an error.
   *
   * @param allowed the modes this caller supports
   * @throws IllegalArgumentException if this suite's mode is not among them
   */
  public void assertMode(final OprfMode... allowed) {
    for (OprfMode candidate : allowed) {
      if (mode == candidate) {
        return;
      }
    }
    throw new IllegalArgumentException(
        "Cipher suite is configured for " + mode + " but this operation requires one of "
            + Arrays.toString(allowed)
            + "; the mode byte changes every domain-separation tag, so the mismatch would "
            + "silently compute a different function");
  }

  /**
   * Returns a copy of the context string.
   *
   * <p>These four accessors clone. The suites are process-wide statics shared across every
   * request thread, so handing out the live array let any caller — or any caller's bug — mutate
   * the domain separation tag that every other thread is about to hash with. The result would be
   * a silent, global change in derived outputs rather than an exception, and on the DeriveKeyPair
   * tag it would change derived keys. Nothing in tree mutates them; the cost of the copy is a
   * few dozen bytes on paths that already do curve arithmetic.
   *
   * @return a copy of the context string
   */
  public byte[] contextString() {
    return contextString.clone();
  }

  /**
   * Returns a copy of the HashToGroup domain separation tag.
   *
   * @return a copy of the HashToGroup DST
   */
  public byte[] hashToGroupDst() {
    return hashToGroupDst.clone();
  }

  /**
   * Returns a copy of the HashToScalar domain separation tag.
   *
   * @return a copy of the HashToScalar DST
   */
  public byte[] hashToScalarDst() {
    return hashToScalarDst.clone();
  }

  /**
   * Returns a copy of the DeriveKeyPair domain separation tag.
   *
   * @return a copy of the DeriveKeyPair DST
   */
  public byte[] deriveKeyPairDst() {
    return deriveKeyPairDst.clone();
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
   * Serialized scalar size in bytes (Ns). A proof is exactly {@code 2 * Ns} bytes.
   *
   * @return the int
   */
  public int scalarSize() {
    return groupSpec.scalarSize();
  }

  /**
   * Derives the public key {@code pkS = skS * G} committed to by a server key.
   * <p>
   * Validating the secret key first is what guarantees the result is not the identity element.
   * That matters beyond hygiene: {@code pkS} becomes {@code B} in the DLEQ challenge transcript,
   * where the client has to deserialize it, and both group implementations reject the identity on
   * deserialize. Without the guard a zero key would yield an encoding that fails confusingly
   * several layers downstream instead of at the point of the mistake.
   *
   * @param skS the server secret key
   * @return the serialized public key
   * @throws IllegalArgumentException if the key is null, negative, or congruent to 0 mod n
   */
  public byte[] derivePublicKey(final BigInteger skS) {
    validateSecretKey(skS);
    return groupSpec.scalarMultiplyGenerator(skS);
  }

  /**
   * Multiplicative inverse of a scalar modulo the group order.
   * <p>
   * Fermat inversion: {@code k^(n-2) mod n == k^-1 mod n} because {@code n} is prime. {@code modPow}
   * with a fixed-length exponent runs in time proportional to the exponent length, which is
   * significantly more constant-time than the Extended Euclidean Algorithm behind
   * {@link BigInteger#modInverse} — that one's running time tracks the operands themselves. Every
   * scalar inverted on this path is secret: the client's blind, and the POPRF tweaked key
   * {@code t = skS + m}.
   *
   * @param k the scalar to invert
   * @return the inverse modulo the group order
   * @throws IllegalArgumentException if {@code k} is congruent to zero modulo the group order
   */
  public BigInteger scalarInverse(final BigInteger k) {
    BigInteger n = groupSpec.groupOrder();
    if (k.mod(n).signum() == 0) {
      throw new IllegalArgumentException("Cannot invert a scalar congruent to zero mod the group order");
    }
    return k.modPow(n.subtract(BigInteger.TWO), n);
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
   * <p>
   * <strong>This method performs no proof verification.</strong> In {@link OprfMode#VOPRF} and
   * {@link OprfMode#POPRF} the caller MUST verify the server's DLEQ proof before calling it —
   * unblinding an unverified element yields an output indistinguishable from a correct one, which
   * is precisely the guarantee the verifiable modes exist to provide. Callers in those modes
   * should go through the mode-specific managers rather than calling this directly.
   *
   * @param input            original client input bytes
   * @param blind            the blinding scalar used by the client
   * @param evaluatedElement the server's response as a serialized group element
   * @return Nh-byte OPRF output
   */
  public byte[] finalize(byte[] input, BigInteger blind, byte[] evaluatedElement) {
    byte[] unblindedElement = unblind(blind, evaluatedElement);

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
   * RFC 9497 §3.3.3 POPRF Finalize: unblind and produce the OPRF output over a public input.
   * <p>
   * <strong>Performs no proof verification</strong> — see {@link #finalize} for why that matters
   * in this mode.
   * <p>
   * Deliberately a separate method rather than an {@code info} parameter on {@link #finalize}. The
   * two transcripts are genuinely different — POPRF emits {@code I2OSP(len(info), 2)} even when
   * {@code info} is empty, which the base and verifiable modes omit entirely — so an API where
   * {@code null} and {@code byte[0]} mean different things would be one "cleanup" away from a
   * silent output change. Base-mode {@link #finalize} is what every stored OPAQUE credential and
   * every persisted OPRF hash in every downstream port depends on; it is left exactly as it was.
   *
   * @param input            original client input bytes
   * @param info             the public input, shared by client and server
   * @param blind            the blinding scalar used by the client
   * @param evaluatedElement the server's response as a serialized group element
   * @return Nh-byte POPRF output
   */
  public byte[] finalizeWithInfo(byte[] input, byte[] info, BigInteger blind, byte[] evaluatedElement) {
    byte[] unblindedElement = unblind(blind, evaluatedElement);

    byte[] finalizeLabel = "Finalize".getBytes(StandardCharsets.UTF_8);
    byte[] hashInput = ByteUtils.concat(
        ByteUtils.I2OSP(input.length, 2),
        input,
        ByteUtils.I2OSP(info.length, 2),
        info,
        ByteUtils.I2OSP(unblindedElement.length, 2),
        unblindedElement,
        finalizeLabel
    );

    return hash(hashInput);
  }

  /**
   * Removes the client's blind from an evaluated element: {@code N = blind^-1 * evaluatedElement}.
   * <p>
   * A blind congruent to 0 mod n inverts to 0, and 0 * anything is the identity, which collapses
   * the output to a key-independent {@code H(len||input||len||identity||"Finalize")} — the same
   * value an identity evaluated element would produce, reached from the caller's side instead of
   * the server's. {@link #randomScalar()} samples from [1, n-1] so no in-tree path can hit this,
   * but the finalize methods are public API and a caller supplying its own blind must not be able
   * to silently disable the OPRF.
   * <p>
   * The result {@code N} cannot itself be the identity: that would need the inverse blind to be
   * zero (foreclosed above) or {@code evaluatedElement} to be the identity, which both
   * {@link GroupSpec} implementations reject when they deserialize it.
   *
   * @param blind            the blinding scalar used by the client
   * @param evaluatedElement the server's response as a serialized group element
   * @return the serialized unblinded element
   */
  byte[] unblind(BigInteger blind, byte[] evaluatedElement) {
    if (blind.mod(groupSpec.groupOrder()).signum() == 0) {
      throw new IllegalArgumentException("Blind must be a non-zero scalar mod the group order");
    }
    return groupSpec.scalarMultiply(scalarInverse(blind), evaluatedElement);
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
    private OprfMode mode = OprfMode.OPRF;
    private RandomProvider random = new RandomProvider();

    /**
     * Sets the RFC 9497 protocol mode. Defaults to {@link OprfMode#OPRF} (base mode), which is
     * what OPAQUE and every existing caller in this repository use.
     *
     * @param mode the mode
     * @return the builder
     */
    public Builder withMode(OprfMode mode) {
      this.mode = mode;
      return this;
    }

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
            mode,
            WeierstrassGroupSpecImpl.P256_SHA256,
            "SHA-256",
            32,
            random
        );
        case P384_SHA384 -> new OprfCipherSuite(
            "P384-SHA384",
            "P384-SHA384",
            mode,
            WeierstrassGroupSpecImpl.P384_SHA384,
            "SHA-384",
            48,
            random
        );
        case P521_SHA512 -> new OprfCipherSuite(
            "P521-SHA512",
            "P521-SHA512",
            mode,
            WeierstrassGroupSpecImpl.P521_SHA512,
            "SHA-512",
            64,
            random
        );
        case RISTRETTO255_SHA512 -> new OprfCipherSuite(
            "ristretto255-SHA512",
            "ristretto255-SHA512",
            mode,
            Ristretto255GroupSpec.INSTANCE,
            "SHA-512",
            64,
            random
        );
      };
    }

  }
}
