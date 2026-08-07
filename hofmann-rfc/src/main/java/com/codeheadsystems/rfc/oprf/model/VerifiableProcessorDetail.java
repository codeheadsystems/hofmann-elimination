package com.codeheadsystems.rfc.oprf.model;

import com.codeheadsystems.rfc.oprf.rfc9497.OprfCipherSuite;
import com.codeheadsystems.rfc.oprf.rfc9497.OprfMode;
import java.math.BigInteger;
import java.util.Arrays;

/**
 * Server key material for the verifiable modes: the secret scalar, the public key it commits to,
 * and the mode it was derived under.
 * <p>
 * The public key is stored rather than derived per request because it is a fixed-base scalar
 * multiplication on the long-term key and never changes for a given key. Note this caching is
 * correct for VOPRF only — the POPRF server's proof is made against a <em>tweaked</em> key
 * {@code (skS + m) * G} that varies with the public input, so it cannot be precomputed.
 * <p>
 * Carrying {@link OprfMode} is what enforces the rule that one secret must not serve two modes.
 * Cross-mode <em>confusion</em> is already impossible — the context string separates every domain
 * separation tag, so a VOPRF proof cannot be replayed as a POPRF one — but two other things do not
 * separate. RFC 9497 §7.2.3's static Diffie-Hellman security budget degrades with the number of
 * evaluations under a key, and sharing a key pools that count. More seriously, POPRF hands clients
 * an inversion oracle while OPRF and VOPRF hand them a multiplication oracle; §7.2.2 rests on
 * One-More Gap SDHI and §7.2.1 on One-More Gap CDH, and no analysis covers an adversary holding
 * both under a single key. Since {@code DeriveKeyPair} is already mode-separated, deriving a
 * distinct key per mode costs nothing.
 *
 * @param masterKey           the server secret scalar
 * @param publicKey           the serialized public key {@code masterKey * G}
 * @param processorIdentifier identifies which key produced a result, for rotation
 * @param mode                the mode this key was derived for
 */
public record VerifiableProcessorDetail(BigInteger masterKey,
                                        byte[] publicKey,
                                        String processorIdentifier,
                                        OprfMode mode) {

  /**
   * Rejects a detail that is structurally unusable.
   */
  public VerifiableProcessorDetail {
    if (masterKey == null) {
      throw new IllegalArgumentException("Server secret key is required");
    }
    if (publicKey == null || publicKey.length == 0) {
      throw new IllegalArgumentException("Server public key is required");
    }
    if (processorIdentifier == null || processorIdentifier.isBlank()) {
      throw new IllegalArgumentException("Processor identifier is required");
    }
    if (mode == null) {
      throw new IllegalArgumentException("Mode is required");
    }
  }

  /**
   * Derives the detail from a secret key, computing the matching public key.
   * <p>
   * The preferred construction path, because it makes a mismatched key pair impossible. A detail
   * assembled by hand with a public key that does not correspond to its secret produces proofs
   * that are internally consistent and yet verify for no client, forever — a failure that looks
   * like a client bug from the server's side and like a server compromise from the client's.
   *
   * @param suite               the cipher suite, whose mode is recorded on the detail
   * @param masterKey           the server secret scalar
   * @param processorIdentifier identifies which key produced a result
   * @return the detail
   */
  public static VerifiableProcessorDetail derive(final OprfCipherSuite suite,
                                                 final BigInteger masterKey,
                                                 final String processorIdentifier) {
    suite.assertMode(OprfMode.VOPRF, OprfMode.POPRF);
    return new VerifiableProcessorDetail(
        suite.normalizeSecretKey(masterKey),
        suite.derivePublicKey(masterKey),
        processorIdentifier,
        suite.mode());
  }

  /**
   * Derives the detail from a seed, which is the path that makes the one-key-per-mode rule
   * self-enforcing.
   * <p>
   * {@link #derive} records the mode but cannot stop a caller handing the same scalar to two
   * modes — it prevents mislabelling, not sharing. Going through {@code DeriveKeyPair} does
   * prevent sharing, because {@code deriveKeyPairDst} embeds the mode-bearing context string, so
   * one seed provably cannot yield the same scalar in two modes. RFC 9497 Appendix A demonstrates
   * it: seed {@code a3a3...} with {@code KeyInfo = "test key"} gives ristretto255
   * {@code skSm = 5ebc...} in base mode and {@code e6f7...} in VOPRF.
   *
   * @param suite               the cipher suite, whose mode selects the derivation
   * @param seed                the key-derivation seed, 32 or more random bytes
   * @param keyInfo             application-specific derivation info
   * @param processorIdentifier identifies which key produced a result
   * @return the detail
   */
  public static VerifiableProcessorDetail deriveFromSeed(final OprfCipherSuite suite,
                                                         final byte[] seed,
                                                         final byte[] keyInfo,
                                                         final String processorIdentifier) {
    suite.assertMode(OprfMode.VOPRF, OprfMode.POPRF);
    return derive(suite, suite.deriveKeyPair(seed, keyInfo), processorIdentifier);
  }

  /**
   * Checks that the stored public key really is {@code masterKey * G} under the given suite, and
   * that the suite's mode matches the one recorded here.
   * <p>
   * Intended for startup validation of hand-assembled or externally-supplied key material. Not
   * called per request: it costs a fixed-base scalar multiplication, and the failure it detects is
   * a static configuration error rather than something that can arise mid-flight.
   *
   * @param suite the cipher suite to check against
   * @throws IllegalArgumentException if the pair is inconsistent or the mode does not match
   */
  public void validateConsistency(final OprfCipherSuite suite) {
    if (suite.mode() != mode) {
      throw new IllegalArgumentException(
          "Key was derived for " + mode + " but the suite is configured for " + suite.mode()
              + "; one secret must not serve two modes");
    }
    if (!Arrays.equals(publicKey, suite.derivePublicKey(masterKey))) {
      throw new IllegalArgumentException(
          "Configured public key does not correspond to the configured secret key for processor '"
              + processorIdentifier + "'; every proof would fail to verify");
    }
  }
}
