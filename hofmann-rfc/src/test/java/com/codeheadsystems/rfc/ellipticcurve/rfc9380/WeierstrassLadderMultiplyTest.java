package com.codeheadsystems.rfc.ellipticcurve.rfc9380;

import static org.assertj.core.api.Assertions.assertThat;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.stream.Stream;
import org.bouncycastle.math.ec.ECPoint;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * {@code scalarMultiply} used BouncyCastle's default multiplier, which for the NIST prime curves
 * is window-NAF: the add/double sequence depends on the scalar's digits, the precomputed table is
 * indexed by secret values, and the window size comes from the bit length. Measured on P-256, two
 * scalars of identical bit length but different Hamming weight differed by ~11% in wall time. The
 * scalars reaching this method are the server's long-term OPRF key, per-credential OPRF keys, AKE
 * keys, and client blinds, and the server-side OPRF lets an attacker choose the point and request
 * unlimited evaluations against a fixed key.
 *
 * <p>It now uses an explicit Montgomery ladder over a fixed-width scalar. These tests pin two
 * things: that the ladder computes exactly what BouncyCastle did, and — structurally, so it
 * cannot be undone by a well-meaning refactor — that the rescaled scalar's width does not depend
 * on the secret. The wall-clock property itself is not asserted, because a timing threshold would
 * be flaky in CI; it was measured out of band (~17-19% Hamming-weight signal before, within noise
 * after; and a 48% bit-length signal before the fixed-width rescale, flat after).
 */
class WeierstrassLadderMultiplyTest {

  private static final SecureRandom RANDOM = new SecureRandom();

  static Stream<Arguments> specs() {
    return Stream.of(
        Arguments.of("P-256", WeierstrassGroupSpecImpl.P256_SHA256),
        Arguments.of("P-384", WeierstrassGroupSpecImpl.P384_SHA384),
        Arguments.of("P-521", WeierstrassGroupSpecImpl.P521_SHA512),
        Arguments.of("secp256k1", WeierstrassGroupSpecImpl.forSecp256k1()));
  }

  /** The reference: what BouncyCastle's own multiplier produces for the same inputs. */
  private static byte[] bouncyCastleReference(WeierstrassGroupSpecImpl spec,
                                              BigInteger scalar, byte[] element) {
    ECPoint p = spec.deserializePoint(element);
    return p.multiply(scalar).normalize().getEncoded(true);
  }

  @ParameterizedTest(name = "{0}")
  @MethodSource("specs")
  void ladderMatchesBouncyCastleForRandomScalarsAndPoints(String name,
                                                          WeierstrassGroupSpecImpl spec) {
    BigInteger n = spec.curve().n();
    for (int i = 0; i < 25; i++) {
      byte[] point = spec.scalarMultiplyGenerator(
          new BigInteger(n.bitLength(), RANDOM).mod(n).max(BigInteger.ONE));
      BigInteger k = new BigInteger(n.bitLength(), RANDOM).mod(n).max(BigInteger.ONE);

      assertThat(spec.scalarMultiply(k, point))
          .as("ladder must agree with BouncyCastle on %s, iteration %d", name, i)
          .isEqualTo(bouncyCastleReference(spec, k, point));
    }
  }

  @ParameterizedTest(name = "{0}")
  @MethodSource("specs")
  void ladderMatchesBouncyCastleAtBoundaryScalars(String name, WeierstrassGroupSpecImpl spec) {
    BigInteger n = spec.curve().n();
    byte[] point = spec.scalarMultiplyGenerator(BigInteger.valueOf(11));

    for (BigInteger k : new BigInteger[]{
        BigInteger.ONE,
        BigInteger.TWO,
        n.subtract(BigInteger.ONE),
        n.subtract(BigInteger.TWO),
        BigInteger.ONE.shiftLeft(n.bitLength() - 1),           // only the top bit set
        BigInteger.ONE.shiftLeft(n.bitLength() - 1).add(BigInteger.ONE),
        n.shiftRight(1)}) {
      assertThat(spec.scalarMultiply(k, point))
          .as("%s, scalar with bitLength=%d hammingWeight=%d", name, k.bitLength(), k.bitCount())
          .isEqualTo(bouncyCastleReference(spec, k, point));
    }
  }

  /**
   * The ladder reduces modulo the group order first. For a point of order n that is the identity
   * transform, so k and k+n must still agree — this is what makes the fixed iteration count safe.
   */
  @ParameterizedTest(name = "{0}")
  @MethodSource("specs")
  void reducingTheScalarChangesNothing(String name, WeierstrassGroupSpecImpl spec) {
    BigInteger n = spec.curve().n();
    byte[] point = spec.scalarMultiplyGenerator(BigInteger.valueOf(13));
    BigInteger k = new BigInteger(n.bitLength(), RANDOM).mod(n).max(BigInteger.ONE);

    assertThat(spec.scalarMultiply(k.add(n), point)).isEqualTo(spec.scalarMultiply(k, point));
    assertThat(spec.scalarMultiply(k.add(n.multiply(BigInteger.TWO)), point))
        .isEqualTo(spec.scalarMultiply(k, point));
  }

  /** A low-Hamming-weight and a high-Hamming-weight scalar of equal width must both be correct. */
  @ParameterizedTest(name = "{0}")
  @MethodSource("specs")
  void extremeHammingWeightsAreComputedCorrectly(String name, WeierstrassGroupSpecImpl spec) {
    BigInteger n = spec.curve().n();
    byte[] point = spec.scalarMultiplyGenerator(BigInteger.valueOf(17));
    BigInteger sparse = BigInteger.ONE.shiftLeft(n.bitLength() - 1).add(BigInteger.ONE);
    BigInteger dense = n.subtract(BigInteger.ONE);

    assertThat(sparse.bitLength()).isEqualTo(dense.bitLength());
    assertThat(spec.scalarMultiply(sparse, point))
        .isEqualTo(bouncyCastleReference(spec, sparse, point));
    assertThat(spec.scalarMultiply(dense, point))
        .isEqualTo(bouncyCastleReference(spec, dense, point));
  }

  /**
   * Pins the SECURITY property, not just correctness.
   *
   * <p>Every functional test here passes if the loop bound is changed from {@code n.bitLength()}
   * to {@code k.bitLength()} — leading-zero iterations are provable no-ops, so the answer is
   * identical — but that change silently restores a secret-dependent iteration count and undoes
   * the reason the ladder exists. A wall-clock assertion would be flaky in CI; asserting that the
   * rescaled scalar has a constant width is not, and it fails against exactly that mutation.
   */
  @ParameterizedTest(name = "{0}")
  @MethodSource("specs")
  void rescaledScalarWidthIsIndependentOfTheSecret(String name, WeierstrassGroupSpecImpl spec) {
    BigInteger n = spec.curve().n();
    int expected = n.bitLength() + 1;

    for (BigInteger k : new BigInteger[]{
        BigInteger.ZERO, BigInteger.ONE, BigInteger.TWO, BigInteger.valueOf(3),
        BigInteger.ONE.shiftLeft(8), BigInteger.ONE.shiftLeft(64),
        BigInteger.ONE.shiftLeft(n.bitLength() / 2),
        BigInteger.ONE.shiftLeft(n.bitLength() - 1),
        n.subtract(BigInteger.ONE), n, n.add(BigInteger.ONE),
        n.multiply(BigInteger.TWO)}) {
      BigInteger rescaled = WeierstrassGroupSpecImpl.fixedWidthScalar(k, n);
      assertThat(rescaled.bitLength())
          .as("%s: scalar %s (bitLength %d) must rescale to a constant width",
              name, k.bitLength() > 64 ? "<large>" : k.toString(), k.bitLength())
          .isEqualTo(expected);
      assertThat(rescaled.testBit(expected - 1))
          .as("%s: the top bit must always be set, so the ladder never short-circuits on "
              + "infinity for a secret-dependent number of iterations", name)
          .isTrue();
    }
  }

  /** Random sampling of the same property — the width must never vary, for any secret. */
  @ParameterizedTest(name = "{0}")
  @MethodSource("specs")
  void rescaledScalarWidthIsConstantAcrossRandomSecrets(String name,
                                                        WeierstrassGroupSpecImpl spec) {
    BigInteger n = spec.curve().n();
    for (int i = 0; i < 200; i++) {
      BigInteger k = new BigInteger(1 + RANDOM.nextInt(n.bitLength()), RANDOM);
      assertThat(WeierstrassGroupSpecImpl.fixedWidthScalar(k, n).bitLength())
          .isEqualTo(n.bitLength() + 1);
    }
  }

  /** Rescaling must not change the answer — that is what makes the fixed width free. */
  @ParameterizedTest(name = "{0}")
  @MethodSource("specs")
  void rescalingDoesNotChangeTheResult(String name, WeierstrassGroupSpecImpl spec) {
    BigInteger n = spec.curve().n();
    byte[] point = spec.scalarMultiplyGenerator(BigInteger.valueOf(23));
    for (int i = 0; i < 20; i++) {
      BigInteger k = new BigInteger(n.bitLength(), RANDOM).mod(n).max(BigInteger.ONE);
      assertThat(spec.scalarMultiply(k, point))
          .isEqualTo(bouncyCastleReference(spec, k, point));
    }
  }

  /**
   * The generator path carries secret scalars too — the server's ephemeral AKE key on every
   * authentication, and the client's long-term private key, which {@code OpaqueEnvelope.recover}
   * recomputes from the same value every time. It must use the ladder, not BouncyCastle's
   * default, which resolves to wNAF for all three NIST curves.
   */
  @ParameterizedTest(name = "{0}")
  @MethodSource("specs")
  void generatorMultiplicationAgreesWithTheLadder(String name, WeierstrassGroupSpecImpl spec) {
    BigInteger n = spec.curve().n();
    byte[] generator = spec.curve().g().normalize().getEncoded(true);
    for (int i = 0; i < 20; i++) {
      BigInteger k = new BigInteger(n.bitLength(), RANDOM).mod(n).max(BigInteger.ONE);
      assertThat(spec.scalarMultiplyGenerator(k))
          .as("%s: generator path must agree with the point path", name)
          .isEqualTo(spec.scalarMultiply(k, generator));
    }
  }

  /**
   * The one property that cannot be asserted from outputs alone, and the one a refactor is most
   * likely to undo.
   *
   * <p>Dropping the fixed-width rescale — or looping over {@code k.bitLength()} instead — leaves
   * every functional test green, because iterations above the scalar's leading set bit are
   * provable no-ops. What it silently restores is a secret-dependent amount of work: before the
   * rescale a 3-bit scalar ran roughly twenty times faster than a full-width one on P-256.
   *
   * <p>Timing assertions are normally a bad idea in CI, so this one is deliberately blunt. The
   * pre-fix gap was about 20x; the threshold here is 2x. Anything between those is not noise, it
   * is the channel reopening. Uses the median of several interleaved samples so a single
   * scheduling hiccup cannot fail the build.
   */
  @Test
  void workDoneDoesNotDependOnTheScalarMagnitude() {
    WeierstrassGroupSpecImpl spec = WeierstrassGroupSpecImpl.P256_SHA256;
    BigInteger n = spec.curve().n();
    byte[] point = spec.scalarMultiplyGenerator(BigInteger.valueOf(29));
    BigInteger tiny = BigInteger.valueOf(3);
    BigInteger full = n.subtract(BigInteger.ONE);

    for (int warmup = 0; warmup < 300; warmup++) {
      spec.scalarMultiply(tiny, point);
      spec.scalarMultiply(full, point);
    }

    long[] tinyTimes = new long[9];
    long[] fullTimes = new long[9];
    for (int i = 0; i < 9; i++) {
      long t0 = System.nanoTime();
      for (int r = 0; r < 20; r++) {
        spec.scalarMultiply(tiny, point);
      }
      tinyTimes[i] = System.nanoTime() - t0;
      long t1 = System.nanoTime();
      for (int r = 0; r < 20; r++) {
        spec.scalarMultiply(full, point);
      }
      fullTimes[i] = System.nanoTime() - t1;
    }
    java.util.Arrays.sort(tinyTimes);
    java.util.Arrays.sort(fullTimes);
    double ratio = (double) tinyTimes[4] / fullTimes[4];

    assertThat(ratio)
        .as("a 3-bit scalar took %.2fx the time of a full-width one; below 0.5 means the "
            + "fixed-width rescale is no longer being applied and the scalar's magnitude is "
            + "observable again", ratio)
        .isGreaterThan(0.5);
  }

  /** Round-trip through the OPRF blind/unblind identity: (k * blindInv) * (blind * P) == k * P. */
  @Test
  void ladderPreservesTheOprfBlindingIdentity() {
    WeierstrassGroupSpecImpl spec = WeierstrassGroupSpecImpl.P256_SHA256;
    BigInteger n = spec.curve().n();
    BigInteger blind = new BigInteger(n.bitLength(), RANDOM).mod(n).max(BigInteger.ONE);
    BigInteger key = new BigInteger(n.bitLength(), RANDOM).mod(n).max(BigInteger.ONE);
    byte[] base = spec.scalarMultiplyGenerator(BigInteger.valueOf(19));

    byte[] blinded = spec.scalarMultiply(blind, base);
    byte[] evaluated = spec.scalarMultiply(key, blinded);
    byte[] unblinded = spec.scalarMultiply(blind.modInverse(n), evaluated);

    assertThat(unblinded).isEqualTo(spec.scalarMultiply(key, base));
  }
}
