package com.codeheadsystems.rfc.ellipticcurve.rfc9380;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.Test;

/**
 * Tests for {@link Ristretto255GroupSpec}.
 * Includes RFC 9496 test vectors and round-trip properties.
 */
class Ristretto255GroupSpecTest {

  private static final Ristretto255GroupSpec SPEC = Ristretto255GroupSpec.INSTANCE;

  // RFC 9496 §4.4: canonical encoding of the base point (1*G)
  private static final String BASE_POINT_ENCODING =
      "e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76";

  @Test
  void groupOrder() {
    BigInteger L = BigInteger.TWO.pow(252).add(
        new BigInteger("27742317777372353535851937790883648493"));
    assertThat(SPEC.groupOrder()).isEqualTo(L);
  }

  @Test
  void elementSize() {
    assertThat(SPEC.elementSize()).isEqualTo(32);
  }

  @Test
  void generatorEncoding() {
    // 1*G should produce the canonical base point encoding from RFC 9496 §4.4
    byte[] encoded = SPEC.scalarMultiplyGenerator(BigInteger.ONE);
    assertThat(Hex.toHexString(encoded)).isEqualTo(BASE_POINT_ENCODING);
  }

  @Test
  void identityEncoding() {
    // 0*G should produce the all-zeros identity encoding
    byte[] encoded = SPEC.scalarMultiplyGenerator(BigInteger.ZERO);
    assertThat(encoded).isEqualTo(new byte[32]);
  }

  @Test
  void groupOrderTimesGenerator() {
    // L*G should produce the identity
    byte[] encoded = SPEC.scalarMultiplyGenerator(SPEC.groupOrder());
    assertThat(encoded).isEqualTo(new byte[32]);
  }

  /**
   * Producing the identity is allowed; accepting it back as an input is not.
   *
   * <p>The two tests above assert only that the all-zero encoding is <em>producible</em>, which is
   * true and uninteresting — {@code 0·G} and {@code L·G} are the identity by definition. The
   * property that matters is the opposite direction, and it was asserted only in the OPRF layer:
   * at the group-spec layer nothing here checked that decoding the identity is refused.
   *
   * <p>It matters on ristretto255 more than anywhere else. The all-zero string is a
   * <em>legitimate</em> ristretto255 encoding, so every RFC 9496 §4.3.1 canonicity check passes
   * for it; only the protocol-layer check catches it. That is exactly the shape of the P0 this
   * suite regressed on once already.
   */
  @Test
  void decodingTheIdentityIsRefusedEvenThoughProducingItIsNot() {
    byte[] identity = new byte[32];

    assertThatThrownBy(() -> SPEC.scalarMultiply(BigInteger.valueOf(7), identity))
        .isInstanceOfAny(SecurityException.class, IllegalArgumentException.class);
    assertThatThrownBy(() -> SPEC.validateElement(identity))
        .isInstanceOfAny(SecurityException.class, IllegalArgumentException.class);
    assertThatThrownBy(() -> SPEC.add(identity, SPEC.generator()))
        .isInstanceOfAny(SecurityException.class, IllegalArgumentException.class);
  }

  @Test
  void decodeEncodeRoundTrip() {
    // Decode the base point encoding, then re-encode — should get the same bytes
    byte[] basePointBytes = Hex.decode(BASE_POINT_ENCODING);
    BigInteger[] pt = Ristretto255GroupSpec.decodeRistretto255(basePointBytes);
    byte[] reEncoded = Ristretto255GroupSpec.encodeRistretto255(pt);
    assertThat(Hex.toHexString(reEncoded)).isEqualTo(BASE_POINT_ENCODING);
  }

  @Test
  void scalarMultiplyRoundTrip() {
    // k*G decoded and re-encoded should produce the same bytes
    BigInteger k = new BigInteger("12345678901234567890");
    byte[] encoded = SPEC.scalarMultiplyGenerator(k);
    BigInteger[] decoded = Ristretto255GroupSpec.decodeRistretto255(encoded);
    byte[] reEncoded = Ristretto255GroupSpec.encodeRistretto255(decoded);
    assertThat(reEncoded).isEqualTo(encoded);
  }

  @Test
  void scalarMultiply_kTimesG_then_1TimesResult() {
    // k*G via scalarMultiplyGenerator should equal scalarMultiply(k, G_encoded)
    BigInteger k = new BigInteger("98765432109876543210");
    byte[] baseEncoded = SPEC.scalarMultiplyGenerator(BigInteger.ONE);
    byte[] kG_direct = SPEC.scalarMultiplyGenerator(k);
    byte[] kG_viaMultiply = SPEC.scalarMultiply(k, baseEncoded);
    assertThat(kG_viaMultiply).isEqualTo(kG_direct);
  }

  @Test
  void hashToGroupDeterministic() {
    byte[] msg = new byte[]{0x00};
    byte[] dst = "test-dst".getBytes();
    byte[] h1 = SPEC.hashToGroup(msg, dst);
    byte[] h2 = SPEC.hashToGroup(msg, dst);
    assertThat(h1).isEqualTo(h2);
    assertThat(h1).hasSize(32);
    Ristretto255GroupSpec.decodeRistretto255(h1);
  }

  @Test
  void hashToScalarDeterministic() {
    byte[] msg = "hello".getBytes();
    byte[] dst = "test-scalar-dst".getBytes();
    BigInteger s1 = SPEC.hashToScalar(msg, dst);
    BigInteger s2 = SPEC.hashToScalar(msg, dst);
    assertThat(s1).isEqualTo(s2);
    assertThat(s1).isGreaterThanOrEqualTo(BigInteger.ZERO);
    assertThat(s1).isLessThan(SPEC.groupOrder());
  }

  @Test
  void serializeScalar_littleEndian() {
    // Scalar 1 should serialize as 01 00 00 ... 00 (LE)
    byte[] serialized = SPEC.serializeScalar(BigInteger.ONE);
    assertThat(serialized).hasSize(32);
    assertThat(serialized[0]).isEqualTo((byte) 0x01);
    for (int i = 1; i < 32; i++) {
      assertThat(serialized[i]).isEqualTo((byte) 0x00);
    }
  }

  @Test
  void decodeInvalidEncoding_tooShort() {
    assertThatThrownBy(() -> Ristretto255GroupSpec.decodeRistretto255(new byte[31]))
        .isInstanceOf(IllegalArgumentException.class);
  }

  @Test
  void decodeInvalidEncoding_nonCanonical() {
    // A byte array with s >= p should be rejected
    byte[] bad = new byte[32];
    java.util.Arrays.fill(bad, (byte) 0xFF);
    assertThatThrownBy(() -> Ristretto255GroupSpec.decodeRistretto255(bad))
        .isInstanceOf(SecurityException.class);
  }

  @Test
  void decodeInvalidEncoding_negativeS() {
    // s = 1 is canonical (< p) but has its least-significant bit set, i.e. a "negative" field
    // element. RFC 9496 §4.3.1 requires rejecting non-canonical / negative s encodings.
    byte[] negativeS = new byte[32];
    negativeS[0] = 0x01; // little-endian value 1, low bit set
    assertThatThrownBy(() -> Ristretto255GroupSpec.decodeRistretto255(negativeS))
        .isInstanceOf(SecurityException.class)
        .hasMessageContaining("negative");
  }

  // RFC 9496 §4.5: small multiples of the generator
  @Test
  void smallMultiplesOfGenerator() {
    // 2*G
    byte[] twoG = SPEC.scalarMultiplyGenerator(BigInteger.TWO);
    // Should be valid and different from G and identity
    assertThat(twoG).isNotEqualTo(new byte[32]);
    assertThat(Hex.toHexString(twoG)).isNotEqualTo(BASE_POINT_ENCODING);
    // Decode should succeed
    Ristretto255GroupSpec.decodeRistretto255(twoG);
  }

  @Test
  void additionIsCommutative() {
    BigInteger k1 = BigInteger.valueOf(42);
    BigInteger k2 = BigInteger.valueOf(100);
    // k1*G + k2*G should equal (k1+k2)*G
    byte[] k1G = SPEC.scalarMultiplyGenerator(k1);
    byte[] k2G = SPEC.scalarMultiplyGenerator(k2);
    byte[] sum = SPEC.scalarMultiplyGenerator(k1.add(k2));

    BigInteger[] pt1 = Ristretto255GroupSpec.decodeRistretto255(k1G);
    BigInteger[] pt2 = Ristretto255GroupSpec.decodeRistretto255(k2G);
    byte[] added = Ristretto255GroupSpec.encodeRistretto255(
        Ristretto255GroupSpec.addPoints(pt1, pt2));
    assertThat(added).isEqualTo(sum);
  }

  // ─── fixed-width scalar rescaling ──────────────────────────────────────────

  /**
   * The rescaled scalar must be exactly one bit wider than the group order, with the top bit set.
   *
   * <p>That width is what makes the ladder's first iteration move the accumulator off the neutral
   * element regardless of the key. Without it the leading iterations ran on 0/1 operands and were
   * measurably cheaper: a 64-bit scalar completed ~25% faster than a full-length one on this
   * machine, against a flat profile on the Weierstrass curves, which have had the equivalent
   * rescaling since the constant-time work. After the change the same measurement is within 1%.
   *
   * <p>Asserting the width rather than the timing, because a timing assertion in a unit test is a
   * flake generator — but the width is the mechanism the timing depends on, so a regression that
   * removed the rescaling fails here.
   */
  @Test
  void fixedWidthScalar_alwaysProducesOneBitMoreThanTheGroupOrder() {
    int want = SPEC.groupOrder().bitLength() + 1;
    SecureRandom rnd = new SecureRandom();

    for (int bits : new int[]{1, 8, 64, 128, 200, 252, 253}) {
      BigInteger k = new BigInteger(bits, rnd);
      BigInteger scaled = Ristretto255GroupSpec.fixedWidthScalar(k);
      assertThat(scaled.bitLength())
          .as("a %d-bit scalar must rescale to %d bits", bits, want)
          .isEqualTo(want);
      assertThat(scaled.testBit(want - 1))
          .as("the top bit must be set so the first iteration is never a no-op")
          .isTrue();
    }
    // Including the values most likely to be special-cased wrong.
    for (BigInteger k : new BigInteger[]{BigInteger.ZERO, BigInteger.ONE,
        SPEC.groupOrder().subtract(BigInteger.ONE), SPEC.groupOrder(),
        SPEC.groupOrder().add(BigInteger.ONE), BigInteger.ONE.negate()}) {
      assertThat(Ristretto255GroupSpec.fixedWidthScalar(k).bitLength()).isEqualTo(want);
    }
  }

  /**
   * Additive homomorphism over full-width scalars, across varied base points.
   *
   * <p>The stronger of the two correctness guards on the rescaling. {@code (k1+k2)·P} must equal
   * {@code k1·P + k2·P}, and each of those three multiplications runs the rescaling independently
   * with a different scalar — so a wrong {@code (k + L) ≡ k} equivalence would have to be
   * additively consistent across all three to hide here, which it would not be. {@code k1 + k2} is
   * deliberately left unreduced so it frequently exceeds {@code L} and exercises the widening path
   * with an input the old code would have reduced away.
   *
   * <p>It also covers what the small-scalar test cannot: full 252-bit scalars, where checking
   * against repeated addition is not tractable. Base points come from four different routes so the
   * sample is not all generator multiples — the structural argument is that every Edwards25519
   * point has order dividing 8L, hence {@code L·P} is always 8-torsion and the encoding is
   * invariant under it, but a sample that only used one construction would not test that.
   */
  @Test
  void multiplicationIsAdditiveOverFullWidthScalars() {
    SecureRandom rnd = new SecureRandom();
    BigInteger order = SPEC.groupOrder();
    int checked = 0;

    for (int i = 0; i < 40; i++) {
      byte[] point = switch (i % 4) {
        case 0 -> SPEC.generator();
        case 1 -> SPEC.hashToGroup(("hg-" + i).getBytes(StandardCharsets.UTF_8),
            "dst".getBytes(StandardCharsets.UTF_8));
        case 2 -> SPEC.scalarMultiplyGenerator(
            new BigInteger(252, rnd).mod(order).max(BigInteger.ONE));
        default -> SPEC.add(SPEC.generator(),
            SPEC.hashToGroup(("mix-" + i).getBytes(StandardCharsets.UTF_8),
                "dst".getBytes(StandardCharsets.UTF_8)));
      };

      BigInteger k1 = new BigInteger(252, rnd).mod(order).max(BigInteger.ONE);
      BigInteger k2 = new BigInteger(252, rnd).mod(order).max(BigInteger.ONE);

      byte[] combined = SPEC.scalarMultiply(k1.add(k2), point);
      byte[] first = SPEC.scalarMultiply(k1, point);
      byte[] second = SPEC.scalarMultiply(k2, point);
      if (k1.add(k2).mod(order).signum() == 0) {
        continue;                       // add() rejects an identity sum, correctly
      }
      assertThat(SPEC.add(first, second)).isEqualTo(combined);
      checked++;
    }
    assertThat(checked).as("the loop must actually have asserted something").isGreaterThan(30);
  }

  /**
   * Rescaling must not change what the multiplication produces.
   *
   * <p>This is the step the Weierstrass version does not need to justify. There, {@code n·P = O}
   * for a prime-order point and adding {@code n} is arithmetically free. ristretto255's
   * representatives live on Edwards25519 with cofactor 8, so {@code L·P} is generally <em>not</em>
   * the Edwards identity — it is 8-torsion, and the encoding is invariant under adding 8-torsion.
   * That invariance is what makes the rescaling sound, and it is worth an assertion rather than a
   * comment.
   */
  @Test
  void addingTheGroupOrderDoesNotChangeTheEncodedResult() {
    SecureRandom rnd = new SecureRandom();
    BigInteger order = SPEC.groupOrder();

    for (int i = 0; i < 25; i++) {
      BigInteger k = new BigInteger(252, rnd).mod(order).max(BigInteger.ONE);
      byte[] point = SPEC.scalarMultiplyGenerator(
          new BigInteger(252, rnd).mod(order).max(BigInteger.ONE));

      byte[] direct = SPEC.scalarMultiply(k, point);
      // Drive the ladder with the rescaled value the implementation actually uses, rather than
      // relying on scalarMultiply's own reduction to undo the addition.
      BigInteger widened = Ristretto255GroupSpec.fixedWidthScalar(k);
      assertThat(widened.mod(order)).isEqualTo(k.mod(order));
      assertThat(SPEC.scalarMultiply(widened, point)).isEqualTo(direct);
    }
  }
}
