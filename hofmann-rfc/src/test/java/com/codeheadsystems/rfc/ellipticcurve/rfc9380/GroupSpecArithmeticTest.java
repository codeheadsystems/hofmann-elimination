package com.codeheadsystems.rfc.ellipticcurve.rfc9380;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * Covers the group operations added to support the RFC 9497 §2.2 proof arithmetic: element
 * addition, multi-scalar accumulation, scalar deserialization, and the serialized generator.
 *
 * <p>The multi-scalar methods carry the load here. They exist because the proof's accumulator
 * legitimately passes through the identity — the RFC's {@code ComputeComposites} starts there —
 * while every serialized-element entry point in {@link GroupSpec} rejects the identity, so the
 * arithmetic has to stay inside the implementation. That makes "agrees with the naive
 * multiply-then-add" the property worth pinning, plus the cases the naive form cannot express.
 */
class GroupSpecArithmeticTest {

  private static final SecureRandom RANDOM = new SecureRandom();

  static Stream<Arguments> specs() {
    return Stream.of(
        Arguments.of("P-256", WeierstrassGroupSpecImpl.P256_SHA256),
        Arguments.of("P-384", WeierstrassGroupSpecImpl.P384_SHA384),
        Arguments.of("P-521", WeierstrassGroupSpecImpl.P521_SHA512),
        Arguments.of("ristretto255", Ristretto255GroupSpec.INSTANCE));
  }

  private static byte[] point(GroupSpec spec, String label) {
    return spec.hashToGroup(label.getBytes(StandardCharsets.UTF_8),
        "GroupSpecArithmeticTest".getBytes(StandardCharsets.UTF_8));
  }

  private static BigInteger randomScalar(GroupSpec spec) {
    BigInteger n = spec.groupOrder();
    BigInteger k;
    do {
      k = new BigInteger(n.bitLength(), RANDOM);
    } while (k.signum() == 0 || k.compareTo(n) >= 0);
    return k;
  }

  // ─── generator ──────────────────────────────────────────────────────────────

  /**
   * The generator must be the same base point {@code scalarMultiplyGenerator} uses, or the proof
   * verifier's {@code t2 = s*G + c*B} would be computed against a different {@code G} than the
   * prover's {@code t2 = r*G}, and every proof would fail.
   */
  @ParameterizedTest(name = "{0}")
  @MethodSource("specs")
  void generatorMatchesScalarMultiplyGenerator(String name, GroupSpec spec) {
    BigInteger k = randomScalar(spec);
    assertThat(spec.scalarMultiply(k, spec.generator()))
        .isEqualTo(spec.scalarMultiplyGenerator(k));
  }

  @ParameterizedTest(name = "{0}")
  @MethodSource("specs")
  void generatorIsElementSized(String name, GroupSpec spec) {
    assertThat(spec.generator()).hasSize(spec.elementSize());
  }

  // ─── add ────────────────────────────────────────────────────────────────────

  @ParameterizedTest(name = "{0}")
  @MethodSource("specs")
  void addIsCommutative(String name, GroupSpec spec) {
    byte[] a = point(spec, "a");
    byte[] b = point(spec, "b");
    assertThat(spec.add(a, b)).isEqualTo(spec.add(b, a));
  }

  /**
   * {@code 2P} via addition must equal {@code 2P} via scalar multiplication. This is the only
   * cross-check available between the new addition path and the long-standing multiply path.
   */
  @ParameterizedTest(name = "{0}")
  @MethodSource("specs")
  void addAgreesWithScalarMultiply(String name, GroupSpec spec) {
    byte[] p = point(spec, "doubling");
    assertThat(spec.add(p, p)).isEqualTo(spec.scalarMultiply(BigInteger.TWO, p));
  }

  /**
   * {@code P + (-P)} is the identity. POPRF's {@code tweakedKey = T + pkS} hits exactly this when
   * the info scalar happens to be the negation of the server key, and RFC 9497 §3.3.3 requires the
   * client to detect it rather than proceed.
   */
  @ParameterizedTest(name = "{0}")
  @MethodSource("specs")
  void addRejectsAnIdentityResult(String name, GroupSpec spec) {
    byte[] p = point(spec, "negation");
    byte[] negated = spec.scalarMultiply(spec.groupOrder().subtract(BigInteger.ONE), p);
    assertThatThrownBy(() -> spec.add(p, negated))
        .isInstanceOf(IdentityResultException.class)
        .hasMessageContaining("identity");
  }

  // ─── linear combination ─────────────────────────────────────────────────────

  /**
   * The defining property: for terms that never touch the identity, the multi-scalar form must
   * agree with multiplying each term and folding them with {@code add}.
   */
  @ParameterizedTest(name = "{0}")
  @MethodSource("specs")
  void linearCombinationAgreesWithNaiveMultiplyThenAdd(String name, GroupSpec spec) {
    byte[][] elements = {point(spec, "e0"), point(spec, "e1"), point(spec, "e2")};
    BigInteger[] scalars = {randomScalar(spec), randomScalar(spec), randomScalar(spec)};

    byte[] naive = spec.scalarMultiply(scalars[0], elements[0]);
    for (int i = 1; i < elements.length; i++) {
      naive = spec.add(naive, spec.scalarMultiply(scalars[i], elements[i]));
    }

    assertThat(spec.linearCombinationPublic(scalars, elements)).isEqualTo(naive);
    assertThat(spec.linearCombinationSecret(scalars, elements)).isEqualTo(naive);
  }

  /**
   * The secret and public forms differ only in which multiplier they use, so they must agree
   * exactly. On ristretto255 they are the same routine; on the Weierstrass curves the public form
   * uses BouncyCastle's default multiplier and the secret form the constant-time ladder, and this
   * is what pins the ladder to the same answer.
   */
  @ParameterizedTest(name = "{0}")
  @MethodSource("specs")
  void secretAndPublicFormsAgree(String name, GroupSpec spec) {
    byte[][] elements = {point(spec, "s0"), point(spec, "s1")};
    BigInteger[] scalars = {randomScalar(spec), randomScalar(spec)};
    assertThat(spec.linearCombinationSecret(scalars, elements))
        .isEqualTo(spec.linearCombinationPublic(scalars, elements));
  }

  /**
   * A zero scalar makes one term the identity. The naive form cannot express this — its
   * intermediate {@code scalarMultiply} result would be rejected — which is the whole reason the
   * multi-scalar method exists. A remote party controls {@code s} and {@code c} in a proof, so
   * zero is reachable from the wire.
   */
  @ParameterizedTest(name = "{0}")
  @MethodSource("specs")
  void linearCombinationToleratesAZeroScalarTerm(String name, GroupSpec spec) {
    byte[][] elements = {point(spec, "z0"), point(spec, "z1")};
    BigInteger[] scalars = {BigInteger.ZERO, BigInteger.ONE};

    assertThat(spec.linearCombinationPublic(scalars, elements)).isEqualTo(elements[1]);
    assertThat(spec.linearCombinationSecret(scalars, elements)).isEqualTo(elements[1]);
  }

  /**
   * The accumulator may pass through the identity on its way to a non-identity sum: here the first
   * two terms cancel exactly. RFC 9497's {@code ComputeComposites} starts its accumulator at the
   * identity for the same reason.
   */
  @ParameterizedTest(name = "{0}")
  @MethodSource("specs")
  void linearCombinationToleratesAnIdentityIntermediate(String name, GroupSpec spec) {
    byte[] p = point(spec, "cancel");
    byte[] q = point(spec, "survivor");
    BigInteger n = spec.groupOrder();
    BigInteger[] scalars = {BigInteger.ONE, n.subtract(BigInteger.ONE), BigInteger.ONE};
    byte[][] elements = {p, p, q};

    assertThat(spec.linearCombinationPublic(scalars, elements)).isEqualTo(q);
    assertThat(spec.linearCombinationSecret(scalars, elements)).isEqualTo(q);
  }

  @ParameterizedTest(name = "{0}")
  @MethodSource("specs")
  void linearCombinationRejectsAnIdentityResult(String name, GroupSpec spec) {
    byte[] p = point(spec, "total-cancel");
    BigInteger n = spec.groupOrder();
    BigInteger[] scalars = {BigInteger.ONE, n.subtract(BigInteger.ONE)};
    byte[][] elements = {p, p};

    assertThatThrownBy(() -> spec.linearCombinationPublic(scalars, elements))
        .isInstanceOf(IdentityResultException.class);
    assertThatThrownBy(() -> spec.linearCombinationSecret(scalars, elements))
        .isInstanceOf(IdentityResultException.class);
  }

  @ParameterizedTest(name = "{0}")
  @MethodSource("specs")
  void linearCombinationRejectsEmptyInput(String name, GroupSpec spec) {
    assertThatThrownBy(() -> spec.linearCombinationPublic(new BigInteger[0], new byte[0][]))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("at least one");
  }

  @ParameterizedTest(name = "{0}")
  @MethodSource("specs")
  void linearCombinationRejectsMismatchedLengths(String name, GroupSpec spec) {
    BigInteger[] scalars = {BigInteger.ONE, BigInteger.ONE};
    byte[][] elements = {point(spec, "only-one")};
    assertThatThrownBy(() -> spec.linearCombinationPublic(scalars, elements))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("differ");
  }

  /**
   * An identity input is still an input, and must be rejected as one. Split by suite because the
   * two encode the identity differently: ristretto255 uses 32 zero bytes, while SEC1 compressed
   * uses the single byte {@code 0x00}. A shared test passing {@code new byte[elementSize()]} would
   * look like it covered both, but on the Weierstrass curves 33 zero bytes is rejected as a
   * malformed <em>encoding</em> before the identity check is ever reached — so it would pass
   * without ever exercising the path it claims to.
   */
  @Test
  void ristrettoLinearCombinationRejectsTheIdentityInputEncoding() {
    GroupSpec spec = Ristretto255GroupSpec.INSTANCE;
    assertThatThrownBy(() -> spec.linearCombinationPublic(
        new BigInteger[]{BigInteger.ONE}, new byte[][]{new byte[32]}))
        .isInstanceOf(SecurityException.class)
        .hasMessageContaining("identity");
  }

  @ParameterizedTest(name = "{0}")
  @MethodSource("weierstrassSpecs")
  void weierstrassLinearCombinationRejectsTheIdentityInputEncoding(String name, GroupSpec spec) {
    assertThatThrownBy(() -> spec.linearCombinationPublic(
        new BigInteger[]{BigInteger.ONE}, new byte[][]{new byte[]{0x00}}))
        .isInstanceOf(SecurityException.class)
        .hasMessageContaining("identity");
  }

  static Stream<Arguments> weierstrassSpecs() {
    return Stream.of(
        Arguments.of("P-256", WeierstrassGroupSpecImpl.P256_SHA256),
        Arguments.of("P-384", WeierstrassGroupSpecImpl.P384_SHA384),
        Arguments.of("P-521", WeierstrassGroupSpecImpl.P521_SHA512));
  }

  // ─── element validation ─────────────────────────────────────────────────────

  @ParameterizedTest(name = "{0}")
  @MethodSource("specs")
  void validateElementAcceptsAWellFormedElement(String name, GroupSpec spec) {
    assertThatCode(() -> spec.validateElement(point(spec, "valid"))).doesNotThrowAnyException();
    assertThatCode(() -> spec.validateElement(spec.generator())).doesNotThrowAnyException();
  }

  @ParameterizedTest(name = "{0}")
  @MethodSource("specs")
  void validateElementRejectsTheIdentityAndGarbage(String name, GroupSpec spec) {
    assertThatThrownBy(() -> spec.validateElement(new byte[spec.elementSize()]))
        .isInstanceOfAny(SecurityException.class, IllegalArgumentException.class);
    assertThatThrownBy(() -> spec.validateElement(null))
        .isInstanceOfAny(SecurityException.class, IllegalArgumentException.class);
  }

  /**
   * RFC 9497 §4.3-§4.5 specify deserialization as the <em>compressed</em> method over an
   * {@code Ne}-byte string, but BouncyCastle's {@code decodePoint} also accepts SEC1 uncompressed
   * ({@code 0x04}) and hybrid ({@code 0x06}/{@code 0x07}) forms, which are longer.
   * <p>
   * Accepting them is not a cosmetic laxity. The RFC 9497 §2.2 proof transcripts hash element
   * <em>bytes</em>, so an attacker who re-encodes a blinded element in flight makes the server
   * prove over bytes the client never sent: the composite coefficients differ, verification fails,
   * and the client cannot distinguish a network attacker from a faulty server. This test pins the
   * length check that closes it — it failed before that check existed.
   */
  @ParameterizedTest(name = "{0}")
  @MethodSource("weierstrassSpecs")
  void weierstrassValidateElementRejectsNonCompressedEncodings(String name, GroupSpec spec) {
    WeierstrassGroupSpecImpl impl = (WeierstrassGroupSpecImpl) spec;
    byte[] uncompressed = impl.deserializePoint(spec.generator()).getEncoded(false);

    assertThat(uncompressed.length).isNotEqualTo(spec.elementSize());
    assertThatThrownBy(() -> spec.validateElement(uncompressed))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("compressed");
  }

  // ─── scalar serialization ───────────────────────────────────────────────────

  @ParameterizedTest(name = "{0}")
  @MethodSource("specs")
  void scalarRoundTrips(String name, GroupSpec spec) {
    for (int i = 0; i < 8; i++) {
      BigInteger k = randomScalar(spec);
      byte[] encoded = spec.serializeScalar(k);
      assertThat(encoded).hasSize(spec.scalarSize());
      assertThat(spec.deserializeScalar(encoded)).isEqualTo(k);
    }
  }

  @ParameterizedTest(name = "{0}")
  @MethodSource("specs")
  void scalarZeroAndMaxRoundTrip(String name, GroupSpec spec) {
    BigInteger max = spec.groupOrder().subtract(BigInteger.ONE);
    assertThat(spec.deserializeScalar(spec.serializeScalar(BigInteger.ZERO)))
        .isEqualTo(BigInteger.ZERO);
    assertThat(spec.deserializeScalar(spec.serializeScalar(max))).isEqualTo(max);
  }

  /**
   * A scalar at or above the group order must not serialize. Before this check, ristretto255
   * silently truncated anything at or above 2^256 into a different, valid-looking scalar, because
   * its little-endian encoder copies at most 32 bytes and drops the rest.
   */
  @ParameterizedTest(name = "{0}")
  @MethodSource("specs")
  void serializeScalarRejectsOutOfRange(String name, GroupSpec spec) {
    assertThatThrownBy(() -> spec.serializeScalar(spec.groupOrder()))
        .isInstanceOf(IllegalArgumentException.class);
    assertThatThrownBy(() -> spec.serializeScalar(BigInteger.ONE.negate()))
        .isInstanceOf(IllegalArgumentException.class);
    assertThatThrownBy(() -> spec.serializeScalar(BigInteger.TWO.pow(600)))
        .isInstanceOf(IllegalArgumentException.class);
  }

  /**
   * The truncation case specifically: {@code L + 2^256} and {@code L} are distinct BigIntegers
   * whose low 32 bytes differ, but an unchecked little-endian encoder would map the former onto a
   * short encoding rather than refusing it.
   */
  @Test
  void ristrettoSerializeScalarRejectsTheValueItUsedToTruncate() {
    GroupSpec spec = Ristretto255GroupSpec.INSTANCE;
    BigInteger beyond = BigInteger.TWO.pow(256).add(BigInteger.ONE);
    assertThatThrownBy(() -> spec.serializeScalar(beyond))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("out of range");
  }

  /**
   * Accepting a non-canonical encoding would make a proof malleable: {@code c} and {@code s}
   * arrive over the wire, and {@code k} and {@code k + n} must not both decode.
   */
  @ParameterizedTest(name = "{0}")
  @MethodSource("specs")
  void deserializeScalarRejectsNonCanonicalEncodings(String name, GroupSpec spec) {
    byte[] atOrder = encodeLike(spec, spec.groupOrder());
    assertThatThrownBy(() -> spec.deserializeScalar(atOrder))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("canonical");

    byte[] allOnes = new byte[spec.scalarSize()];
    java.util.Arrays.fill(allOnes, (byte) 0xff);
    assertThatThrownBy(() -> spec.deserializeScalar(allOnes))
        .isInstanceOf(IllegalArgumentException.class);
  }

  @ParameterizedTest(name = "{0}")
  @MethodSource("specs")
  void deserializeScalarRejectsWrongLength(String name, GroupSpec spec) {
    assertThatThrownBy(() -> spec.deserializeScalar(new byte[spec.scalarSize() - 1]))
        .isInstanceOf(IllegalArgumentException.class);
    assertThatThrownBy(() -> spec.deserializeScalar(new byte[spec.scalarSize() + 1]))
        .isInstanceOf(IllegalArgumentException.class);
    assertThatThrownBy(() -> spec.deserializeScalar(null))
        .isInstanceOf(IllegalArgumentException.class);
  }

  @ParameterizedTest(name = "{0}")
  @MethodSource("specs")
  void deserializeScalarAcceptsTheLargestCanonicalValue(String name, GroupSpec spec) {
    byte[] max = encodeLike(spec, spec.groupOrder().subtract(BigInteger.ONE));
    assertThatCode(() -> spec.deserializeScalar(max)).doesNotThrowAnyException();
  }

  /**
   * Encodes a value using the suite's byte order without going through {@code serializeScalar},
   * which refuses out-of-range values — the point being to construct encodings that
   * {@code deserializeScalar} must reject.
   */
  private static byte[] encodeLike(GroupSpec spec, BigInteger value) {
    int size = spec.scalarSize();
    byte[] be = value.toByteArray();
    byte[] fixed = new byte[size];
    int copy = Math.min(be.length, size);
    System.arraycopy(be, be.length - copy, fixed, size - copy, copy);
    if (spec instanceof Ristretto255GroupSpec) {
      byte[] le = new byte[size];
      for (int i = 0; i < size; i++) {
        le[i] = fixed[size - 1 - i];
      }
      return le;
    }
    return fixed;
  }
}
