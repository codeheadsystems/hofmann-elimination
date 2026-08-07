package com.codeheadsystems.rfc.oprf.rfc9497;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.stream.Stream;
import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * Pins mode separation (RFC 9497 §3.1) and the suite-level primitives the verifiable modes need.
 *
 * <p>The key-derivation vectors are the sharpest test here. {@code deriveKeyPairDst} embeds the
 * context string, which embeds the mode byte, so one seed produces a different server key in each
 * mode — and RFC 9497 Appendix A publishes all three for the same seed and key info. If the mode
 * byte were dropped, ignored, or written in the wrong position, two of the three would collide
 * with the base-mode value and these tests would catch it. The base-mode values are also
 * unchanged from before the mode parameter existed, which is what guarantees OPAQUE and every
 * stored OPRF hash still derive the same key.
 */
class OprfModeTest {

  /** Appendix A: Seed = a3 repeated 32 times, KeyInfo = "test key", for every suite and mode. */
  private static final byte[] SEED = new byte[32];
  private static final byte[] KEY_INFO = "test key".getBytes(StandardCharsets.UTF_8);

  static {
    Arrays.fill(SEED, (byte) 0xa3);
  }

  static Stream<Arguments> keyDerivationVectors() {
    return Stream.of(
        // RFC 9497 A.1.1 / A.1.2 / A.1.3 — ristretto255-SHA512
        Arguments.of(CurveHashSuite.RISTRETTO255_SHA512, OprfMode.OPRF,
            "5ebcea5ee37023ccb9fc2d2019f9d7737be85591ae8652ffa9ef0f4d37063b0e", null),
        Arguments.of(CurveHashSuite.RISTRETTO255_SHA512, OprfMode.VOPRF,
            "e6f73f344b79b379f1a0dd37e07ff62e38d9f71345ce62ae3a9bc60b04ccd909",
            "c803e2cc6b05fc15064549b5920659ca4a77b2cca6f04f6b357009335476ad4e"),
        Arguments.of(CurveHashSuite.RISTRETTO255_SHA512, OprfMode.POPRF,
            "145c79c108538421ac164ecbe131942136d5570b16d8bf41a24d4337da981e07",
            "c647bef38497bc6ec077c22af65b696efa43bff3b4a1975a3e8e0a1c5a79d631"),
        // RFC 9497 A.3.1 / A.3.2 / A.3.3 — P256-SHA256
        Arguments.of(CurveHashSuite.P256_SHA256, OprfMode.OPRF,
            "159749d750713afe245d2d39ccfaae8381c53ce92d098a9375ee70739c7ac0bf", null),
        Arguments.of(CurveHashSuite.P256_SHA256, OprfMode.VOPRF,
            "ca5d94c8807817669a51b196c34c1b7f8442fde4334a7121ae4736364312fca6",
            "03e17e70604bcabe198882c0a1f27a92441e774224ed9c702e51dd17038b102462"),
        Arguments.of(CurveHashSuite.P256_SHA256, OprfMode.POPRF,
            "6ad2173efa689ef2c27772566ad7ff6e2d59b3b196f00219451fb2c89ee4dae2",
            "030d7ff077fddeec965db14b794f0cc1ba9019b04a2f4fcc1fa525dedf72e2a3e3"),
        // RFC 9497 A.4.1 / A.4.2 / A.4.3 — P384-SHA384
        Arguments.of(CurveHashSuite.P384_SHA384, OprfMode.OPRF,
            "dfe7ddc41a4646901184f2b432616c8ba6d452f9bcd0c4f75a5150ef2b2ed02e"
                + "f40b8b92f60ae591bcabd72a6518f188", null),
        Arguments.of(CurveHashSuite.P384_SHA384, OprfMode.VOPRF,
            "051646b9e6e7a71ae27c1e1d0b87b4381db6d3595eeeb1adb41579adbf992f42"
                + "78f9016eafc944edaa2b43183581779d",
            "031d689686c611991b55f1a1d8f4305ccd6cb719446f660a30db61b7aa87b46acf"
                + "59b7c0d4a9077b3da21c25dd482229a0"),
        Arguments.of(CurveHashSuite.P384_SHA384, OprfMode.POPRF,
            "5b2690d6954b8fbb159f19935d64133f12770c00b68422559c65431942d721ff"
                + "79d47d7a75906c30b7818ec0f38b7fb2",
            "02f00f0f1de81e5d6cf18140d4926ffdc9b1898c48dc49657ae36eb1e45deb8b95"
                + "1aaf1f10c82d2eaa6d02aafa3f10d2b6"),
        // RFC 9497 A.5.1 / A.5.2 / A.5.3 — P521-SHA512
        Arguments.of(CurveHashSuite.P521_SHA512, OprfMode.OPRF,
            "0153441b8faedb0340439036d6aed06d1217b34c42f17f8db4c5cc610a4a955d"
                + "698a688831b16d0dc7713a1aa3611ec60703bffc7dc9c84e3ed673b3dbe1d5fccea6", null),
        Arguments.of(CurveHashSuite.P521_SHA512, OprfMode.VOPRF,
            "015c7fc1b4a0b1390925bae915bd9f3d72009d44d9241b962428aad5d13f2280"
                + "3311e7102632a39addc61ea440810222715c9d2f61f03ea424ec9ab1fe5e31cf9238",
            "0301505d646f6e4c9102451eb39730c4ba1c4087618641edbdba4a60896b07fd0c"
                + "9414ce553cbf25b81dfcca50a8f6724ab7a2bc4d0cf736967a287bb6084cc0678ac0"),
        Arguments.of(CurveHashSuite.P521_SHA512, OprfMode.POPRF,
            "014893130030ce69cf714f536498a02ff6b396888f9bb507985c32928c4427d6"
                + "d39de10ef509aca4240e8569e3a88debc0d392e3361bcd934cb9bdd59e339dff7b27",
            "0301de8ceb9ffe9237b1bba87c320ea0bebcfc3447fe6f278065c6c69886d692d1"
                + "126b79b6844f829940ace9b52a5e26882cf7cbc9e57503d4cca3cd834584729f812a"));
  }

  private static OprfCipherSuite suite(CurveHashSuite curve, OprfMode mode) {
    return OprfCipherSuite.builder().withSuite(curve).withMode(mode).build();
  }

  @ParameterizedTest(name = "{0} {1}")
  @MethodSource("keyDerivationVectors")
  void deriveKeyPairMatchesRfcVectors(CurveHashSuite curve, OprfMode mode,
                                      String expectedSkS, String expectedPkS) {
    OprfCipherSuite suite = suite(curve, mode);
    BigInteger skS = suite.deriveKeyPair(SEED, KEY_INFO);

    assertThat(Hex.toHexString(suite.groupSpec().serializeScalar(skS)))
        .as("skSm for %s in %s mode", curve, mode)
        .isEqualTo(expectedSkS);
  }

  /**
   * The verifiable modes commit to a public key, and the client grades every proof against it. A
   * wrong {@code pkS} fails closed rather than open, but it fails every evaluation, so pin it.
   */
  @ParameterizedTest(name = "{0} {1}")
  @MethodSource("keyDerivationVectors")
  void derivePublicKeyMatchesRfcVectors(CurveHashSuite curve, OprfMode mode,
                                        String expectedSkS, String expectedPkS) {
    if (expectedPkS == null) {
      return; // base mode publishes no public key
    }
    OprfCipherSuite suite = suite(curve, mode);
    BigInteger skS = suite.deriveKeyPair(SEED, KEY_INFO);

    assertThat(Hex.toHexString(suite.derivePublicKey(skS)))
        .as("pkSm for %s in %s mode", curve, mode)
        .isEqualTo(expectedPkS);
  }

  /**
   * The same seed must produce three different keys. This is what the mode byte buys, and it is
   * also why one {@code skS} must never be configured for two modes at once — the RFC's static
   * Diffie-Hellman security budget (§7.2.3) is per-key, and the POPRF's inversion oracle and the
   * OPRF's multiplication oracle rest on different hardness assumptions (§7.2.1, §7.2.2).
   */
  @Test
  void eachModeDerivesADistinctKeyFromOneSeed() {
    for (CurveHashSuite curve : CurveHashSuite.values()) {
      BigInteger base = suite(curve, OprfMode.OPRF).deriveKeyPair(SEED, KEY_INFO);
      BigInteger verifiable = suite(curve, OprfMode.VOPRF).deriveKeyPair(SEED, KEY_INFO);
      BigInteger partial = suite(curve, OprfMode.POPRF).deriveKeyPair(SEED, KEY_INFO);

      assertThat(base).as("%s OPRF vs VOPRF", curve).isNotEqualTo(verifiable);
      assertThat(base).as("%s OPRF vs POPRF", curve).isNotEqualTo(partial);
      assertThat(verifiable).as("%s VOPRF vs POPRF", curve).isNotEqualTo(partial);
    }
  }

  // ─── context strings ────────────────────────────────────────────────────────

  /**
   * Builds {@code prefix || "OPRFV1-" || modeByte || "-P256-SHA256"} one byte at a time.
   * <p>
   * Deliberately not a Java string literal. The mode bytes are 0x00, 0x01 and 0x02 — none of them
   * printable — and an earlier draft of this test embedded raw NUL characters directly in the
   * source, where they were invisible in the editor and indistinguishable from a space. A test
   * whose expected value is unreadable cannot be reviewed, and one that accidentally encodes a
   * space would still pass against an implementation that made the same mistake.
   */
  private static byte[] expectedTag(String prefix, byte modeByte) {
    byte[] head = (prefix + "OPRFV1-").getBytes(StandardCharsets.UTF_8);
    byte[] tail = "-P256-SHA256".getBytes(StandardCharsets.UTF_8);
    byte[] out = new byte[head.length + 1 + tail.length];
    System.arraycopy(head, 0, out, 0, head.length);
    out[head.length] = modeByte;
    System.arraycopy(tail, 0, out, head.length + 1, tail.length);
    return out;
  }

  /**
   * Golden bytes for the base mode. Every stored OPAQUE credential and every persisted OPRF hash
   * in every downstream port derives from these; if the mode parameter perturbed them, all of that
   * material would become unreproducible.
   */
  @Test
  void baseModeContextStringIsUnchanged() {
    OprfCipherSuite suite = OprfCipherSuite.builder().withSuite(CurveHashSuite.P256_SHA256).build();
    assertThat(suite.mode()).isEqualTo(OprfMode.OPRF);
    assertThat(Hex.toHexString(suite.contextString()))
        .isEqualTo("4f50524656312d002d503235362d534841323536");
    assertThat(suite.contextString()).isEqualTo(expectedTag("", (byte) 0x00));
    assertThat(suite.deriveKeyPairDst()).isEqualTo(expectedTag("DeriveKeyPair", (byte) 0x00));
  }

  @Test
  void modeByteAppearsInEveryDerivedTag() {
    for (OprfMode mode : OprfMode.values()) {
      OprfCipherSuite suite = suite(CurveHashSuite.P256_SHA256, mode);

      assertThat(suite.contextString()).as("%s context", mode)
          .isEqualTo(expectedTag("", mode.value()));
      assertThat(suite.hashToGroupDst()).as("%s HashToGroup", mode)
          .isEqualTo(expectedTag("HashToGroup-", mode.value()));
      assertThat(suite.hashToScalarDst()).as("%s HashToScalar", mode)
          .isEqualTo(expectedTag("HashToScalar-", mode.value()));
      assertThat(suite.deriveKeyPairDst()).as("%s DeriveKeyPair", mode)
          .isEqualTo(expectedTag("DeriveKeyPair", mode.value()));
    }
  }

  @Test
  void modeSurvivesTheWithRandomCopy() {
    OprfCipherSuite suite = suite(CurveHashSuite.P256_SHA256, OprfMode.POPRF)
        .withRandom(new java.security.SecureRandom());
    assertThat(suite.mode()).isEqualTo(OprfMode.POPRF);
    assertThat(suite.contextString()).isEqualTo(expectedTag("", (byte) 0x02));
  }

  // ─── assertMode ─────────────────────────────────────────────────────────────

  @Test
  void assertModeAcceptsAMatchingMode() {
    assertThatCode(() -> suite(CurveHashSuite.P256_SHA256, OprfMode.VOPRF)
        .assertMode(OprfMode.VOPRF)).doesNotThrowAnyException();
    assertThatCode(() -> suite(CurveHashSuite.P256_SHA256, OprfMode.VOPRF)
        .assertMode(OprfMode.VOPRF, OprfMode.POPRF)).doesNotThrowAnyException();
  }

  @Test
  void assertModeRejectsAMismatch() {
    assertThatThrownBy(() -> suite(CurveHashSuite.P256_SHA256, OprfMode.OPRF)
        .assertMode(OprfMode.VOPRF))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("OPRF")
        .hasMessageContaining("VOPRF");
  }

  // ─── scalar inverse ─────────────────────────────────────────────────────────

  @Test
  void scalarInverseInvertsAndRejectsZero() {
    for (CurveHashSuite curve : CurveHashSuite.values()) {
      OprfCipherSuite suite = suite(curve, OprfMode.POPRF);
      BigInteger n = suite.groupSpec().groupOrder();
      BigInteger k = suite.randomScalar();

      assertThat(k.multiply(suite.scalarInverse(k)).mod(n)).isEqualTo(BigInteger.ONE);

      assertThatThrownBy(() -> suite.scalarInverse(BigInteger.ZERO))
          .isInstanceOf(IllegalArgumentException.class);
      assertThatThrownBy(() -> suite.scalarInverse(n))
          .isInstanceOf(IllegalArgumentException.class);
    }
  }

  /**
   * Pins the precondition: a zero key would derive an identity public key, which the DLEQ
   * transcript cannot carry because both group implementations reject the identity on
   * deserialize.
   */
  @Test
  void derivePublicKeyRejectsAnUnusableKey() {
    OprfCipherSuite suite = suite(CurveHashSuite.P256_SHA256, OprfMode.VOPRF);
    assertThatThrownBy(() -> suite.derivePublicKey(BigInteger.ZERO))
        .isInstanceOf(IllegalArgumentException.class);
    assertThatThrownBy(() -> suite.derivePublicKey(suite.groupSpec().groupOrder()))
        .isInstanceOf(IllegalArgumentException.class);
    assertThatThrownBy(() -> suite.derivePublicKey(null))
        .isInstanceOf(IllegalArgumentException.class);
  }

  @Test
  void scalarSizeMatchesTheGroup() {
    assertThat(suite(CurveHashSuite.P256_SHA256, OprfMode.VOPRF).scalarSize()).isEqualTo(32);
    assertThat(suite(CurveHashSuite.P384_SHA384, OprfMode.VOPRF).scalarSize()).isEqualTo(48);
    assertThat(suite(CurveHashSuite.P521_SHA512, OprfMode.VOPRF).scalarSize()).isEqualTo(66);
    assertThat(suite(CurveHashSuite.RISTRETTO255_SHA512, OprfMode.VOPRF).scalarSize()).isEqualTo(32);
  }

  // ─── finalize variants ──────────────────────────────────────────────────────

  /**
   * POPRF's transcript inserts {@code I2OSP(len(info), 2) || info} that the other modes omit
   * entirely — so even an empty {@code info} yields a different output than base-mode finalize,
   * because the two length bytes are still emitted. That difference is exactly why these are
   * separate methods rather than one with a nullable parameter.
   */
  @Test
  void finalizeWithInfoDiffersFromFinalizeEvenForEmptyInfo() {
    OprfCipherSuite suite = suite(CurveHashSuite.P256_SHA256, OprfMode.POPRF);
    byte[] input = "input".getBytes(StandardCharsets.UTF_8);
    BigInteger blind = suite.randomScalar();
    byte[] element = suite.groupSpec().hashToGroup(input, suite.hashToGroupDst());

    byte[] withoutInfo = suite.finalize(input, blind, element);
    byte[] emptyInfo = suite.finalizeWithInfo(input, new byte[0], blind, element);
    byte[] someInfo = suite.finalizeWithInfo(input, "i".getBytes(StandardCharsets.UTF_8), blind, element);

    assertThat(emptyInfo).isNotEqualTo(withoutInfo);
    assertThat(someInfo).isNotEqualTo(emptyInfo);
  }

  @Test
  void finalizeWithInfoRejectsAZeroBlind() {
    OprfCipherSuite suite = suite(CurveHashSuite.P256_SHA256, OprfMode.POPRF);
    byte[] input = "input".getBytes(StandardCharsets.UTF_8);
    byte[] element = suite.groupSpec().hashToGroup(input, suite.hashToGroupDst());

    assertThatThrownBy(() -> suite.finalizeWithInfo(input, new byte[0], BigInteger.ZERO, element))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("non-zero scalar");
  }
}
