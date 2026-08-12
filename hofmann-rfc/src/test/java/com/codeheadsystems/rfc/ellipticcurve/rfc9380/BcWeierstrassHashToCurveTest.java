package com.codeheadsystems.rfc.ellipticcurve.rfc9380;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.params.provider.Arguments.arguments;

import com.codeheadsystems.rfc.ellipticcurve.curve.Curve;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.stream.Stream;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA384Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.hash2curve.HashToCurveProfile;
import org.bouncycastle.math.ec.ECPoint;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * Known-answer tests for {@link BcWeierstrassHashToCurve} against the published RFC 9380 test
 * vectors.
 *
 * <p>
 * Vectors are taken from <a href="https://www.rfc-editor.org/rfc/rfc9380.txt">RFC 9380</a>,
 * "Hashing to Elliptic Curves", Appendix J ("Suite Test Vectors") — <b>J.1.1</b> for
 * {@code P256_XMD:SHA-256_SSWU_RO_}, <b>J.2.1</b> for {@code P384_XMD:SHA-384_SSWU_RO_} and
 * <b>J.3.1</b> for {@code P521_XMD:SHA-512_SSWU_RO_}, together with the {@code QUUX-V01-CS02-with-}
 * domain separation tags the RFC used to generate them.
 * </p>
 *
 * <p>
 * Those subsection numbers are the ones in the published RFC. Earlier tests in this package cited
 * them one section high (calling P-256 "J.2.1" and P-384 "J.3.1"), a numbering that came from a
 * pre-publication draft. Appendix J.1 is NIST P-256.
 * </p>
 *
 * <p>
 * Each suite supplies all five of the RFC's messages, and these are the primary evidence that
 * delegating to BouncyCastle produces byte-identical output to the hand-rolled pipeline this
 * replaced.
 * </p>
 */
class BcWeierstrassHashToCurveTest {

  private static final String MSG_EMPTY = "";
  private static final String MSG_ABC = "abc";
  private static final String MSG_HEXISH = "abcdef0123456789";
  private static final String MSG_Q128 = "q128_" + "q".repeat(128);
  private static final String MSG_A512 = "a512_" + "a".repeat(512);

  private static final BcWeierstrassHashToCurve P256 = BcWeierstrassHashToCurve.of(
      Curve.P256_CURVE.curve(), HashToCurveProfile.P256_XMD_SHA_256, new SHA256Digest());
  private static final BcWeierstrassHashToCurve P384 = BcWeierstrassHashToCurve.of(
      Curve.P384_CURVE.curve(), HashToCurveProfile.P384_XMD_SHA_384, new SHA384Digest());
  private static final BcWeierstrassHashToCurve P521 = BcWeierstrassHashToCurve.of(
      Curve.P521_CURVE.curve(), HashToCurveProfile.P521_XMD_SHA_512, new SHA512Digest());

  private static void assertPoint(final BcWeierstrassHashToCurve h2c,
                                  final String dst,
                                  final String msg,
                                  final String expectedX,
                                  final String expectedY) {
    final ECPoint point = h2c.hashToCurve(
        msg.getBytes(StandardCharsets.UTF_8), dst.getBytes(StandardCharsets.UTF_8)).normalize();
    assertThat(point.getAffineXCoord().toBigInteger()).isEqualTo(new BigInteger(expectedX, 16));
    assertThat(point.getAffineYCoord().toBigInteger()).isEqualTo(new BigInteger(expectedY, 16));
    assertThat(point.isValid()).isTrue();
  }

  /**
   * RFC 9380 Appendix J.1.1 vectors for {@code P256_XMD:SHA-256_SSWU_RO_}.
   *
   * @return the msg / expected-x / expected-y triples
   */
  static Stream<Arguments> p256Vectors() {
    return Stream.of(
        arguments(MSG_EMPTY,
            "2c15230b26dbc6fc9a37051158c95b79656e17a1a920b11394ca91c44247d3e4",
            "8a7a74985cc5c776cdfe4b1f19884970453912e9d31528c060be9ab5c43e8415"),
        arguments(MSG_ABC,
            "0bb8b87485551aa43ed54f009230450b492fead5f1cc91658775dac4a3388a0f",
            "5c41b3d0731a27a7b14bc0bf0ccded2d8751f83493404c84a88e71ffd424212e"),
        arguments(MSG_HEXISH,
            "65038ac8f2b1def042a5df0b33b1f4eca6bff7cb0f9c6c1526811864e544ed80",
            "cad44d40a656e7aff4002a8de287abc8ae0482b5ae825822bb870d6df9b56ca3"),
        arguments(MSG_Q128,
            "4be61ee205094282ba8a2042bcb48d88dfbb609301c49aa8b078533dc65a0b5d",
            "98f8df449a072c4721d241a3b1236d3caccba603f916ca680f4539d2bfb3c29e"),
        arguments(MSG_A512,
            "457ae2981f70ca85d8e24c308b14db22f3e3862c5ea0f652ca38b5e49cd64bc5",
            "ecb9f0eadc9aeed232dabc53235368c1394c78de05dd96893eefa62b0f4757dc")
    );
  }

  /**
   * Verifies P256_XMD:SHA-256_SSWU_RO_ against RFC 9380 Appendix J.1.1.
   *
   * @param msg       the message to hash
   * @param expectedX the expected affine x coordinate, hex
   * @param expectedY the expected affine y coordinate, hex
   */
  @ParameterizedTest(name = "P256 msg=\"{0}\"")
  @MethodSource("p256Vectors")
  void p256(final String msg, final String expectedX, final String expectedY) {
    assertPoint(P256, "QUUX-V01-CS02-with-P256_XMD:SHA-256_SSWU_RO_", msg, expectedX, expectedY);
  }

  /**
   * RFC 9380 Appendix J.2.1 vectors for {@code P384_XMD:SHA-384_SSWU_RO_}.
   *
   * @return the msg / expected-x / expected-y triples
   */
  static Stream<Arguments> p384Vectors() {
    return Stream.of(
        arguments(MSG_EMPTY,
            "eb9fe1b4f4e14e7140803c1d99d0a93cd823d2b024040f9c067a8eca1f5a2eeac9ad604973527a356f3fa3aeff0e4d83",
            "0c21708cff382b7f4643c07b105c2eaec2cead93a917d825601e63c8f21f6abd9abc22c93c2bed6f235954b25048bb1a"),
        arguments(MSG_ABC,
            "e02fc1a5f44a7519419dd314e29863f30df55a514da2d655775a81d413003c4d4e7fd59af0826dfaad4200ac6f60abe1",
            "01f638d04d98677d65bef99aef1a12a70a4cbb9270ec55248c04530d8bc1f8f90f8a6a859a7c1f1ddccedf8f96d675f6"),
        arguments(MSG_HEXISH,
            "bdecc1c1d870624965f19505be50459d363c71a699a496ab672f9a5d6b78676400926fbceee6fcd1780fe86e62b2aa89",
            "57cf1f99b5ee00f3c201139b3bfe4dd30a653193778d89a0accc5e0f47e46e4e4b85a0595da29c9494c1814acafe183c"),
        arguments(MSG_Q128,
            "03c3a9f401b78c6c36a52f07eeee0ec1289f178adf78448f43a3850e0456f5dd7f7633dd31676d990eda32882ab486c0",
            "cc183d0d7bdfd0a3af05f50e16a3f2de4abbc523215bf57c848d5ea662482b8c1f43dc453a93b94a8026db58f3f5d878"),
        arguments(MSG_A512,
            "7b18d210b1f090ac701f65f606f6ca18fb8d081e3bc6cbd937c5604325f1cdea4c15c10a54ef303aabf2ea58bd9947a4",
            "ea857285a33abb516732915c353c75c576bf82ccc96adb63c094dde580021eddeafd91f8c0bfee6f636528f3d0c47fd2")
    );
  }

  /**
   * Verifies P384_XMD:SHA-384_SSWU_RO_ against RFC 9380 Appendix J.2.1.
   *
   * @param msg       the message to hash
   * @param expectedX the expected affine x coordinate, hex
   * @param expectedY the expected affine y coordinate, hex
   */
  @ParameterizedTest(name = "P384 msg=\"{0}\"")
  @MethodSource("p384Vectors")
  void p384(final String msg, final String expectedX, final String expectedY) {
    assertPoint(P384, "QUUX-V01-CS02-with-P384_XMD:SHA-384_SSWU_RO_", msg, expectedX, expectedY);
  }

  /**
   * RFC 9380 Appendix J.3.1 vectors for {@code P521_XMD:SHA-512_SSWU_RO_}.
   *
   * @return the msg / expected-x / expected-y triples
   */
  static Stream<Arguments> p521Vectors() {
    return Stream.of(
        arguments(MSG_EMPTY,
            "00fd767cebb2452030358d0e9cf907f525f50920c8f607889a6a35680727f64f4d66b161fafeb2654bea0d35086bec0a10b30b14adef3556ed9f7f1bc23cecc9c088",
            "0169ba78d8d851e930680322596e39c78f4fe31b97e57629ef6460ddd68f8763fd7bd767a4e94a80d3d21a3c2ee98347e024fc73ee1c27166dc3fe5eeef782be411d"),
        arguments(MSG_ABC,
            "002f89a1677b28054b50d15e1f81ed6669b5a2158211118ebdef8a6efc77f8ccaa528f698214e4340155abc1fa08f8f613ef14a043717503d57e267d57155cf784a4",
            "010e0be5dc8e753da8ce51091908b72396d3deed14ae166f66d8ebf0a4e7059ead169ea4bead0232e9b700dd380b316e9361cfdba55a08c73545563a80966ecbb86d"),
        arguments(MSG_HEXISH,
            "006e200e276a4a81760099677814d7f8794a4a5f3658442de63c18d2244dcc957c645e94cb0754f95fcf103b2aeaf94411847c24187b89fb7462ad3679066337cbc4",
            "001dd8dfa9775b60b1614f6f169089d8140d4b3e4012949b52f98db2deff3e1d97bf73a1fa4d437d1dcdf39b6360cc518d8ebcc0f899018206fded7617b654f6b168"),
        arguments(MSG_Q128,
            "01b264a630bd6555be537b000b99a06761a9325c53322b65bdc41bf196711f9708d58d34b3b90faf12640c27b91c70a507998e55940648caa8e71098bf2bc8d24664",
            "01ea9f445bee198b3ee4c812dcf7b0f91e0881f0251aab272a12201fd89b1a95733fd2a699c162b639e9acdcc54fdc2f6536129b6beb0432be01aa8da02df5e59aaa"),
        arguments(MSG_A512,
            "00c12bc3e28db07b6b4d2a2b1167ab9e26fc2fa85c7b0498a17b0347edf52392856d7e28b8fa7a2dd004611159505835b687ecf1a764857e27e9745848c436ef3925",
            "01cd287df9a50c22a9231beb452346720bb163344a41c5f5a24e8335b6ccc595fd436aea89737b1281aecb411eb835f0b939073fdd1dd4d5a2492e91ef4a3c55bcbd")
    );
  }

  /**
   * Verifies P521_XMD:SHA-512_SSWU_RO_ against RFC 9380 Appendix J.3.1.
   *
   * @param msg       the message to hash
   * @param expectedX the expected affine x coordinate, hex
   * @param expectedY the expected affine y coordinate, hex
   */
  @ParameterizedTest(name = "P521 msg=\"{0}\"")
  @MethodSource("p521Vectors")
  void p521(final String msg, final String expectedX, final String expectedY) {
    assertPoint(P521, "QUUX-V01-CS02-with-P521_XMD:SHA-512_SSWU_RO_", msg, expectedX, expectedY);
  }
  /**
   * A DST over 255 bytes is rejected rather than hashed down.
   *
   * <p>
   * BouncyCastle's {@code XmdMessageExpansion} throws instead of applying the RFC 9380 §5.3.3
   * {@code H2C-OVERSIZE-DST-} rewrite that the previous hand-rolled {@code ExpandMessageXmd}
   * implemented. This test pins that as a known, deliberate limitation rather than leaving it to be
   * rediscovered. No DST this library generates approaches 255 bytes.
   * </p>
   */
  @Test
  void oversizeDstIsRejected() {
    final byte[] dst = "x".repeat(256).getBytes(StandardCharsets.UTF_8);
    assertThatThrownBy(() -> P256.hashToCurve("abc".getBytes(StandardCharsets.UTF_8), dst))
        .isInstanceOf(IllegalArgumentException.class);
  }

  /**
   * Distinct domain separation tags must produce distinct points for the same message.
   */
  @Test
  void domainSeparationChangesTheResult() {
    final byte[] msg = "abc".getBytes(StandardCharsets.UTF_8);
    final ECPoint a = P256.hashToCurve(msg, "dst-one".getBytes(StandardCharsets.UTF_8));
    final ECPoint b = P256.hashToCurve(msg, "dst-two".getBytes(StandardCharsets.UTF_8));
    assertThat(a.normalize()).isNotEqualTo(b.normalize());
  }

  /**
   * The same message and tag must map to the same point every time.
   */
  @Test
  void outputIsDeterministic() {
    final byte[] msg = "abc".getBytes(StandardCharsets.UTF_8);
    final byte[] dst = "a-stable-dst".getBytes(StandardCharsets.UTF_8);
    assertThat(P256.hashToCurve(msg, dst).normalize())
        .isEqualTo(P256.hashToCurve(msg, dst).normalize());
  }

  /**
   * Distinct messages under one tag must produce distinct points.
   */
  @Test
  void distinctMessagesProduceDistinctPoints() {
    final byte[] dst = "a-stable-dst".getBytes(StandardCharsets.UTF_8);
    final ECPoint a = P256.hashToCurve("one".getBytes(StandardCharsets.UTF_8), dst);
    final ECPoint b = P256.hashToCurve("two".getBytes(StandardCharsets.UTF_8), dst);
    assertThat(a.normalize()).isNotEqualTo(b.normalize());
  }
}
