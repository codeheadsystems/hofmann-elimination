package com.codeheadsystems.rfc.ellipticcurve.rfc9380;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.math.BigInteger;
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
}
