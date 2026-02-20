package com.codeheadsystems.ellipticcurve.rfc9380;

import static org.assertj.core.api.Assertions.assertThat;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;

/**
 * Unit tests for {@link Ristretto255GroupSpec} operations.
 *
 * <p>Verifies group properties, encode/decode round-trips, scalar arithmetic,
 * and endianness utilities against RFC 9496 test vectors and algebraic identities.
 */
public class Ristretto255GroupSpecTest {

  private static final Ristretto255GroupSpec SPEC = Ristretto255GroupSpec.INSTANCE;

  // RFC 9496 §4.4 — ristretto255 generator element encoding
  private static final String BASE_POINT_HEX =
      "e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76";

  // Identity element encoding (all zeros)
  private static final String IDENTITY_HEX =
      "0000000000000000000000000000000000000000000000000000000000000000";

  // ─── Group properties ─────────────────────────────────────────────────────

  @Test
  void groupOrder_isCorrect() {
    // L = 2^252 + 27742317777372353535851937790883648493
    BigInteger expected = BigInteger.TWO.pow(252).add(
        new BigInteger("27742317777372353535851937790883648493"));
    assertThat(SPEC.groupOrder()).isEqualTo(expected);
  }

  @Test
  void elementSize_is32() {
    assertThat(SPEC.elementSize()).isEqualTo(32);
  }

  // ─── Generator scalar multiplication ─────────────────────────────────────

  @Test
  void scalarMultiplyGenerator_zero_isIdentity() {
    byte[] result = SPEC.scalarMultiplyGenerator(BigInteger.ZERO);
    assertThat(toHex(result)).isEqualTo(IDENTITY_HEX);
  }

  @Test
  void scalarMultiplyGenerator_one_isBasePoint() {
    // RFC 9496 §4.4: GENERATOR = e2f2ae0a...
    byte[] result = SPEC.scalarMultiplyGenerator(BigInteger.ONE);
    assertThat(toHex(result)).isEqualTo(BASE_POINT_HEX);
  }

  @Test
  void scalarMultiplyGenerator_groupOrder_isIdentity() {
    // L * B = identity
    byte[] result = SPEC.scalarMultiplyGenerator(SPEC.groupOrder());
    assertThat(toHex(result)).isEqualTo(IDENTITY_HEX);
  }

  // ─── Encode/decode round-trips ────────────────────────────────────────────

  @Test
  void scalarMultiply_one_isIdentityOnElement() {
    // 1 * B = B: scalarMultiply(1, encode(B)) == encode(B)
    byte[] encoded = SPEC.scalarMultiplyGenerator(BigInteger.ONE);
    byte[] reEncoded = SPEC.scalarMultiply(BigInteger.ONE, encoded);
    assertThat(reEncoded).isEqualTo(encoded);
  }

  @Test
  void scalarMultiply_doubling_matchesGeneratorDoubling() {
    // 2*B via scalarMultiply(2, B) == scalarMultiplyGenerator(2)
    byte[] via2G = SPEC.scalarMultiplyGenerator(BigInteger.TWO);
    byte[] baseEnc = SPEC.scalarMultiplyGenerator(BigInteger.ONE);
    byte[] viaScalarMul = SPEC.scalarMultiply(BigInteger.TWO, baseEnc);
    assertThat(viaScalarMul).isEqualTo(via2G);
  }

  @Test
  void scalarMultiply_zero_isIdentity() {
    // 0 * B = identity
    byte[] baseEnc = SPEC.scalarMultiplyGenerator(BigInteger.ONE);
    byte[] result = SPEC.scalarMultiply(BigInteger.ZERO, baseEnc);
    assertThat(toHex(result)).isEqualTo(IDENTITY_HEX);
  }

  // ─── Scalar serialization (little-endian) ────────────────────────────────

  @Test
  void serializeScalar_one_isLittleEndian() {
    byte[] serialized = SPEC.serializeScalar(BigInteger.ONE);
    assertThat(serialized).hasSize(32);
    assertThat(serialized[0]).isEqualTo((byte) 1);
    for (int i = 1; i < 32; i++) {
      assertThat(serialized[i]).as("byte[%d]", i).isEqualTo((byte) 0);
    }
  }

  @Test
  void serializeScalar_256_hasCorrectLayout() {
    // 256 = 0x100 in little-endian is [0x00, 0x01, 0x00, ..., 0x00]
    byte[] serialized = SPEC.serializeScalar(BigInteger.valueOf(256));
    assertThat(serialized).hasSize(32);
    assertThat(serialized[0]).isEqualTo((byte) 0x00);
    assertThat(serialized[1]).isEqualTo((byte) 0x01);
    for (int i = 2; i < 32; i++) {
      assertThat(serialized[i]).as("byte[%d]", i).isEqualTo((byte) 0);
    }
  }

  // ─── Little-endian utilities ──────────────────────────────────────────────

  @Test
  void decodeLittleEndian_one() {
    byte[] leOne = new byte[32];
    leOne[0] = 1;
    BigInteger decoded = Ristretto255GroupSpec.decodeLittleEndian(leOne);
    assertThat(decoded).isEqualTo(BigInteger.ONE);
  }

  @Test
  void decodeLittleEndian_256() {
    byte[] le256 = new byte[32];
    le256[1] = 1; // 256 = 0x100 in LE
    BigInteger decoded = Ristretto255GroupSpec.decodeLittleEndian(le256);
    assertThat(decoded).isEqualTo(BigInteger.valueOf(256));
  }

  @Test
  void encodeLittleEndian_roundTrip() {
    BigInteger value = BigInteger.valueOf(0x1234567890ABCDEFL);
    byte[] encoded = Ristretto255GroupSpec.encodeLittleEndian(value, 32);
    BigInteger decoded = Ristretto255GroupSpec.decodeLittleEndian(encoded);
    assertThat(decoded).isEqualTo(value);
  }

  // ─── hashToGroup ─────────────────────────────────────────────────────────

  @Test
  void hashToGroup_isDeterministic() {
    byte[] dst = "TestDST".getBytes(StandardCharsets.UTF_8);
    byte[] msg = "test message".getBytes(StandardCharsets.UTF_8);
    byte[] r1 = SPEC.hashToGroup(msg, dst);
    byte[] r2 = SPEC.hashToGroup(msg, dst);
    assertThat(r1).isEqualTo(r2);
  }

  @Test
  void hashToGroup_differentInputsGiveDifferentOutputs() {
    byte[] dst = "TestDST".getBytes(StandardCharsets.UTF_8);
    byte[] msg1 = "message1".getBytes(StandardCharsets.UTF_8);
    byte[] msg2 = "message2".getBytes(StandardCharsets.UTF_8);
    assertThat(SPEC.hashToGroup(msg1, dst)).isNotEqualTo(SPEC.hashToGroup(msg2, dst));
  }

  @Test
  void hashToGroup_returnsValidGroupElement() {
    // A valid ristretto255 element must decode without exception, and
    // multiplying by 1 must return the same encoding (canonical form).
    byte[] dst = "TestDST".getBytes(StandardCharsets.UTF_8);
    byte[] msg = "test".getBytes(StandardCharsets.UTF_8);
    byte[] element = SPEC.hashToGroup(msg, dst);
    byte[] reEncoded = SPEC.scalarMultiply(BigInteger.ONE, element);
    assertThat(reEncoded).isEqualTo(element);
  }

  // ─── Helpers ─────────────────────────────────────────────────────────────

  private static String toHex(byte[] b) {
    StringBuilder sb = new StringBuilder(b.length * 2);
    for (byte v : b) {
      sb.append(String.format("%02x", v & 0xFF));
    }
    return sb.toString();
  }
}
