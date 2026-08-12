package com.codeheadsystems.rfc.common;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.math.BigInteger;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.math.ec.ECPoint;
import org.junit.jupiter.api.Test;

/**
 * The type Byte utils test.
 */
class ByteUtilsTest {

  // Removed: privateConstructorIsInaccessible, which made the constructor accessible, invoked it,
  // and asserted nothing. Its own comment said what it was for — "covers the private constructor
  // line" — and its name claimed the opposite of what it did.

  // ─── I2OSP ────────────────────────────────────────────────────────────────

  /**
   * 2 osp single byte zero.
   */
  @Test
  void i2osp_singleByteZero() {
    assertThat(ByteUtils.I2OSP(0, 1)).isEqualTo(new byte[]{0x00});
  }

  /**
   * 2 osp single byte max value.
   */
  @Test
  void i2osp_singleByteMaxValue() {
    assertThat(ByteUtils.I2OSP(255, 1)).isEqualTo(new byte[]{(byte) 0xFF});
  }

  /**
   * 2 osp two byte encoding.
   */
  @Test
  void i2osp_twoByteEncoding() {
    // 256 = 0x0100
    assertThat(ByteUtils.I2OSP(256, 2)).isEqualTo(new byte[]{0x01, 0x00});
  }

  /**
   * 2 osp two byte zero.
   */
  @Test
  void i2osp_twoByteZero() {
    assertThat(ByteUtils.I2OSP(0, 2)).isEqualTo(new byte[]{0x00, 0x00});
  }

  /**
   * 2 osp zero length with zero value.
   */
  @Test
  void i2osp_zeroLengthWithZeroValue() {
    // length=0, loop does not execute, result is empty array
    assertThat(ByteUtils.I2OSP(0, 0)).isEmpty();
  }

  /**
   * 2 osp negative value throws.
   */
  @Test
  void i2osp_negativeValueThrows() {
    // value < 0 branch
    assertThatThrownBy(() -> ByteUtils.I2OSP(-1, 1))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("Value too large for specified length");
  }

  /**
   * 2 osp value too large for length throws.
   */
  @Test
  void i2osp_valueTooLargeForLengthThrows() {
    // value >= (1L << (8 * length)) branch: 256 does not fit in 1 byte
    assertThatThrownBy(() -> ByteUtils.I2OSP(256, 1))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("Value too large for specified length");
  }

  // ─── concat ───────────────────────────────────────────────────────────────

  /**
   * Concat no arrays returns empty.
   */
  @Test
  void concat_noArraysReturnsEmpty() {
    // Both loops execute 0 times
    assertThat(ByteUtils.concat()).isEmpty();
  }

  /**
   * Concat single array.
   */
  @Test
  void concat_singleArray() {
    byte[] a = {1, 2, 3};
    assertThat(ByteUtils.concat(a)).isEqualTo(new byte[]{1, 2, 3});
  }

  /**
   * Concat two arrays.
   */
  @Test
  void concat_twoArrays() {
    byte[] a = {1, 2};
    byte[] b = {3, 4};
    assertThat(ByteUtils.concat(a, b)).isEqualTo(new byte[]{1, 2, 3, 4});
  }

  /**
   * Concat three arrays.
   */
  @Test
  void concat_threeArrays() {
    byte[] a = {1};
    byte[] b = {2};
    byte[] c = {3};
    assertThat(ByteUtils.concat(a, b, c)).isEqualTo(new byte[]{1, 2, 3});
  }

  /**
   * Concat empty array among others.
   */
  @Test
  void concat_emptyArrayAmongOthers() {
    byte[] a = {1, 2};
    byte[] empty = {};
    byte[] b = {3, 4};
    assertThat(ByteUtils.concat(a, empty, b)).isEqualTo(new byte[]{1, 2, 3, 4});
  }

  /**
   * Concat all empty arrays.
   */
  @Test
  void concat_allEmptyArrays() {
    assertThat(ByteUtils.concat(new byte[0], new byte[0])).isEmpty();
  }

  /**
   * Concat does not mutate inputs.
   */
  @Test
  void concat_doesNotMutateInputs() {
    byte[] a = {1, 2};
    byte[] b = {3, 4};
    byte[] result = ByteUtils.concat(a, b);
    result[0] = 99;
    assertThat(a[0]).isEqualTo((byte) 1);
  }

  // ─── xor ────────────────────────────────────────────────────────────────────

  /**
   * Xor basic operation.
   */
  @Test
  void xor_basicOperation() {
    byte[] a = {(byte) 0xFF, 0x00, 0x0F};
    byte[] b = {(byte) 0x0F, (byte) 0xF0, (byte) 0xFF};
    assertThat(ByteUtils.xor(a, b)).isEqualTo(new byte[]{(byte) 0xF0, (byte) 0xF0, (byte) 0xF0});
  }

  /**
   * Xor with zeros is identity.
   */
  @Test
  void xor_withZerosIsIdentity() {
    byte[] a = {1, 2, 3};
    byte[] zeros = {0, 0, 0};
    assertThat(ByteUtils.xor(a, zeros)).isEqualTo(a);
  }

  /**
   * Xor with self is zero.
   */
  @Test
  void xor_withSelfIsZero() {
    byte[] a = {(byte) 0xAB, (byte) 0xCD, (byte) 0xEF};
    assertThat(ByteUtils.xor(a, a)).isEqualTo(new byte[]{0, 0, 0});
  }

  /**
   * Xor empty arrays.
   */
  @Test
  void xor_emptyArrays() {
    assertThat(ByteUtils.xor(new byte[0], new byte[0])).isEmpty();
  }

  /**
   * Xor unequal lengths throws.
   */
  @Test
  void xor_unequalLengthsThrows() {
    assertThatThrownBy(() -> ByteUtils.xor(new byte[]{1, 2}, new byte[]{1}))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("equal length");
  }

  /**
   * Xor does not mutate inputs.
   */
  @Test
  void xor_doesNotMutateInputs() {
    byte[] a = {1, 2};
    byte[] b = {3, 4};
    ByteUtils.xor(a, b);
    assertThat(a).isEqualTo(new byte[]{1, 2});
    assertThat(b).isEqualTo(new byte[]{3, 4});
  }

  // ─── dhECDH ─────────────────────────────────────────────────────────────────

  /**
   * Dh ecdh returns compressed point.
   */
  @Test
  void dhECDH_returnsCompressedPoint() {
    ECNamedCurveParameterSpec spec = ECNamedCurveTable.getParameterSpec("secp256r1");
    ECPoint generator = spec.getG();
    BigInteger scalar = BigInteger.valueOf(42);

    byte[] result = ByteUtils.dhECDH(scalar, generator);

    // Compressed SEC1 P-256 point is 33 bytes, starting with 0x02 or 0x03
    assertThat(result).hasSize(33);
    assertThat(result[0]).isIn((byte) 0x02, (byte) 0x03);
  }

  /**
   * Dh ecdh is consistent with direct multiply.
   */
  @Test
  void dhECDH_isConsistentWithDirectMultiply() {
    ECNamedCurveParameterSpec spec = ECNamedCurveTable.getParameterSpec("secp256r1");
    ECPoint generator = spec.getG();
    BigInteger scalar = BigInteger.valueOf(12345);

    byte[] result = ByteUtils.dhECDH(scalar, generator);
    byte[] expected = generator.multiply(scalar).normalize().getEncoded(true);

    assertThat(result).isEqualTo(expected);
  }

  /**
   * Dh ecdh different scalars produce different results.
   */
  @Test
  void dhECDH_differentScalarsProduceDifferentResults() {
    ECNamedCurveParameterSpec spec = ECNamedCurveTable.getParameterSpec("secp256r1");
    ECPoint generator = spec.getG();

    byte[] result1 = ByteUtils.dhECDH(BigInteger.valueOf(1), generator);
    byte[] result2 = ByteUtils.dhECDH(BigInteger.valueOf(2), generator);

    assertThat(result1).isNotEqualTo(result2);
  }

  /**
   * Dh ecdh commutativity.
   */
  @Test
  void dhECDH_commutativity() {
    // DH commutativity: (a * G) * b == (b * G) * a
    ECNamedCurveParameterSpec spec = ECNamedCurveTable.getParameterSpec("secp256r1");
    ECPoint generator = spec.getG();
    BigInteger a = BigInteger.valueOf(7);
    BigInteger b = BigInteger.valueOf(13);

    ECPoint aG = generator.multiply(a).normalize();
    ECPoint bG = generator.multiply(b).normalize();

    byte[] abG = ByteUtils.dhECDH(b, aG);
    byte[] baG = ByteUtils.dhECDH(a, bG);

    assertThat(abG).isEqualTo(baG);
  }

  // ─── scalarToFixedBytes ─────────────────────────────────────────────────────
  //
  // Public, static, and previously untested. It exists to be branch-free on the scalar's value,
  // which is why it always routes through a length+1 intermediate rather than trimming a sign
  // byte conditionally — so the cases below are chosen to cover the shapes toByteArray() returns:
  // shorter than length, exactly length, and length+1 with a leading sign byte.

  @Test
  void scalarToFixedBytes_padsAShortScalarOnTheLeft() {
    assertThat(ByteUtils.scalarToFixedBytes(BigInteger.valueOf(1), 4))
        .isEqualTo(new byte[]{0x00, 0x00, 0x00, 0x01});
  }

  @Test
  void scalarToFixedBytes_zeroIsAllZeroes() {
    assertThat(ByteUtils.scalarToFixedBytes(BigInteger.ZERO, 4))
        .isEqualTo(new byte[]{0x00, 0x00, 0x00, 0x00});
  }

  /**
   * The case the length+1 intermediate exists for: a scalar whose high bit is set makes
   * {@code toByteArray()} prepend a 0x00 sign byte, so the raw form is one byte longer than the
   * target. The sign byte must be dropped, not shifted into the output.
   */
  @Test
  void scalarToFixedBytes_dropsTheSignByteWhenTheHighBitIsSet() {
    BigInteger highBitSet = new BigInteger(1, new byte[]{(byte) 0xFF, 0x02, 0x03, 0x04});

    assertThat(ByteUtils.scalarToFixedBytes(highBitSet, 4))
        .isEqualTo(new byte[]{(byte) 0xFF, 0x02, 0x03, 0x04});
  }

  @Test
  void scalarToFixedBytes_exactLengthScalarIsUnchanged() {
    BigInteger value = new BigInteger(1, new byte[]{0x01, 0x02, 0x03, 0x04});

    assertThat(ByteUtils.scalarToFixedBytes(value, 4))
        .isEqualTo(new byte[]{0x01, 0x02, 0x03, 0x04});
  }

  /**
   * Records what happens to an over-long scalar, which is currently an unchecked
   * {@link ArrayIndexOutOfBoundsException} rather than a validated rejection: the arraycopy
   * destination offset is {@code length + 1 - raw.length}, which goes negative once the scalar
   * needs more than {@code length + 1} bytes.
   *
   * <p>Every in-tree caller passes a scalar already reduced mod the group order, so this is not
   * reachable through the library today. It is pinned rather than fixed because the method is
   * public and the behaviour should be a deliberate choice: if it ever becomes an
   * {@link IllegalArgumentException}, this test is where that decision gets recorded.
   */
  @Test
  void scalarToFixedBytes_overLongScalarThrowsRatherThanTruncating() {
    BigInteger tooWide = BigInteger.ONE.shiftLeft(8 * 33);

    assertThatThrownBy(() -> ByteUtils.scalarToFixedBytes(tooWide, 32))
        .isInstanceOf(ArrayIndexOutOfBoundsException.class);
  }

  // ─── isAllZero ──────────────────────────────────────────────────────────────
  //
  // The pre-check callers use to refuse the ristretto255 identity with their own exception type.

  @Test
  void isAllZero_trueForAnAllZeroBuffer() {
    assertThat(ByteUtils.isAllZero(new byte[32])).isTrue();
  }

  @Test
  void isAllZero_trueForAnEmptyBuffer() {
    assertThat(ByteUtils.isAllZero(new byte[0])).isTrue();
  }

  @Test
  void isAllZero_falseWhenAnyByteIsSet() {
    byte[] lastByteSet = new byte[32];
    lastByteSet[31] = 1;
    byte[] firstByteSet = new byte[32];
    firstByteSet[0] = 1;

    assertThat(ByteUtils.isAllZero(lastByteSet)).isFalse();
    assertThat(ByteUtils.isAllZero(firstByteSet)).isFalse();
  }
}
