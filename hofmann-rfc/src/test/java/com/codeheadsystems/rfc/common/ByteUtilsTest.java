package com.codeheadsystems.rfc.common;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.lang.reflect.Constructor;
import java.math.BigInteger;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.math.ec.ECPoint;
import org.junit.jupiter.api.Test;

class ByteUtilsTest {

  // ─── Constructor ──────────────────────────────────────────────────────────

  @Test
  void privateConstructorIsInaccessible() throws Exception {
    Constructor<ByteUtils> ctor = ByteUtils.class.getDeclaredConstructor();
    ctor.setAccessible(true);
    ctor.newInstance(); // covers the private constructor line
  }

  // ─── I2OSP ────────────────────────────────────────────────────────────────

  @Test
  void i2osp_singleByteZero() {
    assertThat(ByteUtils.I2OSP(0, 1)).isEqualTo(new byte[]{0x00});
  }

  @Test
  void i2osp_singleByteMaxValue() {
    assertThat(ByteUtils.I2OSP(255, 1)).isEqualTo(new byte[]{(byte) 0xFF});
  }

  @Test
  void i2osp_twoByteEncoding() {
    // 256 = 0x0100
    assertThat(ByteUtils.I2OSP(256, 2)).isEqualTo(new byte[]{0x01, 0x00});
  }

  @Test
  void i2osp_twoByteZero() {
    assertThat(ByteUtils.I2OSP(0, 2)).isEqualTo(new byte[]{0x00, 0x00});
  }

  @Test
  void i2osp_zeroLengthWithZeroValue() {
    // length=0, loop does not execute, result is empty array
    assertThat(ByteUtils.I2OSP(0, 0)).isEmpty();
  }

  @Test
  void i2osp_negativeValueThrows() {
    // value < 0 branch
    assertThatThrownBy(() -> ByteUtils.I2OSP(-1, 1))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("Value too large for specified length");
  }

  @Test
  void i2osp_valueTooLargeForLengthThrows() {
    // value >= (1L << (8 * length)) branch: 256 does not fit in 1 byte
    assertThatThrownBy(() -> ByteUtils.I2OSP(256, 1))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("Value too large for specified length");
  }

  // ─── concat ───────────────────────────────────────────────────────────────

  @Test
  void concat_noArraysReturnsEmpty() {
    // Both loops execute 0 times
    assertThat(ByteUtils.concat()).isEmpty();
  }

  @Test
  void concat_singleArray() {
    byte[] a = {1, 2, 3};
    assertThat(ByteUtils.concat(a)).isEqualTo(new byte[]{1, 2, 3});
  }

  @Test
  void concat_twoArrays() {
    byte[] a = {1, 2};
    byte[] b = {3, 4};
    assertThat(ByteUtils.concat(a, b)).isEqualTo(new byte[]{1, 2, 3, 4});
  }

  @Test
  void concat_threeArrays() {
    byte[] a = {1};
    byte[] b = {2};
    byte[] c = {3};
    assertThat(ByteUtils.concat(a, b, c)).isEqualTo(new byte[]{1, 2, 3});
  }

  @Test
  void concat_emptyArrayAmongOthers() {
    byte[] a = {1, 2};
    byte[] empty = {};
    byte[] b = {3, 4};
    assertThat(ByteUtils.concat(a, empty, b)).isEqualTo(new byte[]{1, 2, 3, 4});
  }

  @Test
  void concat_allEmptyArrays() {
    assertThat(ByteUtils.concat(new byte[0], new byte[0])).isEmpty();
  }

  @Test
  void concat_doesNotMutateInputs() {
    byte[] a = {1, 2};
    byte[] b = {3, 4};
    byte[] result = ByteUtils.concat(a, b);
    result[0] = 99;
    assertThat(a[0]).isEqualTo((byte) 1);
  }

  // ─── xor ────────────────────────────────────────────────────────────────────

  @Test
  void xor_basicOperation() {
    byte[] a = {(byte) 0xFF, 0x00, 0x0F};
    byte[] b = {(byte) 0x0F, (byte) 0xF0, (byte) 0xFF};
    assertThat(ByteUtils.xor(a, b)).isEqualTo(new byte[]{(byte) 0xF0, (byte) 0xF0, (byte) 0xF0});
  }

  @Test
  void xor_withZerosIsIdentity() {
    byte[] a = {1, 2, 3};
    byte[] zeros = {0, 0, 0};
    assertThat(ByteUtils.xor(a, zeros)).isEqualTo(a);
  }

  @Test
  void xor_withSelfIsZero() {
    byte[] a = {(byte) 0xAB, (byte) 0xCD, (byte) 0xEF};
    assertThat(ByteUtils.xor(a, a)).isEqualTo(new byte[]{0, 0, 0});
  }

  @Test
  void xor_emptyArrays() {
    assertThat(ByteUtils.xor(new byte[0], new byte[0])).isEmpty();
  }

  @Test
  void xor_unequalLengthsThrows() {
    assertThatThrownBy(() -> ByteUtils.xor(new byte[]{1, 2}, new byte[]{1}))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("equal length");
  }

  @Test
  void xor_doesNotMutateInputs() {
    byte[] a = {1, 2};
    byte[] b = {3, 4};
    ByteUtils.xor(a, b);
    assertThat(a).isEqualTo(new byte[]{1, 2});
    assertThat(b).isEqualTo(new byte[]{3, 4});
  }

  // ─── dhECDH ─────────────────────────────────────────────────────────────────

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

  @Test
  void dhECDH_isConsistentWithDirectMultiply() {
    ECNamedCurveParameterSpec spec = ECNamedCurveTable.getParameterSpec("secp256r1");
    ECPoint generator = spec.getG();
    BigInteger scalar = BigInteger.valueOf(12345);

    byte[] result = ByteUtils.dhECDH(scalar, generator);
    byte[] expected = generator.multiply(scalar).normalize().getEncoded(true);

    assertThat(result).isEqualTo(expected);
  }

  @Test
  void dhECDH_differentScalarsProduceDifferentResults() {
    ECNamedCurveParameterSpec spec = ECNamedCurveTable.getParameterSpec("secp256r1");
    ECPoint generator = spec.getG();

    byte[] result1 = ByteUtils.dhECDH(BigInteger.valueOf(1), generator);
    byte[] result2 = ByteUtils.dhECDH(BigInteger.valueOf(2), generator);

    assertThat(result1).isNotEqualTo(result2);
  }

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
}
