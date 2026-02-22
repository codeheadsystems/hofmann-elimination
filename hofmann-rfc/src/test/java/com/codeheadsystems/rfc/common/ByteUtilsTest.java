package com.codeheadsystems.rfc.common;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.lang.reflect.Constructor;
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
}
