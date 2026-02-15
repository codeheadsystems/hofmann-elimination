package com.codeheadsystems.hofmann.rfc9380;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.charset.StandardCharsets;
import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.Test;

/**
 * Test vectors for expand_message_xmd(SHA-256) from RFC 9380.
 *
 * <p>Appendix K.1 covers the standard DST case. Appendix K.2 covers the long DST case
 * (DST > 255 bytes), which exercises the H2C-OVERSIZE-DST- hashing path in
 * {@link ExpandMessageXmd}.
 */
public class ExpandMessageXmdTest {

  // RFC 9380 Appendix K.1 DST
  private static final String STANDARD_DST = "QUUX-V01-CS02-with-expander-SHA256-128";

  // RFC 9380 Appendix K.2 DST — 256 bytes (> 255), triggers the oversize DST path
  private static final String LONG_DST;

  static {
    StringBuilder sb = new StringBuilder("QUUX-V01-CS02-with-expander-SHA256-128-long-DST-");
    for (int i = 0; i < 208; i++) {
      sb.append('1');
    }
    LONG_DST = sb.toString();
  }

  // --- RFC 9380 Appendix K.1: standard DST, len_in_bytes = 32 ---

  @Test
  void expandXmd_standardDst_emptyMsg_32bytes() {
    byte[] result = expand("", STANDARD_DST, 32);
    assertThat(Hex.toHexString(result))
        .isEqualTo("68a985b87eb6b46952128911f2a4412bbc302a9d759667f87f7a21d803f07235");
  }

  @Test
  void expandXmd_standardDst_abc_32bytes() {
    byte[] result = expand("abc", STANDARD_DST, 32);
    assertThat(Hex.toHexString(result))
        .isEqualTo("d8ccab23b5985ccea865c6c97b6e5b8350e794e603b4b97902f53a8a0d605615");
  }

  @Test
  void expandXmd_standardDst_abcdef0123456789_32bytes() {
    byte[] result = expand("abcdef0123456789", STANDARD_DST, 32);
    assertThat(Hex.toHexString(result))
        .isEqualTo("eff31487c770a893cfb36f912fbfcbff40d5661771ca4b2cb4eafe524333f5c1");
  }

  @Test
  void expandXmd_standardDst_q128_32bytes() {
    StringBuilder sb = new StringBuilder("q128_");
    for (int i = 0; i < 128; i++) sb.append('q');
    byte[] result = expand(sb.toString(), STANDARD_DST, 32);
    assertThat(Hex.toHexString(result))
        .isEqualTo("b23a1d2b4d97b2ef7785562a7e8bac7eed54ed6e97e29aa51bfe3f12ddad1ff9");
  }

  @Test
  void expandXmd_standardDst_a512_32bytes() {
    StringBuilder sb = new StringBuilder("a512_");
    for (int i = 0; i < 512; i++) sb.append('a');
    byte[] result = expand(sb.toString(), STANDARD_DST, 32);
    assertThat(Hex.toHexString(result))
        .isEqualTo("4623227bcc01293b8c130bf771da8c298dede7383243dc0993d2d94823958c4c");
  }

  // --- RFC 9380 Appendix K.1: standard DST, len_in_bytes = 128 ---

  @Test
  void expandXmd_standardDst_emptyMsg_128bytes() {
    byte[] result = expand("", STANDARD_DST, 128);
    assertThat(Hex.toHexString(result))
        .isEqualTo(
            "af84c27ccfd45d41914fdff5df25293e221afc53d8ad2ac06d5e3e29485dadbee0d121587713a3e0dd4d5e69e93eb7cd4"
                + "f5df4cd103e188cf60cb02edc3edf18eda8576c412b18ffb658e3dd6ec849469b979d444cf7b26911a08e63cf31f9dcc54"
                + "1708d3491184472c2c29bb749d4286b004ceb5ee6b9a7fa5b646c993f0ced");
  }

  @Test
  void expandXmd_standardDst_abc_128bytes() {
    byte[] result = expand("abc", STANDARD_DST, 128);
    assertThat(Hex.toHexString(result))
        .isEqualTo(
            "abba86a6129e366fc877aab32fc4ffc70120d8996c88aee2fe4b32d6c7b6437a647e6c3163d40b76a73cf6a5674ef1d89"
                + "0f95b664ee0afa5359a5c4e07985635bbecbac65d747d3d2da7ec2b8221b17b0ca9dc8a1ac1c07ea6a1e60583e2cb0005"
                + "8e77b7b72a298425cd1b941ad4ec65e8afc50303a22c0f99b0509b4c895f40");
  }

  @Test
  void expandXmd_standardDst_abcdef0123456789_128bytes() {
    byte[] result = expand("abcdef0123456789", STANDARD_DST, 128);
    assertThat(Hex.toHexString(result))
        .isEqualTo(
            "ef904a29bffc4cf9ee82832451c946ac3c8f8058ae97d8d629831a74c6572bd9ebd0df635cd1f208e2038e760c4994984c"
                + "e73f0d55ea9f22af83ba4734569d4bc95e18350f740c07eef653cbb9f87910d833751825f0ebefa1abe5420bb52be14cf"
                + "489b37fe1a72f7de2d10be453b2c9d9eb20c7e3f6edc5a60629178d9478df");
  }

  @Test
  void expandXmd_standardDst_q128_128bytes() {
    StringBuilder sb = new StringBuilder("q128_");
    for (int i = 0; i < 128; i++) sb.append('q');
    byte[] result = expand(sb.toString(), STANDARD_DST, 128);
    assertThat(Hex.toHexString(result))
        .isEqualTo(
            "80be107d0884f0d881bb460322f0443d38bd222db8bd0b0a5312a6fedb49c1bbd88fd75d8b9a09486c60123dfa1d73c1cc"
                + "3169761b17476d3c6b7cbbd727acd0e2c942f4dd96ae3da5de368d26b32286e32de7e5a8cb2949f866a0b80c58116b29"
                + "fa7fabb3ea7d520ee603e0c25bcaf0b9a5e92ec6a1fe4e0391d1cdbce8c68a");
  }

  @Test
  void expandXmd_standardDst_a512_128bytes() {
    StringBuilder sb = new StringBuilder("a512_");
    for (int i = 0; i < 512; i++) sb.append('a');
    byte[] result = expand(sb.toString(), STANDARD_DST, 128);
    assertThat(Hex.toHexString(result))
        .isEqualTo(
            "546aff5444b5b79aa6148bd81728704c32decb73a3ba76e9e75885cad9def1d06d6792f8a7d12794e90efed817d96920d7"
                + "28896a4510864370c207f99bd4a608ea121700ef01ed879745ee3e4ceef777eda6d9e5e38b90c86ea6fb0b36504ba4a45"
                + "d22e86f6db5dd43d98a294bebb9125d5b794e9d2a81181066eb954966a487");
  }

  // --- RFC 9380 Appendix K.2: long DST (256 bytes), len_in_bytes = 32 ---

  @Test
  void expandXmd_longDst_emptyMsg_32bytes() {
    byte[] result = expand("", LONG_DST, 32);
    assertThat(Hex.toHexString(result))
        .isEqualTo("e8dc0c8b686b7ef2074086fbdd2f30e3f8bfbd3bdf177f73f04b97ce618a3ed3");
  }

  @Test
  void expandXmd_longDst_abc_32bytes() {
    byte[] result = expand("abc", LONG_DST, 32);
    assertThat(Hex.toHexString(result))
        .isEqualTo("52dbf4f36cf560fca57dedec2ad924ee9c266341d8f3d6afe5171733b16bbb12");
  }

  @Test
  void expandXmd_longDst_abcdef0123456789_32bytes() {
    byte[] result = expand("abcdef0123456789", LONG_DST, 32);
    assertThat(Hex.toHexString(result))
        .isEqualTo("35387dcf22618f3728e6c686490f8b431f76550b0b2c61cbc1ce7001536f4521");
  }

  @Test
  void expandXmd_longDst_q128_32bytes() {
    StringBuilder sb = new StringBuilder("q128_");
    for (int i = 0; i < 128; i++) sb.append('q');
    byte[] result = expand(sb.toString(), LONG_DST, 32);
    assertThat(Hex.toHexString(result))
        .isEqualTo("01b637612bb18e840028be900a833a74414140dde0c4754c198532c3a0ba42bc");
  }

  @Test
  void expandXmd_longDst_a512_32bytes() {
    StringBuilder sb = new StringBuilder("a512_");
    for (int i = 0; i < 512; i++) sb.append('a');
    byte[] result = expand(sb.toString(), LONG_DST, 32);
    assertThat(Hex.toHexString(result))
        .isEqualTo("20cce7033cabc5460743180be6fa8aac5a103f56d481cf369a8accc0c374431b");
  }

  // --- RFC 9380 Appendix K.2: long DST (256 bytes), len_in_bytes = 128 ---

  @Test
  void expandXmd_longDst_emptyMsg_128bytes() {
    byte[] result = expand("", LONG_DST, 128);
    assertThat(Hex.toHexString(result))
        .isEqualTo(
            "14604d85432c68b757e485c8894db3117992fc57e0e136f71ad987f789a0abc287c47876978e2388a02af86b1e8d1342e5"
                + "ce4f7aaa07a87321e691f6fba7e0072eecc1218aebb89fb14a0662322d5edbd873f0eb35260145cd4e64f748c5dfe6056"
                + "7e126604bcab1a3ee2dc0778102ae8a5cfd1429ebc0fa6bf1a53c36f55dfc");
  }

  @Test
  void expandXmd_longDst_abc_128bytes() {
    byte[] result = expand("abc", LONG_DST, 128);
    assertThat(Hex.toHexString(result))
        .isEqualTo(
            "1a30a5e36fbdb87077552b9d18b9f0aee16e80181d5b951d0471d55b66684914aef87dbb3626eaabf5ded8cd0686567e50"
                + "3853e5c84c259ba0efc37f71c839da2129fe81afdaec7fbdc0ccd4c794727a17c0d20ff0ea55e1389d6982d1241cb8d16"
                + "5762dbc39fb0cee4474d2cbbd468a835ae5b2f20e4f959f56ab24cd6fe267");
  }

  @Test
  void expandXmd_longDst_abcdef0123456789_128bytes() {
    byte[] result = expand("abcdef0123456789", LONG_DST, 128);
    assertThat(Hex.toHexString(result))
        .isEqualTo(
            "d2ecef3635d2397f34a9f86438d772db19ffe9924e28a1caf6f1c8f15603d4028f40891044e5c7e39ebb9b31339979ff33"
                + "a4249206f67d4a1e7c765410bcd249ad78d407e303675918f20f26ce6d7027ed3774512ef5b00d816e51bfcc96c353960"
                + "1fa48ef1c07e494bdc37054ba96ecb9dbd666417e3de289d4f424f502a982");
  }

  @Test
  void expandXmd_longDst_q128_128bytes() {
    StringBuilder sb = new StringBuilder("q128_");
    for (int i = 0; i < 128; i++) sb.append('q');
    byte[] result = expand(sb.toString(), LONG_DST, 128);
    assertThat(Hex.toHexString(result))
        .isEqualTo(
            "ed6e8c036df90111410431431a232d41a32c86e296c05d426e5f44e75b9a50d335b2412bc6c91e0a6dc131de09c43110d9"
                + "180d0a70f0d6289cb4e43b05f7ee5e9b3f42a1fad0f31bac6a625b3b5c50e3a83316783b649e5ecc9d3b1d9471cb5024"
                + "b7ccf40d41d1751a04ca0356548bc6e703fca02ab521b505e8e45600508d32");
  }

  @Test
  void expandXmd_longDst_a512_128bytes() {
    StringBuilder sb = new StringBuilder("a512_");
    for (int i = 0; i < 512; i++) sb.append('a');
    byte[] result = expand(sb.toString(), LONG_DST, 128);
    assertThat(Hex.toHexString(result))
        .isEqualTo(
            "78b53f2413f3c688f07732c10e5ced29a17c6a16f717179ffbe38d92d6c9ec296502eb9889af83a1928cd162e845b0d3c5"
                + "424e83280fed3d10cffb2f8431f14e7a23f4c68819d40617589e4c41169d0b56e0e3535be1fd71fbb08bb70c5b5ffed95"
                + "3d6c14bf7618b35fc1f4c4b30538236b4b08c9fbf90462447a8ada60be495");
  }

  private static byte[] expand(String msg, String dst, int lenInBytes) {
    return ExpandMessageXmd.expand(
        msg.getBytes(StandardCharsets.UTF_8),
        dst.getBytes(StandardCharsets.UTF_8),
        lenInBytes);
  }
}
