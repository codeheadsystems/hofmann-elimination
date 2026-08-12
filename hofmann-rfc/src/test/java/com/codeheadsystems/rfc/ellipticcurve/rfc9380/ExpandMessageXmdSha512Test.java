package com.codeheadsystems.rfc.ellipticcurve.rfc9380;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.nio.charset.StandardCharsets;
import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.Test;

/**
 * Test vectors for expand_message_xmd(SHA-512) from RFC 9380 Appendix K.3.
 *
 * <p>These exist because {@link ExpandMessageXmdTest} covers only {@code forSha256()}, and nothing
 * in the library calls that: the sole production consumer of {@link ExpandMessageXmd} is
 * {@link Ristretto255GroupSpec}, which uses {@code forSha512()}. The one hashing pipeline still
 * hand-rolled here rather than delegated to BouncyCastle was therefore the one with no
 * known-answer coverage, and every ristretto255 hash-to-group operation runs through it.
 *
 * <p>{@code forSha384()} remains uncovered, deliberately: RFC 9380 publishes no expand_message_xmd
 * vectors for SHA-384 and no code in this repository calls it.
 */
public class ExpandMessageXmdSha512Test {

  /** RFC 9380 Appendix K.3 DST. */
  private static final String DST = "QUUX-V01-CS02-with-expander-SHA512-256";

  private static byte[] expand(String msg, int lenInBytes) {
    return ExpandMessageXmd.forSha512().expand(
        msg.getBytes(StandardCharsets.UTF_8),
        DST.getBytes(StandardCharsets.UTF_8),
        lenInBytes);
  }

  private static String repeated(String prefix, char c, int count) {
    StringBuilder sb = new StringBuilder(prefix);
    for (int i = 0; i < count; i++) {
      sb.append(c);
    }
    return sb.toString();
  }

  // --- len_in_bytes = 0x20 (32) ---

  @Test
  void expandXmdSha512_emptyMsg_32bytes() {
    assertThat(Hex.toHexString(expand("", 32)))
        .isEqualTo("6b9a7312411d92f921c6f68ca0b6380730a1a4d982c507211a90964c394179ba");
  }

  @Test
  void expandXmdSha512_abc_32bytes() {
    assertThat(Hex.toHexString(expand("abc", 32)))
        .isEqualTo("0da749f12fbe5483eb066a5f595055679b976e93abe9be6f0f6318bce7aca8dc");
  }

  @Test
  void expandXmdSha512_abcdef0123456789_32bytes() {
    assertThat(Hex.toHexString(expand("abcdef0123456789", 32)))
        .isEqualTo("087e45a86e2939ee8b91100af1583c4938e0f5fc6c9db4b107b83346bc967f58");
  }

  @Test
  void expandXmdSha512_q128_32bytes() {
    assertThat(Hex.toHexString(expand(repeated("q128_", 'q', 128), 32)))
        .isEqualTo("7336234ee9983902440f6bc35b348352013becd88938d2afec44311caf8356b3");
  }

  @Test
  void expandXmdSha512_a512_32bytes() {
    assertThat(Hex.toHexString(expand(repeated("a512_", 'a', 512), 32)))
        .isEqualTo("57b5f7e766d5be68a6bfe1768e3c2b7f1228b3e4b3134956dd73a59b954c66f4");
  }

  // --- len_in_bytes = 0x80 (128) ---
  //
  // The multi-block cases: with b_in_bytes = 64, 128 output bytes means ell = 2, so these are the
  // vectors that exercise the b_i chaining loop rather than just b_1.

  @Test
  void expandXmdSha512_emptyMsg_128bytes() {
    assertThat(Hex.toHexString(expand("", 128)))
        .isEqualTo("41b037d1734a5f8df225dd8c7de38f851efdb45c372887be655212d07251b921"
            + "b052b62eaed99b46f72f2ef4cc96bfaf254ebbbec091e1a3b9e4fb5e5b619d2e"
            + "0c5414800a1d882b62bb5cd1778f098b8eb6cb399d5d9d18f5d5842cf5d13d7e"
            + "b00a7cff859b605da678b318bd0e65ebff70bec88c753b159a805d2c89c55961");
  }

  @Test
  void expandXmdSha512_abc_128bytes() {
    assertThat(Hex.toHexString(expand("abc", 128)))
        .isEqualTo("7f1dddd13c08b543f2e2037b14cefb255b44c83cc397c1786d975653e36a6b11"
            + "bdd7732d8b38adb4a0edc26a0cef4bb45217135456e58fbca1703cd6032cb134"
            + "7ee720b87972d63fbf232587043ed2901bce7f22610c0419751c065922b48843"
            + "1851041310ad659e4b23520e1772ab29dcdeb2002222a363f0c2b1c972b3efe1");
  }

  @Test
  void expandXmdSha512_abcdef0123456789_128bytes() {
    assertThat(Hex.toHexString(expand("abcdef0123456789", 128)))
        .isEqualTo("3f721f208e6199fe903545abc26c837ce59ac6fa45733f1baaf0222f8b7acb04"
            + "24814fcb5eecf6c1d38f06e9d0a6ccfbf85ae612ab8735dfdf9ce84c372a77c8"
            + "f9e1c1e952c3a61b7567dd0693016af51d2745822663d0c2367e3f4f0bed827f"
            + "eecc2aaf98c949b5ed0d35c3f1023d64ad1407924288d366ea159f46287e61ac");
  }

  @Test
  void expandXmdSha512_q128_128bytes() {
    assertThat(Hex.toHexString(expand(repeated("q128_", 'q', 128), 128)))
        .isEqualTo("b799b045a58c8d2b4334cf54b78260b45eec544f9f2fb5bd12fb603eaee70db7"
            + "317bf807c406e26373922b7b8920fa29142703dd52bdf280084fb7ef69da78af"
            + "df80b3586395b433dc66cde048a258e476a561e9deba7060af40adf30c64249c"
            + "a7ddea79806ee5beb9a1422949471d267b21bc88e688e4014087a0b592b695ed");
  }

  @Test
  void expandXmdSha512_a512_128bytes() {
    assertThat(Hex.toHexString(expand(repeated("a512_", 'a', 512), 128)))
        .isEqualTo("05b0bfef265dcee87654372777b7c44177e2ae4c13a27f103340d9cd11c86cb2"
            + "426ffcad5bd964080c2aee97f03be1ca18e30a1f14e27bc11ebbd650f305269c"
            + "c9fb1db08bf90bfc79b42a952b46daf810359e7bc36452684784a64952c343c5"
            + "2e5124cd1f71d474d5197fefc571a92929c9084ffe1112cf5eea5192ebff330b");
  }

  // --- input validation, at SHA-512's block size ---

  /**
   * The {@code ell > 255} ceiling moves with the hash: SHA-512's 64-byte blocks put it at
   * {@code 255 * 64 = 16320}, not the 8160 that bounds the SHA-256 expander. Pinning it here
   * catches a hard-coded SHA-256 constant leaking into the shared path.
   */
  @Test
  void expandXmdSha512_rejectsEllOver255() {
    assertThatThrownBy(() -> expand("msg", 16321))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("lenInBytes too large");
  }

  @Test
  void expandXmdSha512_acceptsTheLargestLegalEll() {
    assertThat(expand("msg", 16320)).hasSize(16320);
  }
}
