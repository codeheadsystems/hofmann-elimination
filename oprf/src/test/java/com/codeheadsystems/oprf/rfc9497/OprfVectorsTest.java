package com.codeheadsystems.oprf.rfc9497;

import static org.assertj.core.api.Assertions.assertThat;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

// Constants verified against RFC 9497 §4.1 and Appendix A

/**
 * Test vectors from RFC 9497 Appendix A: OPRF mode 0.
 * <p>
 * Covers P256-SHA256 (A.1.1), P384-SHA384 (A.2.1), and P521-SHA512 (A.3.1).
 * Seed = a3a3...a3 (32 bytes) and Info = "test key" for all suites.
 */
public class OprfVectorsTest {

  private static final OprfCipherSuite SUITE = OprfCipherSuite.P256_SHA256;

  // Derived key from RFC 9497 Appendix A.1.1
  private static final BigInteger SK_S = new BigInteger(
      "159749d750713afe245d2d39ccfaae8381c53ce92d098a9375ee70739c7ac0bf", 16);

  @Test
  void testDeriveKeyPair() {
    byte[] seed = new byte[32];
    Arrays.fill(seed, (byte) 0xa3);
    byte[] info = "test key".getBytes(StandardCharsets.UTF_8);

    BigInteger skS = SUITE.deriveKeyPair(seed, info);

    assertThat(skS.toString(16))
        .isEqualTo("159749d750713afe245d2d39ccfaae8381c53ce92d098a9375ee70739c7ac0bf");
  }

  @Test
  void testVector1() {
    // RFC 9497 Appendix A.1.1, Test Vector 1
    // Input = 00 (single byte 0x00)
    // Blind = 3338fa65ec36e0290022b48eb562889d89dbfa691d1cde91517fa222ed7ad364
    // Output = a0b34de5fa4c5b6da07e72af73cc507cceeb48981b97b7285fc375345fe495dd

    byte[] input = new byte[]{0x00};
    BigInteger blind = new BigInteger(
        "3338fa65ec36e0290022b48eb562889d89dbfa691d1cde91517fa222ed7ad364", 16);

    // Client: H(input) using RFC 9497 HashToGroup DST
    byte[] P = SUITE.groupSpec().hashToGroup(input, SUITE.hashToGroupDst());

    // Client: blind
    byte[] blindedElement = SUITE.groupSpec().scalarMultiply(blind, P);

    // RFC 9497 A.1.1 Vector 1: BlindedElement (client→server message, 33-byte compressed point)
    assertThat(Hex.toHexString(blindedElement))
        .as("blindedElement")
        .isEqualTo("03723a1e5c09b8b9c18d1dcbca29e8007e95f14f4732d9346d490ffc195110368d");

    // Server: evaluate
    byte[] evaluatedElement = SUITE.groupSpec().scalarMultiply(SK_S, blindedElement);

    // RFC 9497 A.1.1 Vector 1: EvaluationElement (server→client message, 33-byte compressed point)
    assertThat(Hex.toHexString(evaluatedElement))
        .as("evaluationElement")
        .isEqualTo("030de02ffec47a1fd53efcdd1c6faf5bdc270912b8749e783c7ca75bb412958832");

    // Client: finalize
    byte[] output = SUITE.finalize(input, blind, evaluatedElement);

    assertThat(Hex.toHexString(output))
        .isEqualTo("a0b34de5fa4c5b6da07e72af73cc507cceeb48981b97b7285fc375345fe495dd");
  }

  @Test
  void testVector2() {
    // RFC 9497 Appendix A.1.1, Test Vector 2
    // Input = 5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a (17 bytes of 0x5a)
    // Blind = e6d0f1d89ad552e859d708177054aca4695ef33b5d89d4d3f9a2c376e08a1450
    // Output = c748ca6dd327f0ce85f4ae3a8cd6d4d5390bbb804c9e12dcf94f853fece3dcce

    byte[] input = new byte[17];
    Arrays.fill(input, (byte) 0x5a);
    BigInteger blind = new BigInteger(
        "e6d0f1d89ad552e859d708177054aca4695ef33b5d89d4d3f9a2c376e08a1450", 16);

    // Client: H(input) using RFC 9497 HashToGroup DST
    byte[] P = SUITE.groupSpec().hashToGroup(input, SUITE.hashToGroupDst());

    // Client: blind
    byte[] blindedElement = SUITE.groupSpec().scalarMultiply(blind, P);

    // Server: evaluate
    byte[] evaluatedElement = SUITE.groupSpec().scalarMultiply(SK_S, blindedElement);

    // Client: finalize
    byte[] output = SUITE.finalize(input, blind, evaluatedElement);

    assertThat(Hex.toHexString(output))
        .isEqualTo("c748ca6dd327f0ce85f4ae3a8cd6d4d5390bbb804c9e12dcf94f853fece3dcce");
  }

  @Test
  void testP256Constants() {
    // contextString = "OPRFV1-" || I2OSP(0, 1) || "-P256-SHA256" per RFC 9497 §4.1
    // The null byte at position 7 is critical and easily missed in typos.
    assertThat(Hex.toHexString(SUITE.contextString()))
        .isEqualTo("4f50524656312d002d503235362d534841323536");

    // HashToGroup-<contextString>
    assertThat(Hex.toHexString(SUITE.hashToGroupDst()))
        .isEqualTo("48617368546f47726f75702d4f50524656312d002d503235362d534841323536");

    // HashToScalar-<contextString>
    assertThat(Hex.toHexString(SUITE.hashToScalarDst()))
        .isEqualTo("48617368546f5363616c61722d4f50524656312d002d503235362d534841323536");

    // DeriveKeyPair<contextString> — note: no dash between "DeriveKeyPair" and contextString
    assertThat(Hex.toHexString(SUITE.deriveKeyPairDst()))
        .isEqualTo("4465726976654b6579506169724f50524656312d002d503235362d534841323536");
  }

  // ─── RFC 9497 Appendix A.2.1: P384-SHA384 OPRF (mode 0) ─────────────────────

  @Nested
  class P384Sha384 {

    private static final OprfCipherSuite SUITE = OprfCipherSuite.P384_SHA384;

    // skSm from RFC 9497 Appendix A.2.1 (CFRG reference vectors)
    private static final BigInteger SK_S = new BigInteger(
        "dfe7ddc41a4646901184f2b432616c8ba6d452f9bcd0c4f75a5150ef2b2ed02ef40b8b92f60ae591bcabd72a6518f188",
        16);

    @Test
    void testDeriveKeyPair() {
      // Seed = a3a3...a3 (32 bytes), Info = "test key"
      byte[] seed = new byte[32];
      Arrays.fill(seed, (byte) 0xa3);
      byte[] info = "test key".getBytes(StandardCharsets.UTF_8);

      BigInteger skS = SUITE.deriveKeyPair(seed, info);

      assertThat(skS.toString(16))
          .isEqualTo("dfe7ddc41a4646901184f2b432616c8ba6d452f9bcd0c4f75a5150ef2b2ed02ef40b8b92f60ae591bcabd72a6518f188");
    }

    @Test
    void testVector1() {
      // RFC 9497 A.2.1 Test Vector 1: Input = 00 (single byte)
      byte[] input = new byte[]{0x00};
      BigInteger blind = new BigInteger(
          "504650f53df8f16f6861633388936ea23338fa65ec36e0290022b48eb562889d89dbfa691d1cde91517fa222ed7ad364",
          16);

      byte[] P = SUITE.groupSpec().hashToGroup(input, SUITE.hashToGroupDst());
      byte[] blindedElement = SUITE.groupSpec().scalarMultiply(blind, P);

      assertThat(Hex.toHexString(blindedElement))
          .as("blindedElement")
          .isEqualTo("02a36bc90e6db34096346eaf8b7bc40ee1113582155ad3797003ce614c835a874343701d3f2debbd80d97cbe45de6e5f1f");

      byte[] evaluatedElement = SUITE.groupSpec().scalarMultiply(SK_S, blindedElement);

      assertThat(Hex.toHexString(evaluatedElement))
          .as("evaluationElement")
          .isEqualTo("03af2a4fc94770d7a7bf3187ca9cc4faf3732049eded2442ee50fbddda58b70ae2999366f72498cdbc43e6f2fc184afe30");

      byte[] output = SUITE.finalize(input, blind, evaluatedElement);

      assertThat(Hex.toHexString(output))
          .isEqualTo("ed84ad3f31a552f0456e58935fcc0a3039db42e7f356dcb32aa6d487b6b815a07d5813641fb1398c03ddab5763874357");
    }

    @Test
    void testVector2() {
      // RFC 9497 A.2.1 Test Vector 2: Input = 5a5a...5a (17 bytes)
      byte[] input = new byte[17];
      Arrays.fill(input, (byte) 0x5a);
      BigInteger blind = new BigInteger(
          "504650f53df8f16f6861633388936ea23338fa65ec36e0290022b48eb562889d89dbfa691d1cde91517fa222ed7ad364",
          16);

      byte[] P = SUITE.groupSpec().hashToGroup(input, SUITE.hashToGroupDst());
      byte[] blindedElement = SUITE.groupSpec().scalarMultiply(blind, P);

      assertThat(Hex.toHexString(blindedElement))
          .as("blindedElement")
          .isEqualTo("02def6f418e3484f67a124a2ce1bfb19de7a4af568ede6a1ebb2733882510ddd43d05f2b1ab5187936a55e50a847a8b900");

      byte[] evaluatedElement = SUITE.groupSpec().scalarMultiply(SK_S, blindedElement);

      assertThat(Hex.toHexString(evaluatedElement))
          .as("evaluationElement")
          .isEqualTo("034e9b9a2960b536f2ef47d8608b21597ba400d5abfa1825fd21c36b75f927f396bf3716c96129d1fa4a77fa1d479c8d7b");

      byte[] output = SUITE.finalize(input, blind, evaluatedElement);

      assertThat(Hex.toHexString(output))
          .isEqualTo("dd4f29da869ab9355d60617b60da0991e22aaab243a3460601e48b075859d1c526d36597326f1b985778f781a1682e75");
    }
  }

  // ─── RFC 9497 Appendix A.3.1: P521-SHA512 OPRF (mode 0) ─────────────────────

  @Nested
  class P521Sha512 {

    private static final OprfCipherSuite SUITE = OprfCipherSuite.P521_SHA512;

    // skSm from RFC 9497 Appendix A.3.1 (CFRG reference vectors)
    private static final BigInteger SK_S = new BigInteger(
        "0153441b8faedb0340439036d6aed06d1217b34c42f17f8db4c5cc610a4a955d698a688831b16d0dc7713a1aa3611ec60703bffc7dc9c84e3ed673b3dbe1d5fccea6",
        16);

    @Test
    void testDeriveKeyPair() {
      // Seed = a3a3...a3 (32 bytes), Info = "test key"
      byte[] seed = new byte[32];
      Arrays.fill(seed, (byte) 0xa3);
      byte[] info = "test key".getBytes(StandardCharsets.UTF_8);

      BigInteger skS = SUITE.deriveKeyPair(seed, info);

      assertThat(skS.toString(16))
          .isEqualTo("153441b8faedb0340439036d6aed06d1217b34c42f17f8db4c5cc610a4a955d698a688831b16d0dc7713a1aa3611ec60703bffc7dc9c84e3ed673b3dbe1d5fccea6");
    }

    @Test
    void testVector1() {
      // RFC 9497 A.3.1 Test Vector 1: Input = 00 (single byte)
      byte[] input = new byte[]{0x00};
      BigInteger blind = new BigInteger(
          "00d1dccf7a51bafaf75d4a866d53d8cafe4d504650f53df8f16f6861633388936ea23338fa65ec36e0290022b48eb562889d89dbfa691d1cde91517fa222ed7ad364",
          16);

      byte[] P = SUITE.groupSpec().hashToGroup(input, SUITE.hashToGroupDst());
      byte[] blindedElement = SUITE.groupSpec().scalarMultiply(blind, P);

      assertThat(Hex.toHexString(blindedElement))
          .as("blindedElement")
          .isEqualTo("0300e78bf846b0e1e1a3c320e353d758583cd876df56100a3a1e62bacba470fa6e0991be1be80b721c50c5fd0c672ba764457acc18c6200704e9294fbf28859d916351");

      byte[] evaluatedElement = SUITE.groupSpec().scalarMultiply(SK_S, blindedElement);

      assertThat(Hex.toHexString(evaluatedElement))
          .as("evaluationElement")
          .isEqualTo("030166371cf827cb2fb9b581f97907121a16e2dc5d8b10ce9f0ede7f7d76a0d047657735e8ad07bcda824907b3e5479bd72cdef6b839b967ba5c58b118b84d26f2ba07");

      byte[] output = SUITE.finalize(input, blind, evaluatedElement);

      assertThat(Hex.toHexString(output))
          .isEqualTo("26232de6fff83f812adadadb6cc05d7bbeee5dca043dbb16b03488abb9981d0a1ef4351fad52dbd7e759649af393348f7b9717566c19a6b8856284d69375c809");
    }

    @Test
    void testVector2() {
      // RFC 9497 A.3.1 Test Vector 2: Input = 5a5a...5a (17 bytes)
      byte[] input = new byte[17];
      Arrays.fill(input, (byte) 0x5a);
      BigInteger blind = new BigInteger(
          "00d1dccf7a51bafaf75d4a866d53d8cafe4d504650f53df8f16f6861633388936ea23338fa65ec36e0290022b48eb562889d89dbfa691d1cde91517fa222ed7ad364",
          16);

      byte[] P = SUITE.groupSpec().hashToGroup(input, SUITE.hashToGroupDst());
      byte[] blindedElement = SUITE.groupSpec().scalarMultiply(blind, P);

      assertThat(Hex.toHexString(blindedElement))
          .as("blindedElement")
          .isEqualTo("0300c28e57e74361d87e0c1874e5f7cc1cc796d61f9cad50427cf54655cdb455613368d42b27f94bf66f59f53c816db3e95e68e1b113443d66a99b3693bab88afb556b");

      byte[] evaluatedElement = SUITE.groupSpec().scalarMultiply(SK_S, blindedElement);

      assertThat(Hex.toHexString(evaluatedElement))
          .as("evaluationElement")
          .isEqualTo("0301ad453607e12d0cc11a3359332a40c3a254eaa1afc64296528d55bed07ba322e72e22cf3bcb50570fd913cb54f7f09c17aff8787af75f6a7faf5640cbb2d9620a6e");

      byte[] output = SUITE.finalize(input, blind, evaluatedElement);

      assertThat(Hex.toHexString(output))
          .isEqualTo("ad1f76ef939042175e007738906ac0336bbd1d51e287ebaa66901abdd324ea3ffa40bfc5a68e7939c2845e0fd37a5a6e76dadb9907c6cc8579629757fd4d04ba");
    }
  }
}
