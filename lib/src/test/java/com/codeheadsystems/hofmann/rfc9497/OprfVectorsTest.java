package com.codeheadsystems.hofmann.rfc9497;

import static org.assertj.core.api.Assertions.assertThat;

import com.codeheadsystems.hofmann.Curve;
import com.codeheadsystems.hofmann.EcUtilities;
import com.codeheadsystems.hofmann.rfc9380.HashToCurve;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import org.bouncycastle.math.ec.ECPoint;
import org.junit.jupiter.api.Test;

/**
 * Test vectors from RFC 9497 Appendix A.1.1: OPRF(P-256, SHA-256) mode 0.
 * <p>
 * Seed = a3a3...a3 (32 bytes)
 * Info = "test key" (hex: 74657374206b6579)
 * skSm = 159749d750713afe245d2d39ccfaae8381c53ce92d098a9375ee70739c7ac0bf
 */
public class OprfVectorsTest {

  // Derived key from RFC 9497 Appendix A.1.1
  private static final BigInteger SK_S = new BigInteger(
      "159749d750713afe245d2d39ccfaae8381c53ce92d098a9375ee70739c7ac0bf", 16);

  @Test
  void testDeriveKeyPair() {
    byte[] seed = new byte[32];
    Arrays.fill(seed, (byte) 0xa3);
    byte[] info = "test key".getBytes(StandardCharsets.UTF_8);

    BigInteger skS = OprfSuite.deriveKeyPair(seed, info);

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
    ECPoint P = HashToCurve.forP256(Curve.P256_CURVE.params())
        .hashToCurve(input, OprfSuite.HASH_TO_GROUP_DST);

    // Client: blind
    ECPoint blindedElement = P.multiply(blind).normalize();

    // Server: evaluate
    ECPoint evaluatedElement = blindedElement.multiply(SK_S).normalize();

    // Client: finalize
    byte[] output = OprfSuite.finalize(input, blind, evaluatedElement);

    assertThat(EcUtilities.BYTES_TO_HEX(output))
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
    ECPoint P = HashToCurve.forP256(Curve.P256_CURVE.params())
        .hashToCurve(input, OprfSuite.HASH_TO_GROUP_DST);

    // Client: blind
    ECPoint blindedElement = P.multiply(blind).normalize();

    // Server: evaluate
    ECPoint evaluatedElement = blindedElement.multiply(SK_S).normalize();

    // Client: finalize
    byte[] output = OprfSuite.finalize(input, blind, evaluatedElement);

    assertThat(EcUtilities.BYTES_TO_HEX(output))
        .isEqualTo("c748ca6dd327f0ce85f4ae3a8cd6d4d5390bbb804c9e12dcf94f853fece3dcce");
  }
}
