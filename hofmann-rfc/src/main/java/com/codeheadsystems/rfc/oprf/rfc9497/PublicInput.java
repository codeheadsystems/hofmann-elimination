package com.codeheadsystems.rfc.oprf.rfc9497;

import com.codeheadsystems.rfc.common.ByteUtils;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;

/**
 * The POPRF public input and the scalar it frames to (RFC 9497 §3.3.3).
 * <p>
 * Both client and server derive {@code m = HashToScalar("Info" || I2OSP(len(info), 2) || info)}
 * and must reach the same value, so the framing lives in one place rather than being written twice.
 */
public final class PublicInput {

  private static final byte[] INFO_LABEL = "Info".getBytes(StandardCharsets.UTF_8);

  /**
   * Largest permitted public input.
   * <p>
   * RFC 9497 §5.1 caps {@code PublicInput} below {@code 2^16 - 1} bytes. {@link ByteUtils#I2OSP}
   * would itself reject anything at or above {@code 2^16}, but relying on that is one byte adrift
   * of the specified bound and depends on an incidental throw from a length-encoding helper rather
   * than a stated rule.
   */
  public static final int MAX_LENGTH = 65534;

  private PublicInput() {
  }

  /**
   * Derives the info scalar {@code m}.
   *
   * @param suite the cipher suite, which must be in POPRF mode
   * @param info  the public input
   * @return the scalar
   */
  public static BigInteger toScalar(final OprfCipherSuite suite, final byte[] info) {
    validate(info);
    byte[] framedInfo = ByteUtils.concat(
        INFO_LABEL,
        ByteUtils.I2OSP(info.length, 2),
        info);
    return suite.hashToScalar(framedInfo, suite.hashToScalarDst());
  }

  /**
   * Rejects a public input the protocol cannot encode.
   *
   * @param info the public input
   */
  public static void validate(final byte[] info) {
    if (info == null) {
      throw new IllegalArgumentException("Public input is required; use an empty array for none");
    }
    if (info.length > MAX_LENGTH) {
      throw new IllegalArgumentException(
          "Public input of " + info.length + " bytes exceeds the maximum of " + MAX_LENGTH);
    }
  }
}
