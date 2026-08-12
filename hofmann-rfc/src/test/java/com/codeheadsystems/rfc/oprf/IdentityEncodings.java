package com.codeheadsystems.rfc.oprf;

import com.codeheadsystems.rfc.oprf.rfc9497.CurveHashSuite;
import com.codeheadsystems.rfc.oprf.rfc9497.OprfCipherSuite;

/**
 * The identity element's wire encoding, per suite.
 *
 * <p>This exists because {@code new byte[elementSize()]} is not the identity on three of the four
 * supported suites, and a test that uses it looks like it covers all four while covering one.
 * {@code GroupSpecArithmeticTest} documents the trap: on the SEC1 curves an all-zero buffer of
 * {@code elementSize()} bytes (33, 49 or 67) is rejected as a <em>malformed encoding</em> long
 * before the identity check is reached, so an assertion permissive enough to accept either
 * rejection reason — the usual {@code isInstanceOfAny(SecurityException, IllegalArgumentException)}
 * — passes without ever exercising the path it names.
 *
 * <p>The distinction matters because of what the identity check prevents: {@code blindInv * O = O},
 * so an accepted identity collapses the OPRF output to a function of the input alone, independent
 * of both the blind and the server key. That is a malicious server silently downgrading the OPRF
 * to an unkeyed hash, and ristretto255 — the one suite the all-zero buffer does exercise — is the
 * suite that regressed, because the all-zero encoding is a legitimate ristretto255 encoding that
 * passes the RFC 9496 §4.3.1 decode checks and is caught only by the protocol-layer check.
 *
 * @see com.codeheadsystems.rfc.ellipticcurve.rfc9380.GroupSpecArithmeticTest
 */
public final class IdentityEncodings {

  private IdentityEncodings() {
  }

  /**
   * Returns the encoding of the identity element for the given suite.
   *
   * <p>ristretto255 encodes the identity as 32 zero bytes. SEC1 point compression encodes the
   * point at infinity as the single byte {@code 0x00}, regardless of curve size — so P-256,
   * P-384 and P-521 all use a one-byte encoding rather than an {@code elementSize()}-byte one.
   *
   * @param suite the cipher suite
   * @return a fresh array holding the identity encoding for that suite
   */
  public static byte[] identityFor(final CurveHashSuite suite) {
    return suite == CurveHashSuite.RISTRETTO255_SHA512
        ? new byte[32]
        : new byte[]{0x00};
  }

  /**
   * Returns the encoding of the identity element for the given cipher suite.
   *
   * <p>{@link OprfCipherSuite} exposes no accessor for its {@link CurveHashSuite}, so this
   * discriminates on element size instead: ristretto255 is the only supported suite with a
   * 32-byte element encoding, while the SEC1 curves are 33, 49 and 67 bytes.
   *
   * @param suite the cipher suite
   * @return a fresh array holding the identity encoding for that suite
   */
  public static byte[] identityFor(final OprfCipherSuite suite) {
    return suite.elementSize() == 32
        ? new byte[32]
        : new byte[]{0x00};
  }
}
