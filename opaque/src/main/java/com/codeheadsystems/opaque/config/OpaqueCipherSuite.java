package com.codeheadsystems.opaque.config;

import com.codeheadsystems.oprf.rfc9497.OprfCipherSuite;

/**
 * OPAQUE-specific cipher suite wrapper over an OPRF cipher suite.
 * Provides OPAQUE protocol size constants derived from the underlying suite.
 * <p>
 * Supported suites:
 * <ul>
 *   <li>P256_SHA256 — P-256 / SHA-256 (RFC 9807 reference suite)</li>
 *   <li>P384_SHA384 — P-384 / SHA-384</li>
 *   <li>P521_SHA512 — P-521 / SHA-512</li>
 * </ul>
 */
public record OpaqueCipherSuite(OprfCipherSuite oprfSuite) {

  public static final OpaqueCipherSuite P256_SHA256 = new OpaqueCipherSuite(OprfCipherSuite.P256_SHA256);
  public static final OpaqueCipherSuite P384_SHA384 = new OpaqueCipherSuite(OprfCipherSuite.P384_SHA384);
  public static final OpaqueCipherSuite P521_SHA512 = new OpaqueCipherSuite(OprfCipherSuite.P521_SHA512);

  /**
   * Returns the OPAQUE cipher suite for the given name.  Accepted names: {@code "P256_SHA256"},
   * {@code "P384_SHA384"}, {@code "P521_SHA512"}.
   *
   * @throws IllegalArgumentException for unrecognised names
   */
  public static OpaqueCipherSuite fromName(String name) {
    return switch (name) {
      case "P256_SHA256" -> P256_SHA256;
      case "P384_SHA384" -> P384_SHA384;
      case "P521_SHA512" -> P521_SHA512;
      default -> throw new IllegalArgumentException("Unknown OPAQUE cipher suite: " + name
          + ". Valid values: P256_SHA256, P384_SHA384, P521_SHA512");
    };
  }

  /**
   * Compressed public key size in bytes (33, 49, or 67).
   */
  public int Npk() {
    return oprfSuite().elementSize();
  }

  /**
   * Scalar (private key) size in bytes (32, 48, or 66).
   */
  public int Nsk() {
    return (oprfSuite().groupSpec().groupOrder().bitLength() + 7) / 8;
  }

  /**
   * Hash output length in bytes (32, 48, or 64).
   */
  public int Nh() {
    return oprfSuite().hashOutputLength();
  }

  /**
   * MAC output length — equals hash output length.
   */
  public int Nm() {
    return Nh();
  }

  /**
   * HKDF output length — equals hash output length.
   */
  public int Nx() {
    return Nh();
  }

  /**
   * OPRF evaluated element size — equals compressed public key size.
   */
  public int Noe() {
    return Npk();
  }

  /**
   * OPRF key size — equals scalar size.
   */
  public int Nok() {
    return Nsk();
  }

  /**
   * Nonce length — always 32, suite-independent.
   */
  public int Nn() {
    return 32;
  }

  /**
   * Envelope size = Nn + Nm.
   */
  public int envelopeSize() {
    return Nn() + Nm();
  }

  /**
   * Masked response size = Npk + envelopeSize.
   */
  public int maskedResponseSize() {
    return Npk() + envelopeSize();
  }
}
