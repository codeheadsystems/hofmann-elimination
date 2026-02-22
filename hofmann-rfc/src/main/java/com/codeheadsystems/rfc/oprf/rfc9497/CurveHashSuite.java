package com.codeheadsystems.rfc.oprf.rfc9497;

/**
 * Supported curve and hash function combinations for OPRF.
 */
public enum CurveHashSuite {

  /**
   * P 256 sha 256 curve hash suite.
   */
  P256_SHA256,
  /**
   * P 384 sha 384 curve hash suite.
   */
  P384_SHA384,
  /**
   * P 521 sha 512 curve hash suite.
   */
  P521_SHA512

}
