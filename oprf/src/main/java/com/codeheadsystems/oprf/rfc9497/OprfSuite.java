package com.codeheadsystems.oprf.rfc9497;

import java.math.BigInteger;
import org.bouncycastle.math.ec.ECPoint;

/**
 * RFC 9497 P256-SHA256 OPRF cipher suite implementation (mode 0 = OPRF).
 * <p>
 * Cipher suite: OPRF(P-256, SHA-256)
 * contextString = "OPRFV1-\x00-P256-SHA256"
 * <p>
 * This class delegates to {@link OprfCipherSuite#P256_SHA256} for full backward
 * compatibility. New code should use {@link OprfCipherSuite} directly.
 */
public class OprfSuite {

  // Backward-compatible constants — delegate to the P256-SHA256 suite
  public static final byte[] CONTEXT_STRING     = OprfCipherSuite.P256_SHA256.contextString();
  public static final byte[] HASH_TO_GROUP_DST  = OprfCipherSuite.P256_SHA256.hashToGroupDst();
  public static final byte[] HASH_TO_SCALAR_DST = OprfCipherSuite.P256_SHA256.hashToScalarDst();
  public static final byte[] DERIVE_KEY_PAIR_DST = OprfCipherSuite.P256_SHA256.deriveKeyPairDst();

  private OprfSuite() {}

  /**
   * Hashes input to a scalar modulo the P-256 group order.
   * Delegates to {@link OprfCipherSuite#P256_SHA256}.
   */
  public static BigInteger hashToScalar(byte[] input, byte[] dst) {
    return OprfCipherSuite.P256_SHA256.hashToScalar(input, dst);
  }

  /**
   * Derives a server private key from a seed and info string per RFC 9497 §3.2.1.
   * Delegates to {@link OprfCipherSuite#P256_SHA256}.
   */
  public static BigInteger deriveKeyPair(byte[] seed, byte[] info) {
    return OprfCipherSuite.P256_SHA256.deriveKeyPair(seed, info);
  }

  /**
   * RFC 9497 §3.3.1 Finalize: unblind the evaluated element and produce the OPRF output.
   * Delegates to {@link OprfCipherSuite#P256_SHA256}.
   */
  public static byte[] finalize(byte[] input, BigInteger blind, ECPoint evaluatedElement) {
    return OprfCipherSuite.P256_SHA256.finalize(input, blind, evaluatedElement);
  }
}
