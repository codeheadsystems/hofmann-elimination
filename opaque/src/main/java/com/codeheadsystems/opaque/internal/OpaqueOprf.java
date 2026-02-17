package com.codeheadsystems.opaque.internal;

import com.codeheadsystems.oprf.curve.OctetStringUtils;
import com.codeheadsystems.opaque.config.OpaqueCipherSuite;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import org.bouncycastle.math.ec.ECPoint;

/**
 * OPRF operations used by OPAQUE.
 * All methods are suite-parameterized to support multiple cipher suites.
 */
public class OpaqueOprf {

  private OpaqueOprf() {
  }

  /**
   * Client blind: maps password to a curve point and applies a random blinding factor.
   *
   * @param suite  cipher suite (determines hash-to-curve and DST)
   * @param password the client's password
   * @param blind    a randomly-chosen scalar (caller provides for deterministic testing)
   * @return blindedElement as a compressed EC point
   */
  public static byte[] blind(OpaqueCipherSuite suite, byte[] password, BigInteger blind) {
    ECPoint H = suite.oprfSuite().hashToCurve().hashToCurve(password, suite.oprfSuite().hashToGroupDst());
    ECPoint blindedPoint = H.multiply(blind).normalize();
    return blindedPoint.getEncoded(true);
  }

  /**
   * Server OPRF evaluation: multiplies the blinded element by the OPRF key.
   *
   * @param suite          cipher suite (determines curve for deserialization)
   * @param oprfKey        server OPRF private key scalar
   * @param blindedElement compressed EC point from client
   * @return evaluatedElement as a compressed EC point
   */
  public static byte[] blindEvaluate(OpaqueCipherSuite suite, BigInteger oprfKey, byte[] blindedElement) {
    ECPoint Q = OpaqueCrypto.deserializePoint(suite, blindedElement);
    ECPoint evaluated = Q.multiply(oprfKey).normalize();
    return evaluated.getEncoded(true);
  }

  /**
   * Client OPRF finalize: unblinds the evaluated element and hashes to produce OPRF output.
   *
   * @param suite            cipher suite
   * @param password         original client password bytes
   * @param blind            the blinding scalar used during blind()
   * @param evaluatedElement compressed EC point from server
   * @return Nh-byte OPRF output
   */
  public static byte[] finalize(OpaqueCipherSuite suite, byte[] password, BigInteger blind, byte[] evaluatedElement) {
    ECPoint evalPoint = OpaqueCrypto.deserializePoint(suite, evaluatedElement);
    return suite.oprfSuite().finalize(password, blind, evalPoint);
  }

  /**
   * Server: derives per-credential OPRF key from oprf_seed and credential identifier.
   *
   * @param suite                cipher suite
   * @param oprfSeed             server OPRF seed
   * @param credentialIdentifier credential identifier bytes
   * @return OPRF private key scalar
   */
  public static BigInteger deriveOprfKey(OpaqueCipherSuite suite, byte[] oprfSeed, byte[] credentialIdentifier) {
    byte[] info = OctetStringUtils.concat(
        credentialIdentifier,
        "OprfKey".getBytes(StandardCharsets.US_ASCII)
    );
    byte[] seed = OpaqueCrypto.hkdfExpand(suite, oprfSeed, info, suite.Nok());
    return suite.oprfSuite().deriveKeyPair(seed, "OPAQUE-DeriveKeyPair".getBytes(StandardCharsets.US_ASCII));
  }
}
