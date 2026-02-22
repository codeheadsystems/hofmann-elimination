package com.codeheadsystems.rfc.opaque.internal;

import com.codeheadsystems.rfc.ellipticcurve.curve.OctetStringUtils;
import com.codeheadsystems.rfc.opaque.config.OpaqueCipherSuite;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;

/**
 * OPRF operations used by OPAQUE.
 * All methods are suite-parameterized to support multiple cipher suites.
 */
public class OpaqueOprf {

  private OpaqueOprf() {
  }

  /**
   * Client blind: maps password to a group element and applies a random blinding factor.
   *
   * @param suite    cipher suite (determines hash-to-group and DST)
   * @param password the client's password
   * @param blind    a randomly-chosen scalar (caller provides for deterministic testing)
   * @return blindedElement as a serialized group element
   */
  public static byte[] blind(OpaqueCipherSuite suite, byte[] password, BigInteger blind) {
    byte[] H = suite.oprfSuite().groupSpec().hashToGroup(password, suite.oprfSuite().hashToGroupDst());
    return suite.oprfSuite().groupSpec().scalarMultiply(blind, H);
  }

  /**
   * Server OPRF evaluation: multiplies the blinded element by the OPRF key.
   *
   * @param suite          cipher suite
   * @param oprfKey        server OPRF private key scalar
   * @param blindedElement serialized group element from client
   * @return evaluatedElement as a serialized group element
   */
  public static byte[] blindEvaluate(OpaqueCipherSuite suite, BigInteger oprfKey, byte[] blindedElement) {
    return suite.oprfSuite().groupSpec().scalarMultiply(oprfKey, blindedElement);
  }

  /**
   * Client OPRF finalize: unblinds the evaluated element and hashes to produce OPRF output.
   *
   * @param suite            cipher suite
   * @param password         original client password bytes
   * @param blind            the blinding scalar used during blind()
   * @param evaluatedElement serialized group element from server
   * @return Nh-byte OPRF output
   */
  public static byte[] finalize(OpaqueCipherSuite suite, byte[] password, BigInteger blind, byte[] evaluatedElement) {
    return suite.oprfSuite().finalize(password, blind, evaluatedElement);
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
