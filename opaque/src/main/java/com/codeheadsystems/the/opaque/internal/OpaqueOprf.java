package com.codeheadsystems.the.opaque.internal;

import com.codeheadsystems.the.oprf.curve.OctetStringUtils;
import com.codeheadsystems.the.oprf.rfc9380.HashToCurve;
import com.codeheadsystems.the.oprf.rfc9497.OprfSuite;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import org.bouncycastle.math.ec.ECPoint;

/**
 * OPRF operations used by OPAQUE.
 * Wraps the existing OPRF primitive (RFC 9497) for registration and authentication.
 */
public class OpaqueOprf {

  private static final HashToCurve H2C = HashToCurve.forP256();

  private OpaqueOprf() {
  }

  /**
   * Client blind: maps password to a curve point and applies a random blinding factor.
   *
   * @param password the client's password
   * @param blind    a randomly-chosen scalar (caller provides for deterministic testing)
   * @return blindedElement as a 33-byte compressed EC point
   */
  public static byte[] blind(byte[] password, BigInteger blind) {
    ECPoint H = H2C.hashToCurve(password, OprfSuite.HASH_TO_GROUP_DST);
    ECPoint blindedPoint = H.multiply(blind).normalize();
    return blindedPoint.getEncoded(true);
  }

  /**
   * Server OPRF evaluation: multiplies the blinded element by the OPRF key.
   *
   * @param oprfKey        server OPRF private key scalar
   * @param blindedElement 33-byte compressed EC point from client
   * @return evaluatedElement as a 33-byte compressed EC point
   */
  public static byte[] blindEvaluate(BigInteger oprfKey, byte[] blindedElement) {
    ECPoint Q = OpaqueCrypto.deserializePoint(blindedElement);
    ECPoint evaluated = Q.multiply(oprfKey).normalize();
    return evaluated.getEncoded(true);
  }

  /**
   * Client OPRF finalize: unblinds the evaluated element and hashes to produce OPRF output.
   *
   * @param password         original client password bytes
   * @param blind            the blinding scalar used during blind()
   * @param evaluatedElement 33-byte compressed EC point from server
   * @return 32-byte OPRF output
   */
  public static byte[] finalize(byte[] password, BigInteger blind, byte[] evaluatedElement) {
    ECPoint evalPoint = OpaqueCrypto.deserializePoint(evaluatedElement);
    return OprfSuite.finalize(password, blind, evalPoint);
  }

  /**
   * Server: derives per-credential OPRF key from oprf_seed and credential identifier.
   * Per RFC 9807 §3.3.1.1:
   * seed = HKDF-Expand(oprf_seed, "OprfKey" || I2OSP(len(credential_identifier), 2) || credential_identifier, Nok)
   * oprf_key = DeriveKeyPair(seed, "OPAQUE-DeriveKeyPair")
   *
   * @param oprfSeed             32-byte server OPRF seed
   * @param credentialIdentifier credential identifier bytes
   * @return OPRF private key scalar
   */
  public static BigInteger deriveOprfKey(byte[] oprfSeed, byte[] credentialIdentifier) {
    // Per CFRG reference: info = credential_identifier || "OprfKey"
    byte[] info = OctetStringUtils.concat(
        credentialIdentifier,
        "OprfKey".getBytes(StandardCharsets.US_ASCII)
    );
    byte[] seed = OpaqueCrypto.hkdfExpand(oprfSeed, info, 32);
    return OprfSuite.deriveKeyPair(seed, "OPAQUE-DeriveKeyPair".getBytes(StandardCharsets.US_ASCII));
  }
}
