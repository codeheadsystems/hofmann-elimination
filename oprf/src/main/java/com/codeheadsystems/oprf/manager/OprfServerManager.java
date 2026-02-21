package com.codeheadsystems.oprf.manager;

import com.codeheadsystems.ellipticcurve.rfc9380.GroupSpec;
import com.codeheadsystems.oprf.model.EliminationRequest;
import com.codeheadsystems.oprf.model.EliminationResponse;
import com.codeheadsystems.oprf.rfc9497.OprfCipherSuite;
import java.math.BigInteger;
import java.util.UUID;
import org.bouncycastle.util.encoders.Hex;

public class OprfServerManager {

  private final GroupSpec groupSpec;
  private final BigInteger masterKey;
  private final String processIdentifier;

  public OprfServerManager() {
    this(OprfCipherSuite.P256_SHA256);
  }

  /**
   * Used mostly for testing.
   *
   * @param suite the cipher suite.
   */
  public OprfServerManager(OprfCipherSuite suite) {
    this(suite, suite.randomScalar(), "SP:" + UUID.randomUUID());
  }

  public OprfServerManager(OprfCipherSuite suite, BigInteger masterKey, String processIdentifier) {
    this.groupSpec = suite.groupSpec();
    this.masterKey = masterKey;
    this.processIdentifier = processIdentifier;
  }

  public OprfServerManager(byte[] seed, byte[] info) {
    this(OprfCipherSuite.P256_SHA256, seed, info);
  }

  public OprfServerManager(OprfCipherSuite suite, byte[] seed, byte[] info) {
    this.groupSpec = suite.groupSpec();
    this.masterKey = suite.deriveKeyPair(seed, info);
    this.processIdentifier = "SP:" + UUID.randomUUID();
  }

  /**
   * Essentially, the server takes the blinded point from the client and multiplies it by a secret scalar value that is
   * unique to the server. This process transforms the blinded point into a new point on the elliptic curve, which is
   * then returned to the client in a hex-encoded format. That process is difficult to reverse due to computational
   * complexity. However, to reverse it is subject to attack from quantum computers by the first party.
   *
   * @param eliminationRequest the request from the client containing the hex-encoded blinded elliptic curve point.
   * @return the response containing the hex-encoded elliptic curve point resulting from the server's process, along with a process identifier for tracking and correlation purposes.
   */
  public EliminationResponse process(final EliminationRequest eliminationRequest) {
    byte[] q = Hex.decode(eliminationRequest.hexCodedEcPoint());
    byte[] result = groupSpec.scalarMultiply(masterKey, q);
    return new EliminationResponse(Hex.toHexString(result), processIdentifier);
  }

}
