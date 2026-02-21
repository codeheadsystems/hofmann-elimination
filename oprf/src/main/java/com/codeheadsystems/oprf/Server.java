package com.codeheadsystems.oprf;

import com.codeheadsystems.ellipticcurve.rfc9380.GroupSpec;
import com.codeheadsystems.oprf.model.EliminationRequest;
import com.codeheadsystems.oprf.model.EliminationResponse;
import com.codeheadsystems.oprf.rfc9497.OprfCipherSuite;
import java.math.BigInteger;
import java.util.UUID;
import org.bouncycastle.util.encoders.Hex;

public class Server {

  private final GroupSpec groupSpec;
  private final BigInteger masterKey;
  private final String processIdentifier;

  public Server() {
    this(OprfCipherSuite.P256_SHA256);
  }

  public Server(OprfCipherSuite suite) {
    this.groupSpec = suite.groupSpec();
    this.masterKey = suite.randomScalar();
    this.processIdentifier = "SP:" + UUID.randomUUID();
  }

  public Server(byte[] seed, byte[] info) {
    this(OprfCipherSuite.P256_SHA256, seed, info);
  }

  public Server(OprfCipherSuite suite, byte[] seed, byte[] info) {
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
   * @param eliminationRequest
   * @return
   */
  public EliminationResponse process(final EliminationRequest eliminationRequest) {
    byte[] q = Hex.decode(eliminationRequest.hexCodedEcPoint());
    byte[] result = groupSpec.scalarMultiply(masterKey, q);
    return new EliminationResponse(Hex.toHexString(result), processIdentifier);
  }

}
