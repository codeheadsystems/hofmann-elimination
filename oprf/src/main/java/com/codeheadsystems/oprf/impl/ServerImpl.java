package com.codeheadsystems.oprf.impl;

import com.codeheadsystems.oprf.model.EliminationRequest;
import com.codeheadsystems.oprf.model.EliminationResponse;
import com.codeheadsystems.oprf.Server;
import com.codeheadsystems.oprf.rfc9380.GroupSpec;
import com.codeheadsystems.oprf.rfc9497.OprfCipherSuite;
import java.math.BigInteger;
import java.util.UUID;
import org.bouncycastle.util.encoders.Hex;

public class ServerImpl implements Server {

  private final GroupSpec groupSpec;
  private final BigInteger masterKey;
  private final String processIdentifier;

  public ServerImpl() {
    this(OprfCipherSuite.P256_SHA256);
  }

  public ServerImpl(OprfCipherSuite suite) {
    this.groupSpec = suite.groupSpec();
    this.masterKey = groupSpec.randomScalar();
    this.processIdentifier = "SP:" + UUID.randomUUID();
  }

  public ServerImpl(byte[] seed, byte[] info) {
    this(OprfCipherSuite.P256_SHA256, seed, info);
  }

  public ServerImpl(OprfCipherSuite suite, byte[] seed, byte[] info) {
    this.groupSpec = suite.groupSpec();
    this.masterKey = suite.deriveKeyPair(seed, info);
    this.processIdentifier = "SP:" + UUID.randomUUID();
  }

  @Override
  public EliminationResponse process(final EliminationRequest eliminationRequest) {
    byte[] q = Hex.decode(eliminationRequest.hexCodedEcPoint());
    byte[] result = groupSpec.scalarMultiply(masterKey, q);
    return new EliminationResponse(Hex.toHexString(result), processIdentifier);
  }
}
