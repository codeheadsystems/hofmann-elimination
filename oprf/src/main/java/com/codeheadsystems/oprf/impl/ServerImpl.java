package com.codeheadsystems.oprf.impl;

import com.codeheadsystems.oprf.curve.Curve;
import com.codeheadsystems.oprf.model.EliminationRequest;
import com.codeheadsystems.oprf.curve.OctetStringUtils;
import com.codeheadsystems.oprf.model.EliminationResponse;
import com.codeheadsystems.oprf.Server;
import com.codeheadsystems.oprf.rfc9497.OprfCipherSuite;
import java.math.BigInteger;
import java.util.UUID;
import org.bouncycastle.math.ec.ECPoint;

public class ServerImpl implements Server {

  private final Curve curve;
  private final BigInteger masterKey;
  private final String processIdentifier;

  public ServerImpl() {
    this(OprfCipherSuite.P256_SHA256);
  }

  public ServerImpl(OprfCipherSuite suite) {
    this.curve = suite.curve();
    this.masterKey = curve.randomScalar();
    this.processIdentifier = "SP:" + UUID.randomUUID();
  }

  public ServerImpl(byte[] seed, byte[] info) {
    this(OprfCipherSuite.P256_SHA256, seed, info);
  }

  public ServerImpl(OprfCipherSuite suite, byte[] seed, byte[] info) {
    this.curve = suite.curve();
    this.masterKey = suite.deriveKeyPair(seed, info);
    this.processIdentifier = "SP:" + UUID.randomUUID();
  }

  @Override
  public EliminationResponse process(final EliminationRequest eliminationRequest) {
    ECPoint q = OctetStringUtils.toEcPoint(curve, eliminationRequest.hexCodedEcPoint());
    ECPoint result = q.multiply(masterKey).normalize();
    return new EliminationResponse(OctetStringUtils.toHex(result), processIdentifier);
  }
}
