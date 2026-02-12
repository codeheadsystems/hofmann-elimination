package com.codeheadsystems.hofmann.impl;

import com.codeheadsystems.hofmann.Curve;
import com.codeheadsystems.hofmann.EcUtilities;
import com.codeheadsystems.hofmann.EliminationRequest;
import com.codeheadsystems.hofmann.EliminationResponse;
import com.codeheadsystems.hofmann.Server;
import com.codeheadsystems.hofmann.rfc9497.OprfSuite;
import java.math.BigInteger;
import java.util.UUID;
import org.bouncycastle.math.ec.ECPoint;

public class ServerImpl implements Server {

  private final Curve curve;
  private final BigInteger masterKey;
  private final String processIdentifier;

  public ServerImpl() {
    this.curve = Curve.P256_CURVE;
    this.masterKey = curve.randomScaler();
    this.processIdentifier = "SP:" + UUID.randomUUID();
  }


  @Override
  public EliminationResponse process(final EliminationRequest eliminationRequest) {
    ECPoint q = curve.toEcPoint(eliminationRequest.hexCodedEcPoint())
        .orElseThrow(() -> new IllegalArgumentException("Invalid hex-encoded EC point: " + eliminationRequest.hexCodedEcPoint()));
    ECPoint result = q.multiply(masterKey).normalize();
    return new EliminationResponse(curve.toHex(result).orElseThrow(() -> new IllegalArgumentException("Invalid EC point: " + result)),
        processIdentifier);
  }


}
