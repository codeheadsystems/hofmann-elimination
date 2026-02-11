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

  private final ServerData serverData;

  public ServerImpl() {
    serverData = new ServerData(Curve.P256_CURVE.randomScaler(), "SP:" + UUID.randomUUID());
  }

  /**
   * Creates a ServerImpl with a deterministically derived key from seed and info.
   * Uses RFC 9497 DeriveKeyPair to derive the private key.
   *
   * @param seed 32-byte random seed
   * @param info application-specific info string
   */
  public ServerImpl(byte[] seed, byte[] info) {
    BigInteger skS = OprfSuite.deriveKeyPair(seed, info);
    serverData = new ServerData(skS, "SP:" + UUID.randomUUID());
  }

  @Override
  public EliminationResponse process(final EliminationRequest eliminationRequest) {
    // Apply the client key to our master key for this request.
    BigInteger requestKey = serverData.masterKey();
    ECPoint q = EcUtilities.HEX_TO_ECPOINT(eliminationRequest.hexCodedEcPoint());
    ECPoint result = q.multiply(requestKey).normalize();
    return new EliminationResponse(EcUtilities.ECPOINT_TO_HEX(result), serverData.processIdentifier());
  }

  public record ServerData(BigInteger masterKey, String processIdentifier) {

  }

}
