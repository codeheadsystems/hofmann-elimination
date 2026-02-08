package com.codeheadsystems.hofmann.impl;

import com.codeheadsystems.hofmann.ClientKey;
import com.codeheadsystems.hofmann.Curve;
import com.codeheadsystems.hofmann.EliminationRequest;
import com.codeheadsystems.hofmann.EliminationResponse;
import com.codeheadsystems.hofmann.Server;
import java.math.BigInteger;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import org.bouncycastle.math.ec.ECPoint;

public class ServerImpl implements Server {

  private final Map<String, BigInteger> clientScalars;
  private final ServerData serverData;

  public ServerImpl() {
    clientScalars = new HashMap<>();
    serverData = new ServerData(Curve.RANDOM_SCALER(), "SP:" + UUID.randomUUID());
  }

  @Override
  public EliminationResponse process(final EliminationRequest eliminationRequest) {
    BigInteger clientKey = clientScalars.get(eliminationRequest.clientKeyIdentifier());
    if (clientKey == null) {
      throw new IllegalArgumentException("Unknown client key identifier: " + eliminationRequest.clientKeyIdentifier());
    }
    BigInteger modInverseClientKey = clientKey.modInverse(Curve.DEFAULT_CURVE.getN());
    // Apply the client key to our master key for this request.
    BigInteger requestKey = serverData.masterKey().multiply(modInverseClientKey).mod(Curve.DEFAULT_CURVE.getN()); // s * kᵢ⁻¹ mod n
    ECPoint q = Curve.HEX_TO_ECPOINT(eliminationRequest.hexCodedEcPoint());
    ECPoint result = q.multiply(requestKey).normalize();
    return new EliminationResponse(Curve.ECPOINT_TO_HEX(result), serverData.processIdentifier());
  }

  @Override
  public ClientKey generateClientKey(final String clientIdentifier) {
    String key = clientIdentifier + ":" + UUID.randomUUID();
    BigInteger scalar = Curve.RANDOM_SCALER();
    clientScalars.put(key, scalar);
    return new ClientKey(key, scalar);
  }

  public record ServerData(BigInteger masterKey, String processIdentifier) {

  }

}
