package com.codeheadsystems.oprf.manager;

import com.codeheadsystems.ellipticcurve.rfc9380.GroupSpec;
import com.codeheadsystems.oprf.model.EliminationRequest;
import com.codeheadsystems.oprf.model.EliminationResponse;
import com.codeheadsystems.oprf.model.ServerProcessorDetail;
import com.codeheadsystems.oprf.rfc9497.OprfCipherSuite;
import java.math.BigInteger;
import java.util.UUID;
import java.util.function.Supplier;
import org.bouncycastle.util.encoders.Hex;

public class OprfServerManager {

  private final GroupSpec groupSpec;
  private final Supplier<ServerProcessorDetail> supplier;

  public OprfServerManager(OprfCipherSuite suite, Supplier<ServerProcessorDetail> serverProcessorDetailSupplier) {
    this.groupSpec = suite.groupSpec();
    this.supplier = serverProcessorDetailSupplier;
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
    byte[] result = groupSpec.scalarMultiply(supplier.get().masterKey(), q);
    return new EliminationResponse(Hex.toHexString(result), supplier.get().processorIdentifier());
  }

}
