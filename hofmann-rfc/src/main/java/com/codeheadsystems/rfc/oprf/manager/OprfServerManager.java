package com.codeheadsystems.rfc.oprf.manager;

import com.codeheadsystems.rfc.ellipticcurve.rfc9380.GroupSpec;
import com.codeheadsystems.rfc.oprf.model.BlindedRequest;
import com.codeheadsystems.rfc.oprf.model.EvaluatedResponse;
import com.codeheadsystems.rfc.oprf.model.ServerProcessorDetail;
import com.codeheadsystems.rfc.oprf.rfc9497.OprfCipherSuite;
import java.util.function.Supplier;
import org.bouncycastle.util.encoders.Hex;

/**
 * The type Oprf server manager.
 */
public class OprfServerManager {

  private final GroupSpec groupSpec;
  private final Supplier<ServerProcessorDetail> supplier;

  /**
   * Instantiates a new Oprf server manager.
   *
   * @param suite                         the suite
   * @param serverProcessorDetailSupplier the server processor detail supplier
   */
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
   * @param blindedRequest the request from the client containing the hex-encoded blinded elliptic curve point.
   * @return the response containing the hex-encoded elliptic curve point resulting from the server's process, along with a process identifier for tracking and correlation purposes.
   */
  public EvaluatedResponse process(final BlindedRequest blindedRequest) {
    byte[] q = Hex.decode(blindedRequest.blindedPoint());
    byte[] result = groupSpec.scalarMultiply(supplier.get().masterKey(), q);
    return new EvaluatedResponse(Hex.toHexString(result), supplier.get().processorIdentifier());
  }

}
