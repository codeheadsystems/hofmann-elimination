package com.codeheadsystems.rfc.oprf.manager;

import com.codeheadsystems.rfc.common.ByteUtils;
import com.codeheadsystems.rfc.ellipticcurve.rfc9380.GroupSpec;
import com.codeheadsystems.rfc.oprf.model.BlindedRequest;
import com.codeheadsystems.rfc.oprf.model.EvaluatedResponse;
import com.codeheadsystems.rfc.oprf.model.ServerProcessorDetail;
import com.codeheadsystems.rfc.oprf.rfc9497.OprfCipherSuite;
import com.codeheadsystems.rfc.oprf.rfc9497.OprfMode;
import java.util.function.Supplier;
import org.bouncycastle.util.encoders.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * The type Oprf server manager.
 */
public class OprfServerManager {

  private static final Logger log = LoggerFactory.getLogger(OprfServerManager.class);

  private final OprfCipherSuite suite;
  private final GroupSpec groupSpec;
  private final Supplier<ServerProcessorDetail> supplier;

  /**
   * Instantiates a new Oprf server manager.
   *
   * @param suite                         the cipher suite, which must be in base OPRF mode
   * @param serverProcessorDetailSupplier the server processor detail supplier
   * @throws IllegalArgumentException if the suite is configured for VOPRF or POPRF
   */
  public OprfServerManager(OprfCipherSuite suite, Supplier<ServerProcessorDetail> serverProcessorDetailSupplier) {
    suite.assertMode(OprfMode.OPRF);
    this.suite = suite;
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
    // Wrapped because BouncyCastle's DecoderException extends IllegalStateException, not
    // IllegalArgumentException. Unwrapped, malformed hex from a client reaches the HTTP adapters
    // as a server error and becomes a 5xx — letting any caller manufacture 500s and blaming the
    // server for a client mistake. The verifiable modes handle this the same way.
    byte[] q;
    try {
      q = Hex.decode(blindedRequest.blindedPoint());
    } catch (RuntimeException e) {
      throw new IllegalArgumentException("Blinded element is not valid hex", e);
    }
    // RFC 9497 §3.3.2: BlindEvaluate must reject the identity element. For ristretto255
    // the identity is the all-zero encoding, which decodes successfully, so without this
    // check a malicious client could submit it and receive the identity back, stripping a
    // contributory-behaviour guarantee the protocol relies on. The client already rejects
    // the identity; mirror that on the server.
    if (ByteUtils.isAllZero(q)) {
      throw new IllegalArgumentException("Blinded element is the identity element");
    }
    // Snapshot the detail once. The supplier is documented as a rotation seam, so calling it
    // twice can straddle a key swap and label a hash computed with key A as key B — a stored
    // value that can then never be recomputed or verified.
    final ServerProcessorDetail detail = supplier.get();
    // Re-checked per request rather than only at construction, because a rotating supplier can
    // introduce a key the startup validation never saw. Costs one BigInteger mod — under 0.04%
    // of the scalar multiplication that follows, and on ristretto255 it repeats a reduction
    // scalarMul performs anyway.
    //
    // Rethrown as IllegalStateException deliberately. validateSecretKey signals a bad *value*
    // with IllegalArgumentException, which is right at configuration time, but both HTTP
    // adapters catch IllegalArgumentException on this path and turn it into
    // 400 "Invalid EC point data" — blaming the caller for a server misconfiguration and
    // discarding the message. A key that has gone bad under rotation would then produce a
    // healthy-looking server rejecting every client, which is the exact failure mode this
    // check exists to surface. IllegalStateException reaches the adapters unhandled and
    // becomes a 5xx, and the ERROR log carries the real reason.
    try {
      suite.validateSecretKey(detail.masterKey());
    } catch (IllegalArgumentException e) {
      log.error("OPRF server key is unusable for processor '{}': {}. Every evaluation would "
              + "return the identity element. Check the configured oprfMasterKeyHex, or the "
              + "supplier if key rotation is in use.",
          detail.processorIdentifier(), e.getMessage());
      throw new IllegalStateException("OPRF server key is misconfigured", e);
    }
    byte[] result = groupSpec.scalarMultiply(detail.masterKey(), q);
    return new EvaluatedResponse(Hex.toHexString(result), detail.processorIdentifier());
  }

}
