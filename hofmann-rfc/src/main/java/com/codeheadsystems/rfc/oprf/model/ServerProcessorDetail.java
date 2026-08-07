package com.codeheadsystems.rfc.oprf.model;

import java.io.Serializable;
import java.math.BigInteger;

/**
 * The type Server processor detail.
 *
 * <p><strong>Holds long-term secret key material.</strong> {@code toString} is overridden because
 * the generated one would render {@code masterKey} as its full decimal value — {@code BigInteger}
 * has no redacting {@code toString}, unlike {@code byte[]}, which renders as an identity hash and
 * is why {@code JwtKeyDetail} and {@code ByteKey} are safe by accident. A single
 * {@code log.info("detail={}", supplier.get())}, the pattern already used elsewhere on this
 * supplier, would have written the long-term OPRF master key to the log in recoverable form. No
 * call site does that today; this makes it so none can.
 *
 * <p>The record is also {@link Serializable}, so the same field is reachable through any
 * serialization sink. That is not addressed here — the type is part of the public API and
 * removing the interface would be a breaking change — but it is the reason the {@code toString}
 * guard is not sufficient on its own for a deployment that serializes this type.
 */
public record ServerProcessorDetail(BigInteger masterKey, String processorIdentifier) implements Serializable {

  @Override
  public String toString() {
    return "ServerProcessorDetail[masterKey=<redacted>, processorIdentifier="
        + processorIdentifier + "]";
  }
}
