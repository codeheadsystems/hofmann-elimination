package com.codeheadsystems.rfc.oprf.manager;

import com.codeheadsystems.rfc.oprf.model.VerifiableProcessorDetail;
import com.codeheadsystems.rfc.oprf.rfc9497.OprfCipherSuite;
import com.codeheadsystems.rfc.oprf.rfc9497.OprfMode;
import java.math.BigInteger;
import org.bouncycastle.util.encoders.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Key-material checking and request decoding shared by the VOPRF and POPRF servers.
 * <p>
 * Both servers face the same three problems — a supplier that can hand over a different key at any
 * moment, a caller-controlled hex field, and a batch size chosen by the client — and the handling
 * has to be identical, because a divergence would show up as one mode being safe and the other not
 * in a way no test compares directly.
 */
final class VerifiableServerSupport {

  private static final Logger log = LoggerFactory.getLogger(VerifiableServerSupport.class);

  private final OprfCipherSuite suite;
  private final OprfMode expectedMode;

  /**
   * The last key material whose public/secret correspondence was checked.
   * <p>
   * Consistency is verified when the key changes rather than on every request or never. Per
   * request would spend a fixed-base scalar multiplication detecting a static configuration error;
   * never would leave the one case startup validation structurally cannot see — a rotation
   * introducing a mismatched pair, which produces proofs that verify for no client, indefinitely,
   * and which reads as a client bug from the server side and as a compromise from the client side.
   * <p>
   * Racing threads may each validate the same new key once; that is harmless and cheaper than
   * synchronizing. Compared by value rather than by reference because a supplier is free to return
   * a fresh instance per call.
   */
  private volatile KeyIdentity lastValidated;

  /** The part of a detail that determines whether consistency needs rechecking. */
  private record KeyIdentity(String processorIdentifier, BigInteger masterKey) {
    static KeyIdentity of(VerifiableProcessorDetail detail) {
      return new KeyIdentity(detail.processorIdentifier(), detail.masterKey());
    }
  }

  VerifiableServerSupport(final OprfCipherSuite suite, final OprfMode expectedMode) {
    this.suite = suite;
    this.expectedMode = expectedMode;
  }

  /**
   * Checks key material freshly supplied for a request.
   * <p>
   * Re-checked per request rather than only at construction, because a rotating supplier can
   * introduce a key that startup validation never saw.
   * <p>
   * Every failure is an {@link IllegalStateException} deliberately. A bad key value is an
   * {@link IllegalArgumentException} at configuration time, but on this path it is a server
   * misconfiguration, and the HTTP adapters turn {@code IllegalArgumentException} into a 400 that
   * blames the caller. A key gone bad under rotation would then present as a healthy server
   * rejecting every client, which is precisely the failure this check exists to surface.
   *
   * @param detail the supplied key material
   * @return the same detail, once validated
   */
  VerifiableProcessorDetail requireValidDetail(final VerifiableProcessorDetail detail) {
    if (detail == null) {
      throw new IllegalStateException(
          "Key supplier returned no " + expectedMode + " key material");
    }
    if (detail.mode() != expectedMode) {
      log.error("Key material for processor '{}' was derived for {} but is being used for {}; "
              + "one secret must not serve two modes.",
          detail.processorIdentifier(), detail.mode(), expectedMode);
      throw new IllegalStateException(expectedMode + " server key is configured for the wrong mode");
    }
    try {
      suite.validateSecretKey(detail.masterKey());
    } catch (IllegalArgumentException e) {
      log.error("{} server key is unusable for processor '{}': {}. Every evaluation would return "
              + "the identity element. Check the configured key, or the supplier if key rotation "
              + "is in use.",
          expectedMode, detail.processorIdentifier(), e.getMessage());
      throw new IllegalStateException(expectedMode + " server key is misconfigured", e);
    }

    KeyIdentity identity = KeyIdentity.of(detail);
    if (!identity.equals(lastValidated)) {
      try {
        detail.validateConsistency(suite);
      } catch (IllegalArgumentException e) {
        log.error("{} key material for processor '{}' is internally inconsistent: {}. "
                + "Proofs would be generated against a public key no client can match.",
            expectedMode, detail.processorIdentifier(), e.getMessage());
        throw new IllegalStateException(expectedMode + " server key pair is inconsistent", e);
      }
      lastValidated = identity;
    }
    return detail;
  }

  /**
   * Decodes a hex field supplied by the client.
   * <p>
   * BouncyCastle's {@code Hex.decode} throws {@code DecoderException}, which extends
   * {@link IllegalStateException} rather than {@link IllegalArgumentException}. Left unwrapped, a
   * client sending malformed hex would reach the HTTP adapters as a server error and become a 5xx
   * — letting any client manufacture 500s at will, and inverting blame in exactly the way
   * {@link #requireValidDetail} takes pains to get right for the key case.
   *
   * @param hex   the hex text
   * @param what  what the field is, for the error message
   * @return the decoded bytes
   */
  static byte[] decode(final String hex, final String what) {
    try {
      return Hex.decode(hex);
    } catch (RuntimeException e) {
      throw new IllegalArgumentException(what + " is not valid hex", e);
    }
  }
}
