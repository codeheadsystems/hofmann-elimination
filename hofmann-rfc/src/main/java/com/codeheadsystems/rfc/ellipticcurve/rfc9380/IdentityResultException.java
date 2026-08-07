package com.codeheadsystems.rfc.ellipticcurve.rfc9380;

/**
 * Raised when a group operation produces the identity element as its <em>result</em>.
 * <p>
 * Distinct from the {@link SecurityException} both {@link GroupSpec} implementations throw when
 * the identity arrives as an <em>input</em> — that one signals a malformed or malicious wire
 * element, while this one signals a legitimate computation that happened to land on the identity.
 * The RFC 9497 §2.2 proof operations are where this matters: {@code M}, {@code Z}, {@code t2} and
 * {@code t3} are all sums that could in principle be the identity, and the serialized encoding of
 * the identity is not consistent across the suites this module supports — ristretto255 encodes it
 * as 32 zero bytes, while SEC1 compressed encodes it as a single {@code 0x00} rather than
 * {@code Ne} bytes. RFC 9497 never pins that encoding, so any behaviour there would be
 * unspecified and impossible to check against the Appendix A vectors.
 * <p>
 * Callers in the proof layer are expected to catch this and convert it into a verification
 * failure rather than letting it escape: an exception crossing the API boundary where a
 * {@code false} belongs turns a bad proof into a server error and hands the caller an oracle.
 */
public class IdentityResultException extends RuntimeException {

  /**
   * Instantiates a new Identity result exception.
   *
   * @param message the message
   */
  public IdentityResultException(final String message) {
    super(message);
  }
}
