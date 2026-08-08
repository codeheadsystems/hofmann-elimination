package com.codeheadsystems.rfc.oprf.manager;

import com.codeheadsystems.rfc.ellipticcurve.rfc9380.GroupSpec;
import com.codeheadsystems.rfc.oprf.model.BlindedRequest;
import com.codeheadsystems.rfc.oprf.model.ClientHashingContext;
import com.codeheadsystems.rfc.oprf.model.EvaluatedResponse;
import com.codeheadsystems.rfc.oprf.model.HashResult;
import com.codeheadsystems.rfc.oprf.rfc9497.OprfCipherSuite;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.UUID;
import org.bouncycastle.util.encoders.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * The type Oprf client manager.
 */
public class OprfClientManager {

  private static final Logger log = LoggerFactory.getLogger(OprfClientManager.class);

  private final OprfCipherSuite suite;
  private final GroupSpec groupSpec;

  /**
   * Instantiates a new Oprf client manager.
   *
   * @param suite the suite
   */
  public OprfClientManager(OprfCipherSuite suite) {
    log.info("OprfClientManager({})", suite.hashAlgorithm());
    this.suite = suite;
    this.groupSpec = suite.groupSpec();
  }

  /**
   * Generates the components for the OPRF hashing process: a unique request id, a random blinding
   * factor, and a copy of the input. The resulting context carries the exchange from start to
   * finish.
   *
   * <p><strong>This is the entry point to prefer.</strong> The input is the client's plaintext
   * OPRF secret, and a {@code byte[]} is the only form of it the caller can erase — see the
   * {@link #hashingContext(String)} overload for what the string form costs. The context copies
   * what it is given, so the caller may clear their own array as soon as this returns; closing the
   * context clears the copy.
   *
   * @param sensitiveData the sensitive data you want to hash; copied, not retained
   * @return a hashing context
   */
  public ClientHashingContext hashingContext(final byte[] sensitiveData) {
    if (sensitiveData == null) {
      throw new IllegalArgumentException("Sensitive data is required");
    }
    final String requestId = UUID.randomUUID().toString();
    log.trace("performHashing(requestId={})", requestId);
    final BigInteger blindingFactor = suite.randomScalar();
    return new ClientHashingContext(requestId, blindingFactor, sensitiveData);
  }

  /**
   * Convenience overload for callers whose input is already a {@link String}.
   *
   * <p><strong>A {@code String} holding a secret cannot be erased.</strong> It is immutable, so
   * there is no supported way to overwrite its contents; the value survives on the heap until the
   * collector happens to reclaim it, and any interning, substring or concatenation on the way here
   * has already made copies nobody holds a reference to. Every other secret in this library —
   * OPAQUE passwords, the verifiable-mode inputs — is a {@code byte[]} for exactly that reason,
   * and this overload was the last place the base-mode OPRF API forced a caller to give one up.
   *
   * <p>It stays because it is genuinely convenient and because a great deal of calling code has a
   * {@code String} in hand already, in which case the damage is done before this method is reached
   * and refusing it would only move the conversion. If you control where the secret comes from,
   * read it into a {@code byte[]} and call {@link #hashingContext(byte[])} instead.
   *
   * @param sensitiveData the sensitive data you want to hash
   * @return a hashing context
   */
  public ClientHashingContext hashingContext(final String sensitiveData) {
    if (sensitiveData == null) {
      throw new IllegalArgumentException("Sensitive data is required");
    }
    final byte[] input = sensitiveData.getBytes(StandardCharsets.UTF_8);
    try {
      return hashingContext(input);
    } finally {
      // The context copied it; this intermediate is ours and nobody else will clear it. It does
      // not redeem the String itself, which is still on the heap and still unerasable.
      Arrays.fill(input, (byte) 0);
    }
  }

  /**
   * Creates a elimination request for the hashing context. This is largely deterministic based on the hashing context.
   *
   * @param clientHashingContext to generate the elimination request from.
   * @return an elimination request that can be sent to the OPRF server manager.
   */
  public BlindedRequest eliminationRequest(final ClientHashingContext clientHashingContext) {
    log.trace("eliminationRequest(requestId={})", clientHashingContext.requestId());
    final byte[] hashedElement = groupSpec.hashToGroup(clientHashingContext.input(), suite.hashToGroupDst());
    if (isIdentity(hashedElement)) {
      throw new IllegalArgumentException("HashToGroup produced the identity element");
    }
    final byte[] blindedElement = groupSpec.scalarMultiply(clientHashingContext.blindingFactor(), hashedElement);
    final String blindedPointHex = Hex.toHexString(blindedElement);
    return new BlindedRequest(blindedPointHex, clientHashingContext.requestId());
  }

  private static boolean isIdentity(byte[] element) {
    for (byte b : element) {
      if (b != 0) return false;
    }
    return true;
  }

  /**
   * Takes the elimination response from the server and the original hashing context to produce the final hash result.
   * This involves unblinding the evaluated element from the server and applying the finalization step as defined in RFC 9497.
   *
   * <p>The javadoc that belongs here used to sit on {@code isIdentity} above, so this method read
   * as undocumented and that one as describing something it does not do.
   *
   * <p><strong>The context must not have been closed.</strong> This reads its input; a closed
   * context finalizes over zeroes and returns a well-formed hash derived from the wrong value,
   * with no exception anywhere. See {@link ClientHashingContext#close()}.
   *
   * @param evaluatedResponse    the response from the OPRF server manager after processing the elimination request.
   * @param clientHashingContext the original context that was used to generate the elimination request, which contains the necessary information for finalizing the hash.
   * @return the final hash result.
   */
  public HashResult hashResult(final EvaluatedResponse evaluatedResponse, final ClientHashingContext clientHashingContext) {
    log.trace("hashResult(requestId={})", clientHashingContext.requestId());
    // See OprfServerManager for why this is wrapped: BouncyCastle's DecoderException extends
    // IllegalStateException, so a server sending malformed hex would otherwise choose which
    // exception type the calling application sees.
    final byte[] evaluatedElement;
    try {
      evaluatedElement = Hex.decode(evaluatedResponse.evaluatedPoint());
    } catch (RuntimeException e) {
      throw new SecurityException("Server returned malformed hex for the evaluated element", e);
    }
    final byte[] finalHash = suite.finalize(clientHashingContext.input(), clientHashingContext.blindingFactor(), evaluatedElement);
    return new HashResult(finalHash, evaluatedResponse.processIdentifier());
  }

}
