package com.codeheadsystems.rfc.oprf.manager;

import com.codeheadsystems.rfc.ellipticcurve.rfc9380.GroupSpec;
import com.codeheadsystems.rfc.oprf.model.HashResult;
import com.codeheadsystems.rfc.oprf.model.VerifiableBlindedRequest;
import com.codeheadsystems.rfc.oprf.model.VerifiableEvaluatedResponse;
import com.codeheadsystems.rfc.oprf.model.VoprfClientContext;
import com.codeheadsystems.rfc.oprf.rfc9497.OprfCipherSuite;
import com.codeheadsystems.rfc.oprf.rfc9497.OprfMode;
import com.codeheadsystems.rfc.oprf.rfc9497.proof.DleqProof;
import com.codeheadsystems.rfc.oprf.rfc9497.proof.DleqVerifier;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import org.bouncycastle.util.encoders.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * RFC 9497 §3.3.2 VOPRF client: blinds inputs, then verifies the server's proof before trusting
 * the result.
 * <p>
 * The server public key is supplied at construction and never read from a response. That is the
 * whole basis of the guarantee: a key arriving alongside the proof it authenticates lets the
 * server pick the standard it is judged against, and every response would verify. The key must
 * also have been <em>authenticated</em> out of band, not merely obtained — an attacker who can
 * substitute it can run a distinct key per client, producing proofs that verify while
 * partitioning users into individually-identifiable buckets. RFC 9497 §7.3 treats that key
 * consistency as an application responsibility, and nothing in the protocol detects it.
 */
public class VoprfClientManager {

  private static final Logger log = LoggerFactory.getLogger(VoprfClientManager.class);

  private final OprfCipherSuite suite;
  private final GroupSpec groupSpec;
  private final byte[] serverPublicKey;

  /**
   * Instantiates a new VOPRF client manager.
   *
   * @param suite           the cipher suite, which must be in VOPRF mode
   * @param serverPublicKey the server's out-of-band authenticated public key
   */
  public VoprfClientManager(final OprfCipherSuite suite, final byte[] serverPublicKey) {
    suite.assertMode(OprfMode.VOPRF);
    // Validated once, here, rather than on each use. RFC 9497 §3.3 requires wire elements to be
    // checked for the identity; a public key that is the identity, off-curve, or in a
    // non-compressed encoding would otherwise fail every proof with no indication of why.
    suite.groupSpec().validateElement(serverPublicKey);
    this.suite = suite;
    this.groupSpec = suite.groupSpec();
    this.serverPublicKey = serverPublicKey.clone();
    log.info("VoprfClientManager({})", suite.identifier());
  }

  /**
   * Convenience overload for callers whose input is already a {@link String}.
   *
   * <p><strong>A {@code String} holding a secret cannot be erased.</strong> It is immutable, so
   * there is no supported way to overwrite its contents; the value survives on the heap until the
   * collector happens to reclaim it, and any interning, substring or concatenation on the way here
   * has already made copies nobody holds a reference to. Prefer
   * {@link #hashingContext(java.util.List)} with {@code List.of(bytes)} — a {@code byte[]} is
   * the only form of the input this library can clear, and closing the context clears its copy.
   *
   * <p>Unlike the base-mode overload on {@code OprfClientManager}, this one does <strong>not</strong>
   * zero the intermediate array it derives from the {@code String}, and rejects null with a
   * {@link NullPointerException} rather than an {@link IllegalArgumentException}. Both are
   * consequences of it being a thin convenience wrapper; neither is a reason to use it.
   *
   * @param sensitiveData the input to evaluate
   * @return the context
   * @throws NullPointerException if {@code sensitiveData} is null
   */
  public VoprfClientContext hashingContext(final String sensitiveData) {
    return hashingContext(List.of(sensitiveData.getBytes(StandardCharsets.UTF_8)));
  }

  /**
   * Creates a context for a batch of inputs, all evaluated under one proof.
   *
   * @param inputs the inputs to evaluate
   * @return the context
   */
  public VoprfClientContext hashingContext(final List<byte[]> inputs) {
    if (inputs == null || inputs.isEmpty()) {
      throw new IllegalArgumentException("At least one input is required");
    }
    final String requestId = UUID.randomUUID().toString();
    List<byte[]> copied = new ArrayList<>(inputs.size());
    List<BigInteger> blinds = new ArrayList<>(inputs.size());
    List<byte[]> blindedElements = new ArrayList<>(inputs.size());

    for (byte[] input : inputs) {
      byte[] hashed = groupSpec.hashToGroup(input, suite.hashToGroupDst());
      // RFC 9497 §3.3.2 Blind raises InvalidInputError here. Reachable only for an input whose
      // hash-to-group lands on the identity, which no known input does, but the check is what the
      // spec asks for and the alternative is an evaluation independent of the server key.
      if (isIdentity(hashed)) {
        throw new IllegalArgumentException("HashToGroup produced the identity element");
      }
      BigInteger blind = suite.randomScalar();
      copied.add(input.clone());
      blinds.add(blind);
      blindedElements.add(groupSpec.scalarMultiply(blind, hashed));
    }
    return new VoprfClientContext(requestId, copied, blinds, blindedElements);
  }

  /**
   * Builds the wire request for a context.
   *
   * @param context the context; must not have been closed
   * @return the request
   * @throws com.codeheadsystems.rfc.common.ClosedContextException if the context has been closed. This is the
   *         call that matters: a closed context used to build a perfectly valid request here, the
   *         server evaluated it correctly, and the proof verified — only the final hash was wrong
   */
  public VerifiableBlindedRequest eliminationRequest(final VoprfClientContext context) {
    List<String> points = new ArrayList<>(context.size());
    for (byte[] element : context.blindedElements()) {
      points.add(Hex.toHexString(element));
    }
    return new VerifiableBlindedRequest(points, context.requestId());
  }

  /**
   * Verifies the server's proof and, only if it holds, unblinds every evaluated element.
   *
   * <p>
   * A returned {@link HashResult} carries the server's {@code processIdentifier} verbatim. The
   * <em>hash</em> is trustworthy — it was verified against the public key this manager was
   * constructed with, not against anything the server supplied — but the label is not: a
   * misbehaving server can attach any identifier it likes to a correctly-evaluated result. Treat
   * it as a routing hint, and do not persist results keyed by it in a way that would let a server
   * mislabel which key produced a stored value.
   *
   * @param response the server response
   * @param context  the context the request was built from
   * @return one result per input, aligned with the context's inputs
   * @throws SecurityException if the proof does not verify, the response length does not match the
   *                           request, or any field is malformed
   * @throws com.codeheadsystems.rfc.common.ClosedContextException if {@code context} has been closed. Not a
   *                           {@code SecurityException} on purpose — that type means the peer
   *                           misbehaved, and this is a lifetime bug in the calling application
   */
  public List<HashResult> hashResults(final VerifiableEvaluatedResponse response,
                                      final VoprfClientContext context) {
    // Checked before anything else touches the response. A server that returns a different number
    // of elements than it was sent would otherwise have its reply zipped against the client's
    // blinds by position, pairing input i with an evaluation of something else — output that is
    // wrong but indistinguishable from correct. The proof would fail too, but only incidentally;
    // this makes the mismatch the explicit reason.
    if (response.evaluatedPoints().size() != context.size()) {
      throw new SecurityException(
          "Server returned " + response.evaluatedPoints().size() + " evaluated elements for "
              + context.size() + " blinded elements");
    }

    byte[][] blindedElements = context.blindedElements().toArray(new byte[0][]);
    byte[][] evaluatedElements = new byte[context.size()][];
    for (int i = 0; i < context.size(); i++) {
      byte[] evaluated = decode(response.evaluatedPoints().get(i), "evaluated element " + i);
      // Validated before the proof is checked. This leaks nothing — the only party who could
      // distinguish "malformed element" from "bad proof" is the server, which already knows what
      // it sent — and it keeps a malformed element reported as such instead of being laundered
      // into "the proof did not verify" by the verifier's uniform failure handling.
      groupSpec.validateElement(evaluated);
      evaluatedElements[i] = evaluated;
    }

    DleqProof proof = DleqProof.deserialize(suite, decode(response.proof(), "proof"));
    // Verified before unblinding, per §3.3.2. Unblinding first would produce output
    // indistinguishable from a correct result, which is exactly what this mode exists to prevent.
    if (!DleqVerifier.verifyProof(
        suite, serverPublicKey, blindedElements, evaluatedElements, proof)) {
      throw new SecurityException(
          "VOPRF proof did not verify for processor '" + response.processIdentifier()
              + "'; the server did not evaluate with the committed key");
    }

    // Hoisted out of the loop. The accessors now deep-copy, so calling inputs() per element made
    // this quadratic: at the 1024 batch cap with 4 KB inputs that is ~0.32 s of pure copying and
    // gigabytes of transient allocation, against microseconds hoisted. It also produced n^2
    // unzeroed heap copies of the client's plaintext, which is the part that matters beyond speed.
    List<byte[]> inputs = context.inputs();
    List<BigInteger> blinds = context.blinds();
    List<HashResult> results = new ArrayList<>(context.size());
    for (int i = 0; i < context.size(); i++) {
      byte[] hash = suite.finalize(inputs.get(i), blinds.get(i), evaluatedElements[i]);
      results.add(new HashResult(hash, response.processIdentifier()));
    }
    return results;
  }

  /**
   * Convenience for a single-input context.
   *
   * @param response the server response
   * @param context  the context, which must hold exactly one input
   * @return the result
   */
  public HashResult hashResult(final VerifiableEvaluatedResponse response,
                               final VoprfClientContext context) {
    if (context.size() != 1) {
      throw new IllegalArgumentException(
          "hashResult is for single-input contexts; use hashResults for a batch of "
              + context.size());
    }
    return hashResults(response, context).get(0);
  }

  /**
   * Decodes a hex field from the response.
   * <p>
   * Everything a hostile server can cause must present uniformly. BouncyCastle's
   * {@code DecoderException} extends {@link IllegalStateException}, so without this a server could
   * choose whether the application saw a {@link SecurityException} or an unrelated runtime error
   * simply by sending malformed hex — and an application catching {@code SecurityException} to
   * mean "the server misbehaved" would miss it. In a mode whose entire purpose is coping with a
   * hostile server, the failure type should not be the server's to pick.
   */
  private static byte[] decode(final String hex, final String what) {
    try {
      return Hex.decode(hex);
    } catch (RuntimeException e) {
      throw new SecurityException("Server returned malformed hex for " + what, e);
    }
  }

  private static boolean isIdentity(final byte[] element) {
    for (byte b : element) {
      if (b != 0) {
        return false;
      }
    }
    return true;
  }
}
