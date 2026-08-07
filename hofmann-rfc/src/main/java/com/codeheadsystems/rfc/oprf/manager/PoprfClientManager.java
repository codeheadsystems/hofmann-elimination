package com.codeheadsystems.rfc.oprf.manager;

import com.codeheadsystems.rfc.ellipticcurve.rfc9380.GroupSpec;
import com.codeheadsystems.rfc.ellipticcurve.rfc9380.IdentityResultException;
import com.codeheadsystems.rfc.oprf.model.HashResult;
import com.codeheadsystems.rfc.oprf.model.PartiallyBlindedRequest;
import com.codeheadsystems.rfc.oprf.model.PartiallyEvaluatedResponse;
import com.codeheadsystems.rfc.oprf.model.PoprfClientContext;
import com.codeheadsystems.rfc.oprf.rfc9497.OprfCipherSuite;
import com.codeheadsystems.rfc.oprf.rfc9497.OprfMode;
import com.codeheadsystems.rfc.oprf.rfc9497.PublicInput;
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
 * RFC 9497 §3.3.3 POPRF client: evaluates an input under a public input both parties agree on.
 * <p>
 * The public input is exactly that — public. The server sees it in the clear, and it is folded
 * into the output, so it separates evaluations without hiding anything. RFC 9497 §5.4 recommends
 * applications give it higher-level, prefix-free domain separation rather than passing raw
 * user-controlled text.
 * <p>
 * As in VOPRF, the server public key is supplied at construction and must have been authenticated
 * out of band. The client derives its own tweaked key from that key and its own {@code info}, and
 * grades the proof against that — never against anything the server sends. This is what ties a
 * response to the requested public input: a server evaluating under different {@code info}
 * produces a proof against a different tweaked key, and verification fails.
 */
public class PoprfClientManager {

  private static final Logger log = LoggerFactory.getLogger(PoprfClientManager.class);

  private final OprfCipherSuite suite;
  private final GroupSpec groupSpec;
  private final byte[] serverPublicKey;

  /**
   * Instantiates a new POPRF client manager.
   *
   * @param suite           the cipher suite, which must be in POPRF mode
   * @param serverPublicKey the server's out-of-band authenticated public key
   */
  public PoprfClientManager(final OprfCipherSuite suite, final byte[] serverPublicKey) {
    suite.assertMode(OprfMode.POPRF);
    suite.groupSpec().validateElement(serverPublicKey);
    this.suite = suite;
    this.groupSpec = suite.groupSpec();
    this.serverPublicKey = serverPublicKey.clone();
    log.info("PoprfClientManager({})", suite.identifier());
  }

  /**
   * Creates a context for a single input under a public input.
   *
   * @param sensitiveData the input to evaluate
   * @param info          the public input
   * @return the context
   */
  public PoprfClientContext hashingContext(final String sensitiveData, final byte[] info) {
    return hashingContext(List.of(sensitiveData.getBytes(StandardCharsets.UTF_8)), info);
  }

  /**
   * Creates a context for a batch of inputs, all under one public input and one proof.
   *
   * @param inputs the inputs to evaluate
   * @param info   the public input
   * @return the context
   */
  public PoprfClientContext hashingContext(final List<byte[]> inputs, final byte[] info) {
    if (inputs == null || inputs.isEmpty()) {
      throw new IllegalArgumentException("At least one input is required");
    }
    PublicInput.validate(info);

    final String requestId = UUID.randomUUID().toString();
    BigInteger m = PublicInput.toScalar(suite, info);
    byte[] tweakedKey = deriveTweakedKey(m);

    List<byte[]> copied = new ArrayList<>(inputs.size());
    List<BigInteger> blinds = new ArrayList<>(inputs.size());
    List<byte[]> blindedElements = new ArrayList<>(inputs.size());

    for (byte[] input : inputs) {
      byte[] hashed = groupSpec.hashToGroup(input, suite.hashToGroupDst());
      if (isIdentity(hashed)) {
        throw new IllegalArgumentException("HashToGroup produced the identity element");
      }
      BigInteger blind = suite.randomScalar();
      copied.add(input.clone());
      blinds.add(blind);
      blindedElements.add(groupSpec.scalarMultiply(blind, hashed));
    }
    return new PoprfClientContext(
        requestId, copied, blinds, blindedElements, info.clone(), tweakedKey);
  }

  /**
   * Computes {@code tweakedKey = m * G + pkS}.
   * <p>
   * Built as a single multi-scalar operation rather than {@code add(scalarMultiplyGenerator(m),
   * pkS)}. The two are arithmetically the same, but the composed form hands {@code add} an
   * identity encoding whenever {@code m} is zero, and that surfaces as a complaint about a
   * malformed input element rather than as the identity result RFC 9497 §3.3.3 asks the client to
   * detect.
   */
  private byte[] deriveTweakedKey(final BigInteger m) {
    try {
      return groupSpec.linearCombinationPublic(
          new BigInteger[]{m, BigInteger.ONE},
          new byte[][]{groupSpec.generator(), serverPublicKey});
    } catch (IdentityResultException e) {
      // §3.3.3 Blind raises InvalidInputError here. Reaching it means the public input hashed to
      // the negation of the server's secret key — the same condition that makes the server's
      // tweaked key zero, and equally a sign the caller knows that key.
      throw new IllegalArgumentException(
          "Public input tweaks the server key to the identity element; it cannot be used", e);
    }
  }

  /**
   * Builds the wire request for a context.
   *
   * @param context the context
   * @return the request
   */
  public PartiallyBlindedRequest eliminationRequest(final PoprfClientContext context) {
    List<String> points = new ArrayList<>(context.size());
    for (byte[] element : context.blindedElements()) {
      points.add(Hex.toHexString(element));
    }
    return new PartiallyBlindedRequest(
        points, Hex.toHexString(context.info()), context.requestId());
  }

  /**
   * Verifies the server's proof and, only if it holds, unblinds every evaluated element.
   * <p>
   * A returned {@link HashResult} carries the server's {@code processIdentifier} verbatim; the
   * hash is trustworthy but that label is not, since a misbehaving server can attach any
   * identifier to a correctly-evaluated result.
   *
   * @param response the server response
   * @param context  the context the request was built from
   * @return one result per input, aligned with the context's inputs
   * @throws SecurityException if the proof does not verify, the response length does not match the
   *                           request, or any field is malformed
   */
  public List<HashResult> hashResults(final PartiallyEvaluatedResponse response,
                                      final PoprfClientContext context) {
    if (response.evaluatedPoints().size() != context.size()) {
      throw new SecurityException(
          "Server returned " + response.evaluatedPoints().size() + " evaluated elements for "
              + context.size() + " blinded elements");
    }

    byte[][] blindedElements = context.blindedElements().toArray(new byte[0][]);
    byte[][] evaluatedElements = new byte[context.size()][];
    for (int i = 0; i < context.size(); i++) {
      byte[] evaluated = decode(response.evaluatedPoints().get(i), "evaluated element " + i);
      groupSpec.validateElement(evaluated);
      evaluatedElements[i] = evaluated;
    }

    DleqProof proof = DleqProof.deserialize(suite, decode(response.proof(), "proof"));
    // Graded against the client's own tweaked key, with the element lists in POPRF order —
    // evaluated first, because blindedElement = t * evaluatedElement.
    if (!DleqVerifier.verifyProof(
        suite, context.tweakedKey(), evaluatedElements, blindedElements, proof)) {
      throw new SecurityException(
          "POPRF proof did not verify for processor '" + response.processIdentifier()
              + "'; the server did not evaluate with the committed key under this public input");
    }

    // Hoisted out of the loop, info included. The accessors now deep-copy, so calling them per
    // element made this quadratic: at the 1024 batch cap with 4 KB inputs that is ~0.32 s of pure
    // copying and gigabytes of transient allocation, against microseconds hoisted. It also
    // produced n^2 unzeroed heap copies of the client's plaintext.
    List<byte[]> inputs = context.inputs();
    List<BigInteger> blinds = context.blinds();
    byte[] info = context.info();
    List<HashResult> results = new ArrayList<>(context.size());
    for (int i = 0; i < context.size(); i++) {
      byte[] hash = suite.finalizeWithInfo(
          inputs.get(i), info, blinds.get(i), evaluatedElements[i]);
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
  public HashResult hashResult(final PartiallyEvaluatedResponse response,
                               final PoprfClientContext context) {
    if (context.size() != 1) {
      throw new IllegalArgumentException(
          "hashResult is for single-input contexts; use hashResults for a batch of "
              + context.size());
    }
    return hashResults(response, context).get(0);
  }

  /**
   * Decodes a hex field from the response, so that a hostile server cannot choose which exception
   * type the application sees by sending malformed input.
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
