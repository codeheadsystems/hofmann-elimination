package com.codeheadsystems.rfc.oprf.model;

import java.math.BigInteger;
import java.util.Arrays;

/**
 * Client-side context for hashing: { requestId, blindingFactor, input }.
 *
 * <p><strong>The input is copied on construction, and {@link #close()} zeroes the copy.</strong>
 * Copying decouples this record's lifetime from the caller's array, so a caller who clears their
 * own buffer immediately after handing it over does not pull the value out from under an exchange
 * still in flight — and, conversely, closing this does not destroy a buffer the caller still owns.
 * The verifiable-mode contexts copy for the same reason; they gained {@code close()} alongside this
 * one so that "the library keeps an unclearable copy of your secret" stops being true of any of
 * the three.
 *
 * <p><strong>Do not read this as "the input is then gone from memory".</strong> {@code Arrays.fill}
 * clears one copy of one buffer. A moving collector may already have copied it, the page may
 * already be in swap or a core dump, and the JLS does not forbid eliminating a dead store. Treat
 * it as shortening the window on one copy.
 *
 * <p><strong>{@code blindingFactor} cannot be cleared at all</strong>, and taken together with the
 * blinded element derived from this same context it is what lets an observer recover the OPRF
 * output for this input. It is a {@link BigInteger}; nothing at the Java level can zero it. The
 * same caveat, for the same reason, appears on OPAQUE's {@code ClientAuthState}.
 *
 * @param requestId      a unique identifier for the request, used to correlate with the server's response
 * @param blindingFactor the random blinding factor used in the OPRF protocol, which should be kept secret and is used to blind the input before sending it to the server
 * @param input          the original input data that the client wants to hash using the OPRF protocol, which will be blinded and sent to the server for processing; copied, not retained
 */
public record ClientHashingContext(String requestId, BigInteger blindingFactor, byte[] input)
    implements AutoCloseable {

  /**
   * Copies the input so this record's lifetime is independent of the caller's array.
   *
   * @param requestId      correlates the request with its response
   * @param blindingFactor the blinding scalar
   * @param input          the client input; copied, not retained
   */
  public ClientHashingContext {
    if (input == null) {
      throw new IllegalArgumentException("Input is required");
    }
    input = input.clone();
  }

  /**
   * Returns this context's input array directly, <strong>not</strong> a copy.
   *
   * <p>Deliberately unlike {@link VoprfClientContext#inputs()}, which copies on read, and the
   * asymmetry is worth a sentence rather than being left for someone to notice. Copying on read
   * would mint a fresh unerasable plaintext copy of the secret on every access — two per exchange
   * on the normal path, since {@code eliminationRequest} and {@code hashResult} each read it —
   * which cuts directly against the reason this class copies and clears at all. The verifiable
   * contexts pay that cost to protect a batch whose list alignment is load-bearing; there is no
   * alignment to protect here.
   *
   * <p>The price is that a caller can mutate this context through the returned array. That is the
   * same contract as {@link #close()}: the array is live for the duration of the exchange and
   * changing it mid-exchange produces a wrong answer rather than an error.
   *
   * @return the input, live and shared with this context
   */
  @Override
  public byte[] input() {
    return input;
  }

  /**
   * Zeroes this record's copy of the input. Idempotent, and safe to call from a
   * {@code try}-with-resources around a whole exchange.
   *
   * <p>The caller still owns its own array; this clears what was copied, not what was given.
   *
   * <p><strong>Close this after the exchange, never during one — a closed context does not fail,
   * it answers wrongly.</strong> {@code eliminationRequest} and {@code hashResult} both read
   * {@code input}, so calling either against a closed context blinds or finalizes over a run of
   * zeroes: the call succeeds and returns a well-formed value derived from the wrong input. There
   * is no exception and nothing downstream notices. The verifiable modes are sharper still — see
   * {@link VoprfClientContext#close()}.
   *
   * <p>This is not currently guarded. A record cannot carry a mutable "closed" flag, so refusing
   * use-after-close needs this type to stop being a record, which is a larger change than the one
   * that introduced {@code close()}. Tracked in TODO.md. Until then the rule is the scope rule:
   * the {@code try}-with-resources must enclose the whole exchange, which is what makes an
   * asynchronous round trip the shape to watch for.
   */
  @Override
  public void close() {
    Arrays.fill(input, (byte) 0);
  }

  /**
   * Redacts the blinding factor and the input.
   *
   * <p>Same shape as {@link ServerProcessorDetail}: the generated {@code toString} would print
   * {@code blindingFactor} as its full decimal value. Disclosing a blind lets an observer unblind
   * the corresponding evaluated element and recover the OPRF output for that input — and on the
   * OPAQUE path that output is what the envelope keys derive from. {@code input} is redacted too
   * because it is the client's plaintext OPRF input.
   */
  @Override
  public String toString() {
    return "ClientHashingContext[requestId=" + requestId
        + ", blindingFactor=<redacted>, input=<redacted>]";
  }
}
