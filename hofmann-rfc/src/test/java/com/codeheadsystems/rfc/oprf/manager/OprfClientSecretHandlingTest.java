package com.codeheadsystems.rfc.oprf.manager;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.codeheadsystems.rfc.oprf.model.ClientHashingContext;
import com.codeheadsystems.rfc.oprf.model.PoprfClientContext;
import com.codeheadsystems.rfc.oprf.model.VoprfClientContext;
import com.codeheadsystems.rfc.oprf.model.VerifiableProcessorDetail;
import com.codeheadsystems.rfc.oprf.rfc9497.CurveHashSuite;
import com.codeheadsystems.rfc.oprf.rfc9497.OprfCipherSuite;
import com.codeheadsystems.rfc.oprf.rfc9497.OprfMode;
import java.lang.reflect.Field;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import org.junit.jupiter.api.Test;

/**
 * The OPRF client API lets a caller keep its secret in something erasable, and erases its own copy.
 *
 * <p>Base mode used to accept the input only as a {@link String}. A {@code String} is immutable, so
 * a secret placed in one cannot be overwritten — it sits on the heap until the collector happens to
 * reclaim it, and any interning or substring along the way has already made copies nobody holds a
 * reference to. Every other secret in this library is a {@code byte[]} for that reason, including
 * OPAQUE's password and the verifiable modes' inputs; base mode was the last place the API forced
 * a caller to give that up.
 *
 * <p>Two properties, and both are needed. The caller must be able to supply bytes — otherwise their
 * copy is unerasable — and the library must not keep an unerasable copy of its own, or the
 * boundary has just moved one frame inward.
 */
class OprfClientSecretHandlingTest {

  private static final OprfCipherSuite SUITE = OprfCipherSuite.builder()
      .withSuite(CurveHashSuite.P256_SHA256).build();

  private static byte[] secret() {
    return "correct-horse-battery-staple".getBytes(StandardCharsets.UTF_8);
  }

  /** The byte[] entry point exists and is the one that carries the exchange. */
  @Test
  void aByteArrayInputIsAccepted() {
    OprfClientManager manager = new OprfClientManager(SUITE);
    byte[] secret = secret();

    try (ClientHashingContext context = manager.hashingContext(secret)) {
      assertThat(context.input()).isEqualTo(secret);
      assertThat(manager.eliminationRequest(context).blindedPoint()).isNotBlank();
    }
  }

  /**
   * The caller's array is not the context's, so clearing one does not disturb the other.
   *
   * <p>This is what makes "clear your own buffer as soon as the call returns" safe advice. Holding
   * the caller's array by reference would mean an exchange still in flight reads whatever the
   * caller did to it — the bug OPAQUE's {@code ClientAuthState} was fixed for.
   */
  @Test
  void theCallersArrayAndTheContextsCopyAreIndependent() {
    OprfClientManager manager = new OprfClientManager(SUITE);
    byte[] secret = secret();
    byte[] expected = secret.clone();

    ClientHashingContext context = manager.hashingContext(secret);
    Arrays.fill(secret, (byte) 0);

    // input() aliases rather than copies, so this reference is the context's own array and still
    // shows the zeroing after close — which input() itself will no longer answer for.
    byte[] contextsOwnArray = context.input();
    assertThat(contextsOwnArray)
        .as("clearing the caller's array must not empty the context")
        .isEqualTo(expected);

    context.close();
    assertThat(contextsOwnArray)
        .as("and closing the context must clear its own copy")
        .containsOnly((byte) 0);
  }

  /**
   * Closing clears the copy — the half that stops the boundary from being cosmetic.
   *
   * <p>A byte[] API that copies into something the caller cannot reach has not removed an
   * unerasable copy of the secret, it has only moved it out of sight.
   */
  @Test
  void closingZeroesTheContextsCopy() {
    OprfClientManager manager = new OprfClientManager(SUITE);
    ClientHashingContext context = manager.hashingContext(secret());
    byte[] contextsOwnArray = context.input();

    assertThat(contextsOwnArray).isNotEqualTo(new byte[secret().length]);
    context.close();
    assertThat(contextsOwnArray).containsOnly((byte) 0);
    context.close();
    assertThat(contextsOwnArray)
        .as("close is idempotent, so a try-with-resources around a caller that also closes is fine")
        .containsOnly((byte) 0);
  }

  /** The String overload still works, and produces the same context a byte[] would. */
  @Test
  void theStringOverloadStillWorksAndAgreesWithTheByteArrayOne() {
    OprfClientManager manager = new OprfClientManager(SUITE);
    try (ClientHashingContext fromString = manager.hashingContext("correct-horse-battery-staple");
         ClientHashingContext fromBytes = manager.hashingContext(secret())) {
      assertThat(fromString.input()).isEqualTo(fromBytes.input());
    }
  }

  /** Null is rejected at the door rather than surfacing later as an NPE from hashToGroup. */
  @Test
  void nullInputIsRejected() {
    OprfClientManager manager = new OprfClientManager(SUITE);
    assertThatThrownBy(() -> manager.hashingContext((byte[]) null))
        .isInstanceOf(IllegalArgumentException.class);
    assertThatThrownBy(() -> manager.hashingContext((String) null))
        .isInstanceOf(IllegalArgumentException.class);
  }

  /**
   * The verifiable modes close too, so the property does not depend on which mode you picked.
   *
   * <p>They already took {@code byte[]} and already copied it; what they lacked was any way for the
   * caller to clear that copy. Fixing base mode alone would have left the library holding an
   * unerasable secret in two modes out of three.
   */
  @Test
  void theVerifiableModeContextsAlsoClear() {
    OprfCipherSuite vsuite = OprfCipherSuite.builder()
        .withSuite(CurveHashSuite.P256_SHA256).withMode(OprfMode.VOPRF).build();
    VerifiableProcessorDetail vd =
        VerifiableProcessorDetail.derive(vsuite, vsuite.randomScalar(), "key-v1");
    VoprfClientManager voprf = new VoprfClientManager(vsuite, vd.publicKey());
    VoprfClientContext vctx = voprf.hashingContext(List.of(secret()));
    assertThat(vctx.inputs().get(0)).isEqualTo(secret());
    vctx.close();
    assertThat(heldInputs(vctx).get(0))
        .as("VOPRF context must clear its copy of the input")
        .containsOnly((byte) 0);

    OprfCipherSuite psuite = OprfCipherSuite.builder()
        .withSuite(CurveHashSuite.P256_SHA256).withMode(OprfMode.POPRF).build();
    VerifiableProcessorDetail pd =
        VerifiableProcessorDetail.derive(psuite, psuite.randomScalar(), "key-v1");
    PoprfClientManager poprf = new PoprfClientManager(psuite, pd.publicKey());
    byte[] info = "public-info".getBytes(StandardCharsets.UTF_8);
    PoprfClientContext pctx = poprf.hashingContext(List.of(secret()), info);
    assertThat(pctx.inputs().get(0)).isEqualTo(secret());
    byte[] publicInputBefore = pctx.info();
    pctx.close();
    assertThat(heldInputs(pctx).get(0))
        .as("POPRF context must clear its copy of the input")
        .containsOnly((byte) 0);
    assertThat(publicInputBefore)
        .as("but not the public input, which is not a secret")
        .isEqualTo(info);
    assertThat(heldInfo(pctx))
        .as("and the context's own copy of it is left alone too")
        .isEqualTo(info);
  }

  /**
   * Reads the list of inputs a context is holding, without going through {@code inputs()}.
   *
   * <p>Needed because the verifiable-mode accessors copy on read <em>and</em> now refuse once
   * closed, so neither a before-reference nor an after-call can observe the zeroing the way
   * {@code ClientHashingContext.input()} allows. Reflection is the established idiom for this in
   * the tree ({@code ByteUtilsTest}, {@code PackageBoundaryTest},
   * {@code HofmannOpaqueClientManagerZeroizationTest}), and the alternative — a package-private
   * accessor existing only for tests — would put a hole in production code to observe a property
   * of production code.
   */
  @SuppressWarnings("unchecked")
  private static List<byte[]> heldInputs(final Object context) {
    return (List<byte[]>) read(context, "inputs");
  }

  private static byte[] heldInfo(final PoprfClientContext context) {
    return (byte[]) read(context, "info");
  }

  private static Object read(final Object target, final String fieldName) {
    try {
      Field field = target.getClass().getDeclaredField(fieldName);
      field.setAccessible(true);
      return field.get(target);
    } catch (ReflectiveOperationException e) {
      throw new AssertionError("could not read " + fieldName, e);
    }
  }
}
