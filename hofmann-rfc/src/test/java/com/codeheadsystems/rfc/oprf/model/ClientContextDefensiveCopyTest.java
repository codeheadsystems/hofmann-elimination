package com.codeheadsystems.rfc.oprf.model;

import static org.assertj.core.api.Assertions.assertThat;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;

/**
 * The client contexts must not alias the caller's arrays, in either direction.
 *
 * <p>{@code List.copyOf} makes the <em>list</em> immutable but leaves every {@code byte[]} element
 * pointing at the caller's array, so a context could still be mutated after construction through a
 * reference the caller kept — and equally, a caller could reach into a context through an accessor
 * and mutate the state it holds.
 *
 * <p>{@code PoprfClientContext.tweakedKey} is the one where this has teeth. It is the client's own
 * {@code m*G + pkS}, and DLEQ verification grades the server's proof against it. Changing it
 * between construction and verification swaps the statement being proved, so a proof computed for
 * a different public input would verify — defeating the binding the type exists to enforce.
 */
class ClientContextDefensiveCopyTest {

  private static List<byte[]> mutableListOf(byte[]... values) {
    return new ArrayList<>(List.of(values));
  }

  private static PoprfClientContext poprf(byte[] input, byte[] blinded, byte[] info,
                                          byte[] tweakedKey) {
    return new PoprfClientContext("req-1", mutableListOf(input), List.of(BigInteger.ONE),
        mutableListOf(blinded), info, tweakedKey);
  }

  @Test
  void poprf_mutatingTheCallersTweakedKeyAfterConstruction_doesNotChangeTheContext() {
    byte[] tweakedKey = new byte[]{1, 2, 3, 4};
    PoprfClientContext ctx = poprf(new byte[]{9}, new byte[]{8}, new byte[]{7}, tweakedKey);

    tweakedKey[0] = 0x7f;

    assertThat(ctx.tweakedKey())
        .as("the key the proof is graded against must not follow the caller's array")
        .containsExactly(1, 2, 3, 4);
  }

  @Test
  void poprf_mutatingTheReturnedTweakedKey_doesNotChangeTheContext() {
    PoprfClientContext ctx = poprf(new byte[]{9}, new byte[]{8}, new byte[]{7},
        new byte[]{1, 2, 3, 4});

    ctx.tweakedKey()[0] = 0x7f;

    assertThat(ctx.tweakedKey()).containsExactly(1, 2, 3, 4);
  }

  @Test
  void poprf_infoIsCopiedBothWays() {
    byte[] info = new byte[]{10, 20};
    PoprfClientContext ctx = poprf(new byte[]{9}, new byte[]{8}, info, new byte[]{1});

    info[0] = 99;
    ctx.info()[1] = 99;

    assertThat(ctx.info()).containsExactly(10, 20);
  }

  @Test
  void poprf_listElementsAreCopiedBothWays() {
    byte[] input = new byte[]{1, 1};
    byte[] blinded = new byte[]{2, 2};
    PoprfClientContext ctx = poprf(input, blinded, new byte[]{7}, new byte[]{1});

    input[0] = 99;
    blinded[0] = 99;
    ctx.inputs().get(0)[1] = 99;
    ctx.blindedElements().get(0)[1] = 99;

    assertThat(ctx.inputs().get(0)).containsExactly(1, 1);
    assertThat(ctx.blindedElements().get(0)).containsExactly(2, 2);
  }

  @Test
  void voprf_listElementsAreCopiedBothWays() {
    byte[] input = new byte[]{1, 1};
    byte[] blinded = new byte[]{2, 2};
    VoprfClientContext ctx = new VoprfClientContext("req-1", mutableListOf(input),
        List.of(BigInteger.ONE), mutableListOf(blinded));

    input[0] = 99;
    blinded[0] = 99;
    ctx.inputs().get(0)[1] = 99;
    ctx.blindedElements().get(0)[1] = 99;

    assertThat(ctx.inputs().get(0)).containsExactly(1, 1);
    assertThat(ctx.blindedElements().get(0)).containsExactly(2, 2);
  }

  @Test
  void addingToTheCallersListAfterConstruction_doesNotChangeTheBatch() {
    List<byte[]> inputs = mutableListOf(new byte[]{1});
    List<byte[]> blinded = mutableListOf(new byte[]{2});
    VoprfClientContext ctx = new VoprfClientContext("req-1", inputs, List.of(BigInteger.ONE),
        blinded);

    inputs.add(new byte[]{3});
    blinded.add(new byte[]{4});

    assertThat(ctx.size()).isEqualTo(1);
    assertThat(ctx.inputs()).hasSize(1);
  }
}
