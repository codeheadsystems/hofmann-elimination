package com.codeheadsystems.rfc.opaque.internal;

import static org.assertj.core.api.Assertions.assertThat;

import com.codeheadsystems.rfc.common.RandomProvider;
import com.codeheadsystems.rfc.opaque.config.OpaqueCipherSuite;
import com.codeheadsystems.rfc.opaque.config.OpaqueConfig;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;

/**
 * Zeroization of the password-equivalent intermediates in {@link OpaqueCredentials}.
 *
 * <p>{@code randomizedPwd} is the value from which the envelope keys, the masking key and the
 * client's long-term private key all derive, so recovering it from a heap dump or a swap page is
 * equivalent to recovering the password — no guessing required. The two values it is built from
 * are equally strong: {@code oprfOutput} is a deterministic function of the password under the
 * server's OPRF key, and {@code stretchedOutput} is the KSF applied to that. None of the three
 * was being cleared.
 *
 * <p>The KSF is the one seam in this path that a test can hold on to: it is handed
 * {@code oprfOutput} and its return value becomes {@code stretchedOutput}, so a recording
 * implementation keeps live references to both and can assert on them after the call returns.
 * The remaining intermediates — {@code randomizedPwd} itself, and the envelope's {@code authKey}
 * and private-key seed — are method-local with no seam to observe them through, so those are
 * covered by reading rather than by assertion. Said plainly rather than left implied.
 */
class OpaqueCredentialsZeroizationTest {

  private static final byte[] PASSWORD = "correct-horse-battery-staple".getBytes(StandardCharsets.UTF_8);

  /** Hands back a fresh array so {@code stretchedOutput} is distinguishable from its input. */
  private static class RecordingKsf implements OpaqueConfig.KeyStretchingFunction {
    private final List<byte[]> inputs = new ArrayList<>();
    private final List<byte[]> outputs = new ArrayList<>();

    @Override
    public byte[] stretch(byte[] input, OpaqueConfig config) {
      inputs.add(input);
      byte[] out = new byte[config.Nh()];
      // Content is irrelevant to what is being asserted, but make it non-zero so an "all zero"
      // assertion below cannot pass merely because nothing ever wrote to it.
      java.util.Arrays.fill(out, (byte) 0x5a);
      outputs.add(out);
      return out;
    }
  }

  private OpaqueConfig configWith(RecordingKsf ksf) {
    return new OpaqueConfig(OpaqueCipherSuite.P256_SHA256, 0, 0, 0,
        "zeroization-test".getBytes(StandardCharsets.UTF_8), ksf, new RandomProvider());
  }

  @Test
  void deriveRandomizedPwd_zerosBothOprfOutputAndStretchedOutput() {
    RecordingKsf ksf = new RecordingKsf();
    OpaqueConfig config = configWith(ksf);
    BigInteger blind = config.cipherSuite().oprfSuite().randomScalar();
    byte[] blindedElement = OpaqueOprf.blind(config.cipherSuite(), PASSWORD, blind);
    BigInteger oprfKey = config.cipherSuite().oprfSuite().randomScalar();
    byte[] evaluated = OpaqueOprf.blindEvaluate(config.cipherSuite(), oprfKey, blindedElement);

    byte[] randomizedPwd =
        OpaqueCredentials.deriveRandomizedPwd(PASSWORD, blind, evaluated, config);

    assertThat(ksf.inputs).hasSize(1);
    assertThat(ksf.outputs).hasSize(1);
    assertThat(ksf.inputs.get(0))
        .as("oprfOutput is password-equivalent under the server key and must not survive")
        .containsOnly((byte) 0);
    assertThat(ksf.outputs.get(0))
        .as("stretchedOutput was 0x5a-filled by the KSF, so all-zero here means it was cleared")
        .containsOnly((byte) 0);
    // The return value belongs to the caller and must NOT have been zeroed — clearing it here
    // would break every caller silently rather than visibly.
    assertThat(randomizedPwd).isNotEmpty().isNotEqualTo(new byte[randomizedPwd.length]);
  }

  /**
   * The clearing must happen after the concatenation that feeds the extract, not before.
   *
   * <p>The identity KSF returns its input array rather than a copy, so {@code oprfOutput} and
   * {@code stretchedOutput} are the same object under that config and the clearing code zeroes it
   * twice. Harmless — but only given the ordering, and reversing it would derive the randomized
   * password from a buffer of zeros: stable, plausible, identical for every password, and silent.
   *
   * <p><strong>This assertion is against the zeros-derived value specifically.</strong> An earlier
   * version compared two invocations to each other and claimed to pin the ordering; a reviewer
   * moved the fills above the concat and it still passed, because under the bug both runs produce
   * the same wrong answer. Comparing a computation with itself proves nothing about which inputs
   * it used. The real protection was coming from the RFC vector tests all along.
   */
  @Test
  void deriveRandomizedPwd_derivesFromTheRealInputsRatherThanTheClearedOnes() {
    OpaqueConfig identity = new OpaqueConfig(OpaqueCipherSuite.P256_SHA256, 0, 0, 0,
        "zeroization-test".getBytes(StandardCharsets.UTF_8),
        new OpaqueConfig.IdentityKsf(), new RandomProvider());
    BigInteger blind = identity.cipherSuite().oprfSuite().randomScalar();
    byte[] blindedElement = OpaqueOprf.blind(identity.cipherSuite(), PASSWORD, blind);
    BigInteger oprfKey = identity.cipherSuite().oprfSuite().randomScalar();
    byte[] evaluated = OpaqueOprf.blindEvaluate(identity.cipherSuite(), oprfKey, blindedElement);

    byte[] actual = OpaqueCredentials.deriveRandomizedPwd(PASSWORD, blind, evaluated, identity);

    // What the function would return if oprfOutput and stretchedOutput had been cleared first:
    // under IdentityKsf both are Nh bytes and alias, so the ikm would be 2 * Nh zeros.
    byte[] ifClearedTooEarly = identity.cipherSuite()
        .hkdfExtract(new byte[0], new byte[2 * identity.Nh()]);

    assertThat(actual)
        .as("deriving from cleared buffers would be silent: same value for every password")
        .isNotEqualTo(ifClearedTooEarly);
  }

  /** Different passwords must not collapse to one value — the observable symptom of the above. */
  @Test
  void deriveRandomizedPwd_differsBetweenPasswords() {
    OpaqueConfig identity = new OpaqueConfig(OpaqueCipherSuite.P256_SHA256, 0, 0, 0,
        "zeroization-test".getBytes(StandardCharsets.UTF_8),
        new OpaqueConfig.IdentityKsf(), new RandomProvider());
    BigInteger oprfKey = identity.cipherSuite().oprfSuite().randomScalar();

    byte[] a = derive(identity, PASSWORD, oprfKey);
    byte[] b = derive(identity, "a-different-password".getBytes(StandardCharsets.UTF_8), oprfKey);

    assertThat(a).isNotEqualTo(b);
  }

  private byte[] derive(OpaqueConfig config, byte[] password, BigInteger oprfKey) {
    BigInteger blind = config.cipherSuite().oprfSuite().randomScalar();
    byte[] blindedElement = OpaqueOprf.blind(config.cipherSuite(), password, blind);
    byte[] evaluated = OpaqueOprf.blindEvaluate(config.cipherSuite(), oprfKey, blindedElement);
    return OpaqueCredentials.deriveRandomizedPwd(password, blind, evaluated, config);
  }
}
