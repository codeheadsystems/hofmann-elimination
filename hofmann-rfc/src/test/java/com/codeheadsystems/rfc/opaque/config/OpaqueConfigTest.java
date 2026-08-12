package com.codeheadsystems.rfc.opaque.config;

import static org.assertj.core.api.Assertions.assertThat;

import com.codeheadsystems.rfc.common.RandomProvider;
import com.codeheadsystems.rfc.opaque.testfixtures.OpaqueTestConfigs;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;

class OpaqueConfigTest {

  // --- Factory methods ---

  /**
   * Kept, unlike the sibling factory tests removed below, because these are not stored arguments:
   * they are the shipped defaults a deployment gets by saying nothing. Argon2id at 64 MiB with
   * three iterations is the cost an offline attacker pays per password guess, so silently
   * lowering it is a security change and this is the test that makes it a loud one.
   */
  @Test
  void default_usesP256AndArgon2WithTheDocumentedCost() {
    OpaqueConfig config = OpaqueConfig.DEFAULT;
    assertThat(config.cipherSuite()).isSameAs(OpaqueCipherSuite.P256_SHA256);
    assertThat(config.ksf()).isInstanceOf(OpaqueConfig.Argon2idKsf.class);
    assertThat(config.argon2Memory()).isEqualTo(65536);
    assertThat(config.argon2Iterations()).isEqualTo(3);
    assertThat(config.argon2Parallelism()).isEqualTo(1);
  }

  /**
   * The test fixture must stay the identity KSF. Not an accessor check: if this fixture ever
   * acquired a real KSF the whole rfc suite would slow to Argon2id speed per test, and if a
   * production default leaked into it the vector tests would silently stop reproducing RFC 9807.
   */
  @Test
  void forTesting_usesIdentityKsfAndTheCfrgContext() {
    OpaqueConfig config = OpaqueTestConfigs.forTesting();
    assertThat(config.cipherSuite()).isSameAs(OpaqueCipherSuite.P256_SHA256);
    assertThat(config.ksf()).isInstanceOf(OpaqueConfig.IdentityKsf.class);
    assertThat(config.context()).isEqualTo("OPAQUE-POC".getBytes(StandardCharsets.US_ASCII));
  }

  // Removed: forTesting_withSuite_usesGivenSuite, withArgon2id_noSuite_usesP256 and
  // withArgon2id_withSuite_usesGivenSuite. Each handed a factory a suite and some Argon2
  // parameters and asserted the returned record held them — the compiler's job, not a test's.
  // The suite argument is exercised for real by every @MethodSource("allSuites") test in this
  // package, and the Argon2 parameters by argon2idKsf_producesCorrectLengthOutput below.

  // --- withRandomConfig ---

  @Test
  void withRandomConfig_preservesOtherFields() {
    OpaqueConfig original = OpaqueTestConfigs.forTesting();
    RandomProvider rp = new RandomProvider();
    OpaqueConfig copy = original.withRandomConfig(rp);
    assertThat(copy.randomProvider()).isSameAs(rp);
    assertThat(copy.cipherSuite()).isSameAs(original.cipherSuite());
    assertThat(copy.ksf()).isSameAs(original.ksf());
    assertThat(copy.context()).isEqualTo(original.context());
  }

  // Removed: sizeDelegates_matchCipherSuite, which asserted config.Nm() == cipherSuite.Nm() and
  // eight more of the same. Every one of those methods is a one-line delegation, so the assertion
  // holds for any value the suite returns and fails only if the delegation is deleted outright.
  // The values themselves are pinned where they mean something — against RFC 9807's fixed-size
  // wire fields in OpaqueVectorsTest.
  //
  // Removed: nn_isAlways32, which asserted a constant equalled its own literal.

  // --- IdentityKsf ---

  @Test
  void identityKsf_returnsInputUnchanged() {
    OpaqueConfig.IdentityKsf ksf = new OpaqueConfig.IdentityKsf();
    byte[] input = {1, 2, 3, 4, 5};
    byte[] result = ksf.stretch(input, OpaqueTestConfigs.forTesting());
    assertThat(result).isSameAs(input);
  }

  // --- Argon2idKsf ---

  @Test
  void argon2idKsf_producesCorrectLengthOutput() {
    OpaqueConfig config = OpaqueConfig.withArgon2id(
        "ctx".getBytes(StandardCharsets.UTF_8), 1024, 1, 1);
    byte[] input = "password".getBytes(StandardCharsets.UTF_8);
    byte[] result = config.ksf().stretch(input, config);
    assertThat(result).hasSize(config.Nh());
  }

  @Test
  void argon2idKsf_isDeterministic() {
    OpaqueConfig config = OpaqueConfig.withArgon2id(
        "ctx".getBytes(StandardCharsets.UTF_8), 1024, 1, 1);
    byte[] input = "password".getBytes(StandardCharsets.UTF_8);
    byte[] r1 = config.ksf().stretch(input, config);
    byte[] r2 = config.ksf().stretch(input, config);
    assertThat(r1).isEqualTo(r2);
  }
}
