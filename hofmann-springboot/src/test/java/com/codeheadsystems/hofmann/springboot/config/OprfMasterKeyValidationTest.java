package com.codeheadsystems.hofmann.springboot.config;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.codeheadsystems.rfc.oprf.model.ServerProcessorDetail;
import com.codeheadsystems.rfc.oprf.rfc9497.CurveHashSuite;
import com.codeheadsystems.rfc.oprf.rfc9497.OprfCipherSuite;
import java.math.BigInteger;
import java.util.function.Supplier;
import org.junit.jupiter.api.Test;

/**
 * Pins the startup fail-fast behaviour at the configuration site itself.
 *
 * <p>Without these, deleting the validation from {@code serverProcessorDetailSupplier} leaves the
 * whole suite green: the per-request check in {@code OprfServerManager} still refuses the key, so
 * no identity element is ever emitted and nothing else notices. What is lost is failing at
 * startup instead of on every request, which is the entire reason the configuration site is
 * touched at all.
 */
class OprfMasterKeyValidationTest {

  private final HofmannAutoConfiguration autoConfig = new HofmannAutoConfiguration();

  private HofmannProperties propsWithKey(String hex) {
    HofmannProperties props = new HofmannProperties();
    props.setOprfMasterKeyHex(hex);
    return props;
  }

  @Test
  void zeroMasterKeyFailsAtStartup() {
    assertThatThrownBy(() -> autoConfig.serverProcessorDetailSupplier(propsWithKey("00")))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("congruent to zero");
  }

  @Test
  void masterKeyEqualToGroupOrderFailsAtStartup() {
    BigInteger n = OprfCipherSuite.builder()
        .withSuite(CurveHashSuite.P256_SHA256).build().groupSpec().groupOrder();

    assertThatThrownBy(() ->
        autoConfig.serverProcessorDetailSupplier(propsWithKey(n.toString(16))))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("congruent to zero");
  }

  @Test
  void missingMasterKeyFailsAtStartup() {
    assertThatThrownBy(() -> autoConfig.serverProcessorDetailSupplier(propsWithKey("")))
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining("oprfMasterKeyHex");
  }

  /** The key actually shipped in the test and demo configs must keep working. */
  @Test
  void realConfiguredKeyIsAcceptedAndNormalizedIntoRange() {
    String hex = "137564f38fb14059492bbab74f03624de228817bd877b74e6df5ac378878720e";
    Supplier<ServerProcessorDetail> supplier =
        autoConfig.serverProcessorDetailSupplier(propsWithKey(hex));
    BigInteger n = OprfCipherSuite.builder()
        .withSuite(CurveHashSuite.P256_SHA256).build().groupSpec().groupOrder();

    assertThat(supplier.get().masterKey()).isPositive().isLessThan(n);
  }

  /**
   * A key above the group order must be normalized rather than refused — refusing would break
   * every deployment whose key came from {@code openssl rand -hex 32}, and whose stored OPRF
   * outputs only that key reproduces.
   */
  @Test
  void keyAboveGroupOrderIsNormalizedNotRefused() {
    OprfCipherSuite suite =
        OprfCipherSuite.builder().withSuite(CurveHashSuite.P256_SHA256).build();
    BigInteger n = suite.groupSpec().groupOrder();
    BigInteger oversized = BigInteger.valueOf(987654321L).add(n);

    Supplier<ServerProcessorDetail> supplier =
        autoConfig.serverProcessorDetailSupplier(propsWithKey(oversized.toString(16)));

    assertThat(supplier.get().masterKey()).isEqualTo(BigInteger.valueOf(987654321L));
  }

  @Test
  void validKeyStartsCleanly() {
    assertThatCode(() -> autoConfig.serverProcessorDetailSupplier(propsWithKey("2a")))
        .doesNotThrowAnyException();
  }
}
