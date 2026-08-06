package com.codeheadsystems.rfc.oprf.manager;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.codeheadsystems.rfc.oprf.model.BlindedRequest;
import com.codeheadsystems.rfc.oprf.model.EvaluatedResponse;
import com.codeheadsystems.rfc.oprf.model.ServerProcessorDetail;
import com.codeheadsystems.rfc.oprf.rfc9497.CurveHashSuite;
import com.codeheadsystems.rfc.oprf.rfc9497.OprfCipherSuite;
import java.math.BigInteger;
import java.util.concurrent.atomic.AtomicInteger;
import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

/**
 * The OPRF secret key was read straight out of configuration with
 * {@code new BigInteger(masterKeyHex, 16)} and never checked.
 *
 * <p>The fatal value is a key congruent to zero modulo the group order: {@code BlindEvaluate}
 * then returns the identity for every request, and on ristretto255 the identity is a decodable
 * encoding, so a deployment configured with {@code oprfMasterKeyHex: "00"} would serve traffic
 * normally while having no effective key at all.
 *
 * <p>A key merely at or above the order is NOT fatal and must not be refused — scalar
 * multiplication reduces modulo the order, so it already works, and the documented
 * {@code openssl rand -hex 32} exceeds ristretto255's order about 94% of the time. Those keys are
 * normalized instead, which is transparent: {@code k} and {@code k mod n} produce byte-identical
 * output. Normalizing makes the equivalence explicit so two configs differing by a multiple of
 * the order stop looking like distinct keys a rotation could move between.
 */
class OprfServerKeyValidationTest {

  private static OprfCipherSuite suite(CurveHashSuite s) {
    return OprfCipherSuite.builder().withSuite(s).build();
  }

  @ParameterizedTest
  @EnumSource(CurveHashSuite.class)
  void zeroKeyIsRejected(CurveHashSuite s) {
    assertThatThrownBy(() -> suite(s).validateSecretKey(BigInteger.ZERO))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("congruent to zero");
  }

  @ParameterizedTest
  @EnumSource(CurveHashSuite.class)
  void negativeKeyIsRejected(CurveHashSuite s) {
    assertThatThrownBy(() -> suite(s).validateSecretKey(BigInteger.valueOf(-1)))
        .isInstanceOf(IllegalArgumentException.class);
  }

  @ParameterizedTest
  @EnumSource(CurveHashSuite.class)
  void nullKeyIsRejected(CurveHashSuite s) {
    assertThatThrownBy(() -> suite(s).validateSecretKey(null))
        .isInstanceOf(IllegalArgumentException.class);
  }

  /** k == n is congruent to zero, so it is the fatal case rather than merely out of range. */
  @ParameterizedTest
  @EnumSource(CurveHashSuite.class)
  void keyEqualToGroupOrderIsRejected(CurveHashSuite s) {
    OprfCipherSuite cs = suite(s);
    assertThatThrownBy(() -> cs.validateSecretKey(cs.groupSpec().groupOrder()))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("congruent to zero");
  }

  /**
   * A key above the order must NOT be refused. It already works — scalar multiplication reduces
   * modulo the order — and the documented `openssl rand -hex 32` exceeds ristretto255's order
   * about 94% of the time, so refusing would break existing deployments whose stored OPRF
   * outputs only that key can reproduce.
   */
  @ParameterizedTest
  @EnumSource(CurveHashSuite.class)
  void keyAboveGroupOrderIsAcceptedAndNormalized(CurveHashSuite s) {
    OprfCipherSuite cs = suite(s);
    BigInteger n = cs.groupSpec().groupOrder();
    BigInteger oversized = BigInteger.valueOf(1234567).add(n);

    assertThatCode(() -> cs.validateSecretKey(oversized)).doesNotThrowAnyException();
    assertThat(cs.normalizeSecretKey(oversized)).isEqualTo(BigInteger.valueOf(1234567));
  }

  /** A full-width 32-byte key, as the documented generation recipe produces. */
  @ParameterizedTest
  @EnumSource(CurveHashSuite.class)
  void fullWidthRandomKeyIsAccepted(CurveHashSuite s) {
    OprfCipherSuite cs = suite(s);
    BigInteger fullWidth = new BigInteger(
        "137564f38fb14059492bbab74f03624de228817bd877b74e6df5ac378878720e", 16);

    assertThatCode(() -> cs.validateSecretKey(fullWidth)).doesNotThrowAnyException();
    BigInteger normalized = cs.normalizeSecretKey(fullWidth);
    assertThat(normalized).isPositive().isLessThan(cs.groupSpec().groupOrder());
  }

  /** Normalizing must never change what the server computes. */
  @ParameterizedTest
  @EnumSource(CurveHashSuite.class)
  void normalizingDoesNotChangeAnyOutput(CurveHashSuite s) {
    OprfCipherSuite cs = suite(s);
    BigInteger configured = new BigInteger(
        "137564f38fb14059492bbab74f03624de228817bd877b74e6df5ac378878720e", 16);
    byte[] element = cs.groupSpec().scalarMultiplyGenerator(BigInteger.valueOf(9));

    assertThat(cs.groupSpec().scalarMultiply(cs.normalizeSecretKey(configured), element))
        .as("normalization must be transparent, or every stored OPRF output would change")
        .isEqualTo(cs.groupSpec().scalarMultiply(configured, element));
  }

  @ParameterizedTest
  @EnumSource(CurveHashSuite.class)
  void keyCongruentToZeroIsRejected(CurveHashSuite s) {
    OprfCipherSuite cs = suite(s);
    assertThatThrownBy(() ->
        cs.validateSecretKey(cs.groupSpec().groupOrder().multiply(BigInteger.TWO)))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("congruent to zero");
  }

  @ParameterizedTest
  @EnumSource(CurveHashSuite.class)
  void validKeysAreAccepted(CurveHashSuite s) {
    OprfCipherSuite cs = suite(s);
    assertThatCode(() -> cs.validateSecretKey(BigInteger.ONE)).doesNotThrowAnyException();
    assertThatCode(() -> cs.validateSecretKey(cs.randomScalar())).doesNotThrowAnyException();
    assertThatCode(() -> cs.validateSecretKey(cs.groupSpec().groupOrder().subtract(BigInteger.ONE)))
        .doesNotThrowAnyException();
  }

  /**
   * The footgun normalization removes: an operator could "rotate" to k+n, see a new processor
   * identifier, and be serving byte-identical output.
   */
  @ParameterizedTest
  @EnumSource(CurveHashSuite.class)
  void keyPlusGroupOrderProducesIdenticalOutput(CurveHashSuite s) {
    OprfCipherSuite cs = suite(s);
    BigInteger k = BigInteger.valueOf(1234567);
    byte[] element = cs.groupSpec().scalarMultiplyGenerator(BigInteger.valueOf(9));

    assertThat(cs.groupSpec().scalarMultiply(k.add(cs.groupSpec().groupOrder()), element))
        .as("k and k+n are the same key, which is why normalizing is transparent")
        .isEqualTo(cs.groupSpec().scalarMultiply(k, element));
  }

  /**
   * A rotating supplier can introduce a key the startup validation never saw, so the manager
   * re-checks per request rather than trusting construction.
   *
   * <p>Asserts {@link IllegalStateException} specifically, not merely "something threw". Both
   * HTTP adapters catch {@link IllegalArgumentException} on this path and rewrite it to
   * 400 "Invalid EC point data" — which would blame the caller for a server misconfiguration,
   * discard the reason, and leave a server that rejects every client while looking healthy.
   * That is the failure mode this check exists to surface, so the type is load-bearing.
   */
  @ParameterizedTest
  @EnumSource(CurveHashSuite.class)
  void managerRejectsAKeyRotatedInAfterConstruction(CurveHashSuite s) {
    OprfCipherSuite cs = suite(s);
    ServerProcessorDetail good = new ServerProcessorDetail(cs.randomScalar(), "v1");
    ServerProcessorDetail bad = new ServerProcessorDetail(BigInteger.ZERO, "v2");
    ServerProcessorDetail[] current = {good};
    OprfServerManager manager = new OprfServerManager(cs, () -> current[0]);
    BlindedRequest request = new BlindedRequest(
        Hex.toHexString(cs.groupSpec().scalarMultiplyGenerator(BigInteger.valueOf(7))), "req-1");

    assertThatCode(() -> manager.process(request)).doesNotThrowAnyException();

    current[0] = bad;
    assertThatThrownBy(() -> manager.process(request))
        .isInstanceOf(IllegalStateException.class)
        .isNotInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("misconfigured");
  }

  /**
   * The supplier is a documented rotation seam, so calling it twice can straddle a swap and label
   * a hash computed with key A as key B — a stored value that can never be recomputed.
   */
  @Test
  void managerReadsTheSupplierExactlyOncePerRequest() {
    OprfCipherSuite cs = suite(CurveHashSuite.P256_SHA256);
    AtomicInteger calls = new AtomicInteger();
    ServerProcessorDetail detail = new ServerProcessorDetail(cs.randomScalar(), "v1");
    OprfServerManager manager = new OprfServerManager(cs, () -> {
      calls.incrementAndGet();
      return detail;
    });

    EvaluatedResponse response = manager.process(new BlindedRequest(
        Hex.toHexString(cs.groupSpec().scalarMultiplyGenerator(BigInteger.valueOf(7))), "req-1"));

    assertThat(calls.get()).isEqualTo(1);
    assertThat(response.processIdentifier()).isEqualTo("v1");
  }
}
