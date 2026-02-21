package com.codeheadsystems.ellipticcurve.rfc9380;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.codeheadsystems.ellipticcurve.curve.Curve;
import org.bouncycastle.math.ec.ECPoint;
import org.junit.jupiter.api.Test;

class WeierstrassGroupSpecImplTest {

  private static final WeierstrassGroupSpecImpl SPEC = WeierstrassGroupSpecImpl.P256_SHA256;

  // ─── toHex ────────────────────────────────────────────────────────────────

  @Test
  void toHex_nullPointThrows() {
    assertThatThrownBy(() -> SPEC.toHex(null))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("EC point must not be null");
  }

  @Test
  void toHex_generatorPointProducesExpectedHex() {
    ECPoint g = Curve.P256_CURVE.g();
    String hex = SPEC.toHex(g);
    // P-256 generator — compressed SEC1 is 33 bytes = 66 hex chars, starts with 02 or 03
    assertThat(hex).hasSize(66);
    assertThat(hex).startsWith("0");
  }

  @Test
  void toHex_roundTripsWithToEcPoint() {
    ECPoint g = Curve.P256_CURVE.g().normalize();
    String hex = SPEC.toHex(g);
    ECPoint recovered = SPEC.toEcPoint(hex);
    assertThat(recovered.normalize()).isEqualTo(g);
  }

  // ─── toEcPoint ────────────────────────────────────────────────────────────

  @Test
  void toEcPoint_nullHexThrows() {
    assertThatThrownBy(() -> SPEC.toEcPoint(null))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("Hex string must not be null or empty");
  }

  @Test
  void toEcPoint_emptyHexThrows() {
    assertThatThrownBy(() -> SPEC.toEcPoint(""))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("Hex string must not be null or empty");
  }

  @Test
  void toEcPoint_validHexReturnsPoint() {
    String generatorHex = SPEC.toHex(Curve.P256_CURVE.g());
    ECPoint point = SPEC.toEcPoint(generatorHex);
    assertThat(point).isNotNull();
    assertThat(point.normalize()).isEqualTo(Curve.P256_CURVE.g().normalize());
  }
}
