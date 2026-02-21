package com.codeheadsystems.opaque.model;

import static org.assertj.core.api.Assertions.assertThat;

import com.codeheadsystems.opaque.config.OpaqueConfig;
import java.util.Arrays;
import org.junit.jupiter.api.Test;

/**
 * Unit tests for {@link KE2} serialization / deserialization layout.
 */
class KE2Test {

  private static final OpaqueConfig CONFIG = OpaqueConfig.forTesting(); // P256-SHA256, IdentityKsf

  private static void fill(byte[] arr, int offset, int length, byte value) {
    Arrays.fill(arr, offset, offset + length, value);
  }

  /**
   * Verifies that {@link KE2#deserialize} maps each region of the wire format to the
   * correct field.  Each region is filled with a distinct sentinel byte so that an
   * off-by-one in any offset would put the wrong sentinel in the wrong field.
   * <p>
   * P256-SHA256 wire layout:
   * evaluatedElement  – Noe  = 33 bytes  → sentinel 0x01
   * maskingNonce      – Nn   = 32 bytes  → sentinel 0x02
   * maskedResponse    – Npk+Nn+Nm = 97 bytes → sentinel 0x03
   * serverNonce       – Nn   = 32 bytes  → sentinel 0x04
   * serverAkePublicKey– Npk  = 33 bytes  → sentinel 0x05
   * serverMac         – Nm   = 32 bytes  → sentinel 0x06
   */
  @Test
  void deserializeAssignsFieldsAtCorrectOffsets() {
    int noe = CONFIG.Noe();               // 33
    int nn = OpaqueConfig.Nn;            // 32
    int masked = CONFIG.maskedResponseSize(); // 97 for P256
    int npk = CONFIG.Npk();               // 33
    int nm = CONFIG.Nm();                // 32
    int total = noe + nn + masked + nn + npk + nm;

    byte[] wire = new byte[total];
    int off = 0;
    fill(wire, off, noe, (byte) 0x01);
    off += noe;
    fill(wire, off, nn, (byte) 0x02);
    off += nn;
    fill(wire, off, masked, (byte) 0x03);
    off += masked;
    fill(wire, off, nn, (byte) 0x04);
    off += nn;
    fill(wire, off, npk, (byte) 0x05);
    off += npk;
    fill(wire, off, nm, (byte) 0x06);

    KE2 ke2 = KE2.deserialize(CONFIG, wire);

    assertThat(ke2.credentialResponse().evaluatedElement()).containsOnly((byte) 0x01);
    assertThat(ke2.credentialResponse().maskingNonce()).containsOnly((byte) 0x02);
    assertThat(ke2.credentialResponse().maskedResponse()).containsOnly((byte) 0x03);
    assertThat(ke2.serverNonce()).containsOnly((byte) 0x04);
    assertThat(ke2.serverAkePublicKey()).containsOnly((byte) 0x05);
    assertThat(ke2.serverMac()).containsOnly((byte) 0x06);
  }

  @Test
  void deserializeThenRoundTripLengthsMatch() {
    // Verify that all deserialized field lengths match the config-defined sizes.
    int noe = CONFIG.Noe();
    int nn = OpaqueConfig.Nn;
    int masked = CONFIG.maskedResponseSize();
    int npk = CONFIG.Npk();
    int nm = CONFIG.Nm();
    int total = noe + nn + masked + nn + npk + nm;

    KE2 ke2 = KE2.deserialize(CONFIG, new byte[total]);

    assertThat(ke2.credentialResponse().evaluatedElement()).hasSize(noe);
    assertThat(ke2.credentialResponse().maskingNonce()).hasSize(nn);
    assertThat(ke2.credentialResponse().maskedResponse()).hasSize(masked);
    assertThat(ke2.serverNonce()).hasSize(nn);
    assertThat(ke2.serverAkePublicKey()).hasSize(npk);
    assertThat(ke2.serverMac()).hasSize(nm);
  }
}
