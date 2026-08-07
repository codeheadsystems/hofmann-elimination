package com.codeheadsystems.rfc.oprf.rfc9497;

/**
 * The three RFC 9497 protocol variants, identified by the mode byte that appears in every
 * cipher suite's context string (RFC 9497 §3.1).
 * <p>
 * The mode is not a cosmetic label. It is folded into {@code contextString}, which every
 * domain-separation tag in the protocol derives from — {@code HashToGroup-}, {@code HashToScalar-},
 * {@code DeriveKeyPair}, and the {@code Seed-} value inside the proof composites. Two modes
 * therefore produce different outputs, different proof transcripts, and different keys from the
 * same seed. RFC 9497 Appendix A demonstrates the last of these: seed {@code a3a3...} with
 * {@code KeyInfo = "test key"} derives {@code skSm = 5ebc...} for ristretto255 OPRF and
 * {@code e6f7...} for the same suite in VOPRF mode.
 */
public enum OprfMode {

  /** Base mode, no verifiability (RFC 9497 §3.3.1). */
  OPRF((byte) 0x00),

  /** Verifiable mode: the server proves the evaluation used its committed key (§3.3.2). */
  VOPRF((byte) 0x01),

  /** Partially oblivious mode: adds a public input to the evaluation (§3.3.3). */
  POPRF((byte) 0x02);

  private final byte value;

  OprfMode(final byte value) {
    this.value = value;
  }

  /**
   * The mode byte as it appears in the context string.
   *
   * @return the byte
   */
  public byte value() {
    return value;
  }
}
