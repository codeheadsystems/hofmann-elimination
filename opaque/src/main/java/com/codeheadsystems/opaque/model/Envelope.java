package com.codeheadsystems.opaque.model;

/**
 * OPAQUE credential envelope: { envelopeNonce, authTag }.
 * The envelope protects the client's long-term private key.
 */
public record Envelope(byte[] envelopeNonce, byte[] authTag) {

  /**
   * Deserializes from envelopeNonce || authTag.
   */
  public static Envelope deserialize(byte[] bytes, int offset, int nonceLen, int tagLen) {
    // Validate input bounds before deserialization to prevent ArrayIndexOutOfBoundsException
    // from malformed messages, which could leak internal message structure via stack traces.
    int required = offset + nonceLen + tagLen;
    if (bytes == null || bytes.length < required) {
      throw new IllegalArgumentException("Envelope data too short: need at least "
          + required + " bytes from offset " + offset);
    }
    byte[] nonce = new byte[nonceLen];
    byte[] tag = new byte[tagLen];
    System.arraycopy(bytes, offset, nonce, 0, nonceLen);
    System.arraycopy(bytes, offset + nonceLen, tag, 0, tagLen);
    return new Envelope(nonce, tag);
  }

  /**
   * Serializes to envelopeNonce || authTag (64 bytes total).
   */
  public byte[] serialize() {
    byte[] out = new byte[envelopeNonce.length + authTag.length];
    System.arraycopy(envelopeNonce, 0, out, 0, envelopeNonce.length);
    System.arraycopy(authTag, 0, out, envelopeNonce.length, authTag.length);
    return out;
  }
}
