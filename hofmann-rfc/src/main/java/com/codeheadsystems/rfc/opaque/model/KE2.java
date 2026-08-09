package com.codeheadsystems.rfc.opaque.model;

import com.codeheadsystems.rfc.opaque.config.OpaqueConfig;

/**
 * KE2: server's AKE response.
 * Wire format: credentialResponse || serverNonce || serverAkePublicKey || serverMac
 *
 * @param credentialResponse the evaluated element plus the masked envelope
 * @param serverNonce        the server's per-exchange nonce, {@code Nn} bytes
 * @param serverAkePublicKey the server's ephemeral AKE public key, {@code Npk} bytes
 * @param serverMac          the MAC the client verifies before deriving anything. A failure here
 *                           means a wrong password or the wrong server, indistinguishably
 */
public record KE2(CredentialResponse credentialResponse, byte[] serverNonce,
                  byte[] serverAkePublicKey, byte[] serverMac) {

  /**
   * Deserializes KE2 from wire bytes using config-provided size constants.
   * Layout: evaluatedElement(Noe) || maskingNonce(Nn) || maskedResponse(maskedResponseSize) ||
   * serverNonce(Nn) || serverAkePk(Npk) || serverMac(Nm)
   *
   * @param config the config
   * @param bytes  the bytes
   * @return the ke 2
   */
  public static KE2 deserialize(OpaqueConfig config, byte[] bytes) {
    // Validate input length before deserialization to prevent ArrayIndexOutOfBoundsException
    // from malformed messages, which could leak internal message structure via stack traces.
    int expectedLen = config.Noe() + OpaqueConfig.Nn + config.maskedResponseSize()
        + OpaqueConfig.Nn + config.Npk() + config.Nm();
    // Exact length, not a lower bound. Every field here is a suite constant, so a conformant KE2
    // is exactly expectedLen bytes; accepting longer inputs meant trailing bytes parsed and were
    // silently dropped, giving one logical message many accepted encodings. Nothing in tree sends
    // a long KE2, but "not the inverse of serialize" is the same defect closed on the group
    // element encodings, and here it would let an attacker vary the bytes of a message whose
    // handling is otherwise transcript-bound.
    if (bytes == null || bytes.length != expectedLen) {
      throw new IllegalArgumentException("KE2 message must be exactly "
          + expectedLen + " bytes, got " + (bytes == null ? "null" : String.valueOf(bytes.length)));
    }
    int off = 0;
    byte[] evaluatedElement = slice(bytes, off, config.Noe());
    off += config.Noe();
    byte[] maskingNonce = slice(bytes, off, OpaqueConfig.Nn);
    off += OpaqueConfig.Nn;
    byte[] maskedResponse = slice(bytes, off, config.maskedResponseSize());
    off += config.maskedResponseSize();
    byte[] serverNonce = slice(bytes, off, OpaqueConfig.Nn);
    off += OpaqueConfig.Nn;
    byte[] serverAkePk = slice(bytes, off, config.Npk());
    off += config.Npk();
    byte[] serverMac = slice(bytes, off, config.Nm());
    return new KE2(
        new CredentialResponse(evaluatedElement, maskingNonce, maskedResponse),
        serverNonce, serverAkePk, serverMac
    );
  }

  private static byte[] slice(byte[] src, int off, int len) {
    byte[] out = new byte[len];
    System.arraycopy(src, off, out, 0, len);
    return out;
  }

  /**
   * Serializes credential response to wire format for preamble construction.
   * credResponse = evaluatedElement || maskingNonce || maskedResponse
   *
   * @return the byte [ ]
   */
  public byte[] serializeCredentialResponse() {
    CredentialResponse cr = credentialResponse;
    byte[] out = new byte[cr.evaluatedElement().length + cr.maskingNonce().length + cr.maskedResponse().length];
    int off = 0;
    System.arraycopy(cr.evaluatedElement(), 0, out, off, cr.evaluatedElement().length);
    off += cr.evaluatedElement().length;
    System.arraycopy(cr.maskingNonce(), 0, out, off, cr.maskingNonce().length);
    off += cr.maskingNonce().length;
    System.arraycopy(cr.maskedResponse(), 0, out, off, cr.maskedResponse().length);
    return out;
  }
}
