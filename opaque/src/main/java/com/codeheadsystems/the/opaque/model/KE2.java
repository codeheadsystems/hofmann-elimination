package com.codeheadsystems.the.opaque.model;

import com.codeheadsystems.the.opaque.config.OpaqueConfig;

/**
 * KE2: server's AKE response.
 * Wire format: credentialResponse || serverNonce || serverAkePublicKey || serverMac
 */
public record KE2(CredentialResponse credentialResponse, byte[] serverNonce,
                  byte[] serverAkePublicKey, byte[] serverMac) {

  /**
   * Deserializes KE2 from wire bytes.
   * Layout: evaluatedElement(Noe) || maskingNonce(Nn) || maskedResponse(Npk+Nn+Nm) ||
   * serverNonce(Nn) || serverAkePk(Npk) || serverMac(Nm)
   */
  public static KE2 deserialize(byte[] bytes) {
    int off = 0;
    byte[] evaluatedElement = slice(bytes, off, OpaqueConfig.Noe);
    off += OpaqueConfig.Noe;
    byte[] maskingNonce = slice(bytes, off, OpaqueConfig.Nn);
    off += OpaqueConfig.Nn;
    byte[] maskedResponse = slice(bytes, off, OpaqueConfig.MASKED_RESPONSE_SIZE);
    off += OpaqueConfig.MASKED_RESPONSE_SIZE;
    byte[] serverNonce = slice(bytes, off, OpaqueConfig.Nn);
    off += OpaqueConfig.Nn;
    byte[] serverAkePk = slice(bytes, off, OpaqueConfig.Npk);
    off += OpaqueConfig.Npk;
    byte[] serverMac = slice(bytes, off, OpaqueConfig.Nm);
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
