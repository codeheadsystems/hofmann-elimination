package com.codeheadsystems.rfc.opaque.model;

/**
 * KE1: client's first AKE message.
 * Wire format: credentialRequest.blindedElement || clientNonce || clientAkePublicKey
 */
public record KE1(CredentialRequest credentialRequest, byte[] clientNonce, byte[] clientAkePublicKey) {

  /**
   * Serializes to wire format (33 + 32 + 33 = 98 bytes).
   */
  public byte[] serialize() {
    byte[] be = credentialRequest.blindedElement();
    byte[] out = new byte[be.length + clientNonce.length + clientAkePublicKey.length];
    int off = 0;
    System.arraycopy(be, 0, out, off, be.length);
    off += be.length;
    System.arraycopy(clientNonce, 0, out, off, clientNonce.length);
    off += clientNonce.length;
    System.arraycopy(clientAkePublicKey, 0, out, off, clientAkePublicKey.length);
    return out;
  }
}
