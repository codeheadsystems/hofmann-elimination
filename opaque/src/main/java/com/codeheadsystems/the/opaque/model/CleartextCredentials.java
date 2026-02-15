package com.codeheadsystems.the.opaque.model;

import com.codeheadsystems.the.oprf.curve.OctetStringUtils;

/**
 * Cleartext credentials included in HMAC computation during envelope construction/recovery.
 * Contains { serverPublicKey, serverIdentity, clientIdentity }.
 */
public record CleartextCredentials(byte[] serverPublicKey, byte[] serverIdentity, byte[] clientIdentity) {

  /**
   * Creates cleartext credentials, defaulting identities to public keys when null.
   * When serverIdentity is null, it defaults to serverPublicKey.
   * When clientIdentity is null, it defaults to clientPublicKey.
   */
  public static CleartextCredentials create(byte[] serverPublicKey, byte[] clientPublicKey,
                                            byte[] serverIdentity, byte[] clientIdentity) {
    byte[] si = (serverIdentity != null) ? serverIdentity : serverPublicKey;
    byte[] ci = (clientIdentity != null) ? clientIdentity : clientPublicKey;
    return new CleartextCredentials(serverPublicKey, si, ci);
  }

  /**
   * Serializes to: serverPublicKey || I2OSP(len(serverIdentity),2) || serverIdentity
   * || I2OSP(len(clientIdentity),2) || clientIdentity
   */
  public byte[] serialize() {
    byte[] sIdLen = OctetStringUtils.I2OSP(serverIdentity.length, 2);
    byte[] cIdLen = OctetStringUtils.I2OSP(clientIdentity.length, 2);
    byte[] out = new byte[serverPublicKey.length + 2 + serverIdentity.length + 2 + clientIdentity.length];
    int off = 0;
    System.arraycopy(serverPublicKey, 0, out, off, serverPublicKey.length);
    off += serverPublicKey.length;
    System.arraycopy(sIdLen, 0, out, off, 2);
    off += 2;
    System.arraycopy(serverIdentity, 0, out, off, serverIdentity.length);
    off += serverIdentity.length;
    System.arraycopy(cIdLen, 0, out, off, 2);
    off += 2;
    System.arraycopy(clientIdentity, 0, out, off, clientIdentity.length);
    return out;
  }
}
