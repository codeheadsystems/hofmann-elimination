package com.codeheadsystems.rfc.opaque.model;

import java.util.Arrays;

/**
 * Result of a successful client-side authentication: { ke3, sessionKey, exportKey }.
 *
 * <p>Implements {@link AutoCloseable} so a caller that does not need the key material can clear
 * it rather than drop it. Both arrays are secrets and both were being abandoned: this library's
 * own client takes {@code ke3} out of here to send to the server and lets the rest fall out of
 * scope, so a full authentication left a live session key and a live export key on the heap
 * every time.
 *
 * <p>The export key is the one that matters. It is derived from {@code randomizedPwd} and is a
 * long-term client secret — the same value the registration flow now destroys when it drops it,
 * so leaving it here was the same defect on the other side of the protocol.
 *
 * <p>Unlike {@link ClientAuthState} this does <em>not</em> copy on construction: the arrays are
 * freshly derived by {@code generateKE3} and have no other owner, so there is nothing to
 * decouple. Closing therefore clears the arrays a caller may still be holding a reference to.
 * Take what you need before closing.
 */
public record AuthResult(KE3 ke3, byte[] sessionKey, byte[] exportKey) implements AutoCloseable {

  @Override
  public void close() {
    Arrays.fill(sessionKey, (byte) 0);
    Arrays.fill(exportKey, (byte) 0);
  }
}
