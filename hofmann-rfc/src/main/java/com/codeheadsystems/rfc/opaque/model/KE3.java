package com.codeheadsystems.rfc.opaque.model;

/**
 * KE3: client's final AKE message containing the client MAC.
 *
 * @param clientMac the MAC over the transcript, {@code Nm} bytes. Not a secret — it is computed
 *                  over public values and transmitted — which is why {@code AuthResult.ke3()}
 *                  remains readable after that result has been closed
 */
public record KE3(byte[] clientMac) {
}
