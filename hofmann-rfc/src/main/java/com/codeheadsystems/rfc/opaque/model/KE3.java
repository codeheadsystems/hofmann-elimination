package com.codeheadsystems.rfc.opaque.model;

/**
 * KE3: client's final AKE message containing the client MAC.
 */
public record KE3(byte[] clientMac) {
}
