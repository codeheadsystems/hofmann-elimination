package com.codeheadsystems.the.opaque.model;

import java.math.BigInteger;

/**
 * Client-side state during authentication: { blind, password, ke1, clientAkePrivateKey }.
 */
public record ClientAuthState(BigInteger blind, byte[] password, KE1 ke1, BigInteger clientAkePrivateKey) {
}
