package com.codeheadsystems.opaque.model;

import java.math.BigInteger;

/**
 * Client-side state during registration: { blind, password, request }.
 */
public record ClientRegistrationState(BigInteger blind, byte[] password, RegistrationRequest request) {
}
