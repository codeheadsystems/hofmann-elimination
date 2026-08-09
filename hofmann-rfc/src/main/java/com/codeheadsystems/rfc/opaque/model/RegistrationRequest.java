package com.codeheadsystems.rfc.opaque.model;

/**
 * Client's registration request: { blindedElement }.
 *
 * <p>The blinded element is {@code blind * H(password)}. It discloses nothing about the password on
 * its own — that is what the blind is for — but it is <strong>not</strong> safe to log alongside the
 * blind that produced it. Anyone holding both recovers {@code H(password)} and can mount an offline
 * dictionary attack without the server. See {@code ClientRegistrationState}, which holds the pair
 * and redacts both in its {@code toString}.
 *
 * @param blindedElement the blinded password, {@code Ne} bytes, serialized for the wire
 */
public record RegistrationRequest(byte[] blindedElement) {
}
