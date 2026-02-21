package com.codeheadsystems.oprf.model;

/**
 * Result of a hash operation, including the hash and an identifier for the process that generated it.
 * @param hash The resulting hash as a byte array.
 * @param processIdentifier A unique identifier for the processor that generated this hash. Usually represents which key was used.
 */
public record HashResult(byte[] hash, String processIdentifier) {
}
