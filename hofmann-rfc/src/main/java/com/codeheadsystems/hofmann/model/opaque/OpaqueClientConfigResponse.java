package com.codeheadsystems.hofmann.model.opaque;

import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Server response to GET /opaque/config — the configuration clients need to initialize
 * the OPAQUE protocol.
 * <p>
 * The {@code context} string and KSF parameters must be supplied verbatim to the client's
 * OPAQUE config; any mismatch causes authentication failures.
 * {@code argon2MemoryKib == 0} indicates the server is using the identity KSF (test/dev only).
 *
 * @param cipherSuite       the OPAQUE cipher suite name (e.g. {@code "P256_SHA256"})
 * @param context           the OPAQUE protocol context string
 * @param argon2MemoryKib   Argon2id memory cost in KiB; {@code 0} = identity KSF (dev/test only)
 * @param argon2Iterations  Argon2id iteration count
 * @param argon2Parallelism Argon2id parallelism
 */
public record OpaqueClientConfigResponse(
    @JsonProperty("cipherSuite") String cipherSuite,
    @JsonProperty("context") String context,
    @JsonProperty("argon2MemoryKib") int argon2MemoryKib,
    @JsonProperty("argon2Iterations") int argon2Iterations,
    @JsonProperty("argon2Parallelism") int argon2Parallelism) {}
