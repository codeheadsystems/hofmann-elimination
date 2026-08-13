package com.codeheadsystems.hofmann.model.oprf;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * One verifiable mode a server has enabled, as advertised by {@code GET /oprf/config}.
 *
 * <p><strong>This is not a source of trust.</strong> The config response is unauthenticated, so a
 * hostile or compromised server can put anything here. A client must still obtain the server
 * public key out of band and pin it; what this record is for is letting the client notice a
 * mismatch and say so, instead of failing every proof verification with no indication of why. The
 * only two outcomes a client may draw from it are "proceed with the key I already pinned" and
 * "stop" — never "adopt this key". RFC 9497 §7.3 is the reason: an attacker who can substitute the
 * public key can run a distinct key per client and still produce proofs that verify.
 *
 * @param mode              the mode name, {@code "VOPRF"} or {@code "POPRF"}
 * @param publicKeyHex      the server's untweaked public key, hex-encoded. For POPRF this is
 *                          {@code pkS}, not any tweaked key — the client derives the tweak from
 *                          the public input it chooses
 * @param processIdentifier the keying-context label the server stamps on responses for this mode
 * @param maxBatchSize      the largest batch this server accepts for this mode, so a client can
 *                          refuse an oversized batch locally rather than learning about it from a
 *                          400 or a 413
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record OprfModeInfo(
    @JsonProperty("mode") String mode,
    @JsonProperty("publicKeyHex") String publicKeyHex,
    @JsonProperty("processIdentifier") String processIdentifier,
    @JsonProperty("maxBatchSize") int maxBatchSize) {}
