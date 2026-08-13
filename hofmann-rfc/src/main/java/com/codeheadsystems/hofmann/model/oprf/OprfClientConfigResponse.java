package com.codeheadsystems.hofmann.model.oprf;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.List;

/**
 * Server response to GET /oprf/config — the cipher suite the server is using, and the verifiable
 * modes it has enabled.
 *
 * <p><strong>{@code modes} is absent, not empty, when nothing is enabled.</strong> That is a wire
 * compatibility requirement, not a style choice. Every caller in tree constructs the client's
 * {@code ObjectMapper} bare, which leaves {@code FAIL_ON_UNKNOWN_PROPERTIES} on, so an
 * already-released client would reject a document carrying a field it has never heard of.
 * Suppressing the field unless a verifiable mode is configured means a base-mode deployment —
 * which is every deployment an old client talks to — emits the byte-identical document it always
 * has. {@link JsonIgnoreProperties} fixes the same class of problem going forward, but it cannot
 * fix the jars already out there.
 *
 * <p>A client reads {@code modes} as three states: absent means the server predates this field or
 * has no verifiable mode, so no cross-check is possible; present-and-listing the mode is
 * authoritative and a key mismatch is fatal; present-but-not-listing it means the mode is off.
 * See {@link OprfModeInfo} for why none of that makes this a source of trust.
 *
 * @param cipherSuite the OPRF cipher suite name (e.g. {@code "P256_SHA256"})
 * @param modes       the verifiable modes this server has enabled, or null if none
 */
@JsonIgnoreProperties(ignoreUnknown = true)
@JsonInclude(JsonInclude.Include.NON_NULL)
public record OprfClientConfigResponse(
    @JsonProperty("cipherSuite") String cipherSuite,
    @JsonProperty("modes") List<OprfModeInfo> modes) {

  /**
   * Canonical constructor, defensively copying the mode list.
   */
  public OprfClientConfigResponse {
    modes = modes == null ? null : List.copyOf(modes);
  }

  /**
   * Base-mode form, emitting exactly the document previous versions emitted.
   *
   * @param cipherSuite the OPRF cipher suite name
   */
  public OprfClientConfigResponse(final String cipherSuite) {
    this(cipherSuite, null);
  }
}
