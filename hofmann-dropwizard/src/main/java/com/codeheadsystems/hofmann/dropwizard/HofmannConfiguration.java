package com.codeheadsystems.hofmann.dropwizard;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.dropwizard.core.Configuration;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotEmpty;
import java.util.Collections;
import java.util.List;

/**
 * Dropwizard configuration for the Hofmann OPAQUE and OPRF server.
 * <p>
 * For production, supply both {@code serverKeySeedHex} and {@code oprfSeedHex}
 * (each a hex-encoded 32-byte random value) so that OPAQUE keys survive restarts.
 * Omitting both causes random key generation on each startup (dev/test only —
 * all existing registrations become invalid after a restart).
 * <p>
 * For the standalone OPRF endpoint, supply {@code oprfMasterKeyHex} (a hex-encoded
 * scalar in the curve group) so that OPRF outputs are stable across restarts.
 * Omitting it causes a random key to be generated (dev/test only).
 * <p>
 * Generate seeds/keys with: {@code openssl rand -hex 32}
 */
public class HofmannConfiguration extends Configuration {

  /**
   * OPAQUE cipher suite to use.  Valid values: {@code P256_SHA256} (default),
   * {@code P384_SHA384}, {@code P521_SHA512}.
   * Must match the client's configuration exactly.
   */
  private String opaqueCipherSuite = "P256_SHA256";

  /**
   * Cipher suite for the standalone OPRF endpoint.  Valid values: {@code P256_SHA256} (default),
   * {@code P384_SHA384}, {@code P521_SHA512}.
   * Independent of the OPAQUE cipher suite.
   */
  private String oprfCipherSuite = "P256_SHA256";

  /**
   * Hex-encoded 32-byte seed for deriving the server's long-term AKE key pair.
   * Leave empty for random generation (dev only — invalidates all registrations on restart).
   */
  private String serverKeySeedHex = "";

  /**
   * Hex-encoded 32-byte OPRF seed for deriving per-credential OPRF keys.
   * Leave empty for random generation (dev only — invalidates all registrations on restart).
   */
  private String oprfSeedHex = "";

  /**
   * Hex-encoded previous 32-byte seed for the server's AKE key pair, used during key rotation.
   * When set along with {@code previousOprfSeedHex}, credentials registered under these keys
   * remain authenticatable while new registrations use the current keys.
   */
  private String previousServerKeySeedHex = "";

  /**
   * Hex-encoded previous 32-byte OPRF seed, used during key rotation.
   * Must be set together with {@code previousServerKeySeedHex} or both omitted.
   */
  private String previousOprfSeedHex = "";

  /**
   * Hex-encoded scalar (BigInteger) used as the server's master key for the standalone
   * OPRF endpoint ({@code POST /oprf}).  Must be a valid non-zero scalar in the P-256 group.
   * Leave empty for random generation (dev only — OPRF outputs change on restart).
   */
  private String oprfMasterKeyHex = "";

  /**
   * Human-readable identifier for this OPRF processor instance.  Returned in every
   * {@code OprfResponse} so clients can trace which server key produced a given output
   * (useful when rotating keys).
   */
  private String oprfProcessorId = "hofmann-oprf-v1";
  /**
   * VOPRF (RFC 9497 mode 0x01) master key, hex. Empty disables {@code POST /oprf/verifiable}.
   *
   * <p>Separate from {@code oprfMasterKeyHex}: the mode byte is part of every domain-separation
   * tag, so one secret serving two modes computes two different functions under two different tag
   * sets. There is deliberately no ephemeral fallback — the point of a verifiable mode is that
   * clients pin the public key, and a key regenerated on restart makes every pinned key wrong.
   */
  private String voprfMasterKeyHex = "";
  /** POPRF (RFC 9497 mode 0x02) master key, hex. Empty disables {@code POST /oprf/partially-oblivious}. */
  private String poprfMasterKeyHex = "";

  /**
   * Application context string bound into the OPAQUE preamble.
   * Must be unique per deployment to prevent cross-deployment replay.
   */
  @NotEmpty
  private String context = "hofmann-opaque-v1";

  /**
   * Hex-encoded HMAC-SHA256 signing secret for JWT tokens.
   * Leave empty for random generation (dev only — tokens become invalid on restart).
   */
  private String jwtSecretHex = "";

  /**
   * Hex-encoded previous HMAC-SHA256 signing secret for JWT key rotation.
   * When set, tokens signed with this key are still accepted for verification
   * while new tokens are signed with {@code jwtSecretHex}.
   * Leave empty when no rotation is in progress.
   */
  private String jwtPreviousSecretHex = "";

  /**
   * JWT token time-to-live in seconds.
   */
  @Min(1)
  private long jwtTtlSeconds = 3600;

  /**
   * JWT issuer claim.
   */
  @NotEmpty
  private String jwtIssuer = "hofmann";

  /**
   * Argon2id memory cost in kibibytes. 0 disables Argon2 (identity KSF — dev only).
   */
  @Min(0)
  private int argon2MemoryKib = 65536;

  /**
   * Argon2id iteration count. Ignored when argon2MemoryKib == 0.
   */
  @Min(1)
  private int argon2Iterations = 3;

  /**
   * Argon2id parallelism. Ignored when argon2MemoryKib == 0.
   */
  @Min(1)
  private int argon2Parallelism = 1;

  /**
   * Whether the identity KSF (no key stretching) is allowed.  Must be set to {@code true}
   * when {@code argon2MemoryKib} is 0, otherwise startup fails.  Defaults to {@code false}
   * to prevent accidental production deployment without key stretching.
   */
  private boolean allowIdentityKsf = false;

  /**
   * Whether the server may generate ephemeral key material at startup when
   * {@code jwtSecretHex}, {@code serverKeySeedHex} or {@code oprfSeedHex} is unset.
   * <p>
   * Defaults to {@code false}, so a deployment missing any of them fails to start rather than
   * silently generating a fresh key per process. Generated keys are random, so this is not a
   * key-disclosure risk — the failure is availability and consistency: every node signs with a
   * different key, tokens minted on one are rejected by another, credentials registered against
   * one cannot authenticate against another, and a restart invalidates every account. Those
   * symptoms surface as intermittent authentication failures long after the deployment, which is
   * a poor trade for a warning line in a startup log.
   * <p>
   * Set to {@code true} for local development and tests, where losing all state on restart is
   * the intended behaviour.
   */
  private boolean allowEphemeralKeys = false;

  /**
   * Allowed CORS origins.  When empty (the default), no CORS headers are added and
   * all cross-origin requests are blocked by the browser's same-origin policy.
   * Set to specific origins (e.g. {@code ["https://app.example.com"]}) to allow
   * cross-origin requests from those origins.
   */
  private List<String> corsAllowedOrigins = Collections.emptyList();

  /**
   * Maximum allowed request body size in bytes.  Requests with a {@code Content-Length}
   * header exceeding this value are rejected with HTTP 413 before the body is read.
   * Defaults to 65536 (64 KiB) — well above the largest OPAQUE/OPRF message
   * but small enough to block large-payload DoS attempts.
   */
  @Min(1)
  private long maxRequestBodyBytes = 65536;

  /**
   * Whether to derive the OPRF rate-limit client IP from the {@code X-Forwarded-For} header.
   * Only enable this when the server runs behind a trusted reverse proxy that overwrites the
   * header; otherwise it is attacker-controlled and the rate limit on the unauthenticated OPRF
   * endpoint can be trivially bypassed. Defaults to {@code false} (use the real socket address).
   */
  private boolean trustForwardedHeaders = false;

  /**
   * Whether to serve the OpenAPI specs and Swagger UI from this bundle.
   *
   * <p><strong>Off by default, and it used to be unconditional.</strong> This is a bundle every
   * consumer installs into their own application, so registering a servlet was claiming a path on
   * someone else's server without asking — and a consumer with their own {@code /api-docs}
   * mapping collided with it. Opting in is the only way a library can register a servlet
   * honestly.
   *
   * <p>The servlet is also outside the JAX-RS filter chain, so {@link SecurityHeadersFilter} and
   * {@link CorsFilter} — which are registered with {@code environment.jersey()} — never saw these
   * responses. When enabled, {@link ApiDocsSecurityHeadersFilter} is installed on the same path
   * so the assets get security headers rather than none.
   */
  private boolean serveApiDocs = false;

  /**
   * Path prefix for the API docs when {@link #serveApiDocs} is enabled.
   *
   * <p>Configurable so a consumer who already serves something at {@code /api-docs} can move
   * these out of the way rather than having to choose between the two.
   */
  @NotEmpty
  private String apiDocsPath = "/api-docs";

  /**
   * Creates a configuration holding the defaults documented on each field. Dropwizard instantiates
   * this and populates it from YAML; applications rarely construct it directly.
   */
  public HofmannConfiguration() {
  }

  /**
   * Gets opaque cipher suite.
   *
   * @return the opaque cipher suite
   */
  @JsonProperty
  public String getOpaqueCipherSuite() {
    return opaqueCipherSuite;
  }

  /**
   * Sets opaque cipher suite.
   *
   * @param opaqueCipherSuite the opaque cipher suite
   */
  @JsonProperty
  public void setOpaqueCipherSuite(String opaqueCipherSuite) {
    this.opaqueCipherSuite = opaqueCipherSuite;
  }

  /**
   * Gets oprf cipher suite.
   *
   * @return the oprf cipher suite
   */
  @JsonProperty
  public String getOprfCipherSuite() {
    return oprfCipherSuite;
  }

  /**
   * Sets oprf cipher suite.
   *
   * @param oprfCipherSuite the oprf cipher suite
   */
  @JsonProperty
  public void setOprfCipherSuite(String oprfCipherSuite) {
    this.oprfCipherSuite = oprfCipherSuite;
  }

  /**
   * Gets jwt secret hex.
   *
   * @return the jwt secret hex
   */
  @JsonProperty
  public String getJwtSecretHex() {
    return jwtSecretHex;
  }

  /**
   * Sets jwt secret hex.
   *
   * @param jwtSecretHex the jwt secret hex
   */
  @JsonProperty
  public void setJwtSecretHex(String jwtSecretHex) {
    this.jwtSecretHex = jwtSecretHex;
  }

  /**
   * Gets jwt previous secret hex.
   *
   * @return the jwt previous secret hex
   */
  @JsonProperty
  public String getJwtPreviousSecretHex() {
    return jwtPreviousSecretHex;
  }

  /**
   * Sets jwt previous secret hex.
   *
   * @param jwtPreviousSecretHex the jwt previous secret hex
   */
  @JsonProperty
  public void setJwtPreviousSecretHex(String jwtPreviousSecretHex) {
    this.jwtPreviousSecretHex = jwtPreviousSecretHex;
  }

  /**
   * Gets jwt ttl seconds.
   *
   * @return the jwt ttl seconds
   */
  @JsonProperty
  public long getJwtTtlSeconds() {
    return jwtTtlSeconds;
  }

  /**
   * Sets jwt ttl seconds.
   *
   * @param jwtTtlSeconds the jwt ttl seconds
   */
  @JsonProperty
  public void setJwtTtlSeconds(long jwtTtlSeconds) {
    this.jwtTtlSeconds = jwtTtlSeconds;
  }

  /**
   * Gets jwt issuer.
   *
   * @return the jwt issuer
   */
  @JsonProperty
  public String getJwtIssuer() {
    return jwtIssuer;
  }

  /**
   * Sets jwt issuer.
   *
   * @param jwtIssuer the jwt issuer
   */
  @JsonProperty
  public void setJwtIssuer(String jwtIssuer) {
    this.jwtIssuer = jwtIssuer;
  }

  /**
   * Gets server key seed hex.
   *
   * @return the server key seed hex
   */
  @JsonProperty
  public String getServerKeySeedHex() {
    return serverKeySeedHex;
  }

  /**
   * Sets server key seed hex.
   *
   * @param serverKeySeedHex the server key seed hex
   */
  @JsonProperty
  public void setServerKeySeedHex(String serverKeySeedHex) {
    this.serverKeySeedHex = serverKeySeedHex;
  }

  /**
   * Gets oprf seed hex.
   *
   * @return the oprf seed hex
   */
  @JsonProperty
  public String getOprfSeedHex() {
    return oprfSeedHex;
  }

  /**
   * Sets oprf seed hex.
   *
   * @param oprfSeedHex the oprf seed hex
   */
  @JsonProperty
  public void setOprfSeedHex(String oprfSeedHex) {
    this.oprfSeedHex = oprfSeedHex;
  }

  /**
   * Gets the previous server key seed hex.
   *
   * @return the previous server key seed hex, or the empty string when not rotating
   */
  @JsonProperty
  public String getPreviousServerKeySeedHex() {
    return previousServerKeySeedHex;
  }

  /**
   * Sets the previous server key seed hex. Set it together with
   * {@link #setPreviousOprfSeedHex(String)} during key rotation, so that credentials registered
   * under the old keys stay authenticatable.
   *
   * @param previousServerKeySeedHex the previous server key seed hex
   */
  @JsonProperty
  public void setPreviousServerKeySeedHex(String previousServerKeySeedHex) {
    this.previousServerKeySeedHex = previousServerKeySeedHex;
  }

  /**
   * Gets the previous oprf seed hex.
   *
   * @return the previous oprf seed hex, or the empty string when not rotating
   */
  @JsonProperty
  public String getPreviousOprfSeedHex() {
    return previousOprfSeedHex;
  }

  /**
   * Sets the previous oprf seed hex. Must be set together with
   * {@link #setPreviousServerKeySeedHex(String)}, or both left unset.
   *
   * @param previousOprfSeedHex the previous oprf seed hex
   */
  @JsonProperty
  public void setPreviousOprfSeedHex(String previousOprfSeedHex) {
    this.previousOprfSeedHex = previousOprfSeedHex;
  }

  /**
   * Gets context.
   *
   * @return the context
   */
  @JsonProperty
  public String getContext() {
    return context;
  }

  /**
   * Sets context.
   *
   * @param context the context
   */
  @JsonProperty
  public void setContext(String context) {
    this.context = context;
  }

  /**
   * Gets argon 2 memory kib.
   *
   * @return the argon 2 memory kib
   */
  @JsonProperty
  public int getArgon2MemoryKib() {
    return argon2MemoryKib;
  }

  /**
   * Sets argon 2 memory kib.
   *
   * @param argon2MemoryKib the argon 2 memory kib
   */
  @JsonProperty
  public void setArgon2MemoryKib(int argon2MemoryKib) {
    this.argon2MemoryKib = argon2MemoryKib;
  }

  /**
   * Gets argon 2 iterations.
   *
   * @return the argon 2 iterations
   */
  @JsonProperty
  public int getArgon2Iterations() {
    return argon2Iterations;
  }

  /**
   * Sets argon 2 iterations.
   *
   * @param argon2Iterations the argon 2 iterations
   */
  @JsonProperty
  public void setArgon2Iterations(int argon2Iterations) {
    this.argon2Iterations = argon2Iterations;
  }

  /**
   * Gets argon 2 parallelism.
   *
   * @return the argon 2 parallelism
   */
  @JsonProperty
  public int getArgon2Parallelism() {
    return argon2Parallelism;
  }

  /**
   * Sets argon 2 parallelism.
   *
   * @param argon2Parallelism the argon 2 parallelism
   */
  @JsonProperty
  public void setArgon2Parallelism(int argon2Parallelism) {
    this.argon2Parallelism = argon2Parallelism;
  }

  /**
   * Gets oprf master key hex.
   *
   * @return the oprf master key hex
   */
  @JsonProperty
  public String getOprfMasterKeyHex() {
    return oprfMasterKeyHex;
  }

  /**
   * Sets oprf master key hex.
   *
   * @param oprfMasterKeyHex the oprf master key hex
   */
  @JsonProperty
  public void setOprfMasterKeyHex(String oprfMasterKeyHex) {
    this.oprfMasterKeyHex = oprfMasterKeyHex;
  }

  /**
   * Gets oprf processor id.
   *
   * @return the oprf processor id
   */
  @JsonProperty
  public String getOprfProcessorId() {
    return oprfProcessorId;
  }

  /**
   * Sets oprf processor id.
   *
   * @param oprfProcessorId the oprf processor id
   */
  @JsonProperty
  public void setOprfProcessorId(String oprfProcessorId) {
    this.oprfProcessorId = oprfProcessorId;
  }

  /**
   * Gets max request body bytes.
   *
   * @return the max request body bytes
   */
  @JsonProperty
  public long getMaxRequestBodyBytes() {
    return maxRequestBodyBytes;
  }

  /**
   * Sets max request body bytes.
   *
   * @param maxRequestBodyBytes the max request body bytes
   */
  @JsonProperty
  public void setMaxRequestBodyBytes(long maxRequestBodyBytes) {
    this.maxRequestBodyBytes = maxRequestBodyBytes;
  }

  /**
   * Whether the OPRF rate-limit client IP is derived from the {@code X-Forwarded-For} header.
   *
   * @return true if forwarded headers are trusted
   */
  @JsonProperty
  public boolean isTrustForwardedHeaders() {
    return trustForwardedHeaders;
  }

  /**
   * Sets whether to trust forwarded headers for client-IP extraction.
   *
   * @param trustForwardedHeaders the trust forwarded headers flag
   */
  @JsonProperty
  public void setTrustForwardedHeaders(boolean trustForwardedHeaders) {
    this.trustForwardedHeaders = trustForwardedHeaders;
  }

  /**
   * Whether the bundle serves the OpenAPI specs and Swagger UI.
   *
   * @return true if the API docs servlet should be registered
   */
  @JsonProperty
  public boolean isServeApiDocs() {
    return serveApiDocs;
  }

  /**
   * Sets whether the bundle serves the OpenAPI specs and Swagger UI.
   *
   * @param serveApiDocs true to register the API docs servlet
   */
  @JsonProperty
  public void setServeApiDocs(boolean serveApiDocs) {
    this.serveApiDocs = serveApiDocs;
  }

  /**
   * Gets the path prefix the API docs are served from.
   *
   * @return the api docs path
   */
  @JsonProperty
  public String getApiDocsPath() {
    return apiDocsPath;
  }

  /**
   * Sets the path prefix the API docs are served from.
   *
   * @param apiDocsPath the api docs path
   */
  @JsonProperty
  public void setApiDocsPath(String apiDocsPath) {
    this.apiDocsPath = apiDocsPath;
  }

  /**
   * Gets cors allowed origins.
   *
   * @return the cors allowed origins
   */
  @JsonProperty
  public List<String> getCorsAllowedOrigins() {
    return corsAllowedOrigins;
  }

  /**
   * Sets cors allowed origins.
   *
   * @param corsAllowedOrigins the cors allowed origins
   */
  @JsonProperty
  public void setCorsAllowedOrigins(List<String> corsAllowedOrigins) {
    this.corsAllowedOrigins = corsAllowedOrigins;
  }

  /**
   * Whether the identity KSF (no key stretching) is allowed.
   *
   * @return true if identity KSF is allowed
   */
  @JsonProperty
  public boolean isAllowIdentityKsf() {
    return allowIdentityKsf;
  }

  /**
   * Whether ephemeral key generation is permitted when key material is unset.
   *
   * @return true if ephemeral keys are allowed
   */
  @JsonProperty
  public boolean isAllowEphemeralKeys() {
    return allowEphemeralKeys;
  }

  /**
   * Sets whether ephemeral key generation is permitted.
   *
   * @param allowEphemeralKeys the flag
   */
  @JsonProperty
  public void setAllowEphemeralKeys(boolean allowEphemeralKeys) {
    this.allowEphemeralKeys = allowEphemeralKeys;
  }

  /**
   * Sets allow identity ksf.
   *
   * @param allowIdentityKsf the allow identity ksf
   */
  @JsonProperty
  public void setAllowIdentityKsf(boolean allowIdentityKsf) {
    this.allowIdentityKsf = allowIdentityKsf;
  }

  /**
   * Gets the VOPRF master key hex.
   *
   * @return the voprf master key hex
   */
  public String getVoprfMasterKeyHex() {
    return voprfMasterKeyHex;
  }

  /**
   * Sets the VOPRF master key hex.
   *
   * @param voprfMasterKeyHex the voprf master key hex
   */
  public void setVoprfMasterKeyHex(String voprfMasterKeyHex) {
    this.voprfMasterKeyHex = voprfMasterKeyHex;
  }

  /**
   * Gets the POPRF master key hex.
   *
   * @return the poprf master key hex
   */
  public String getPoprfMasterKeyHex() {
    return poprfMasterKeyHex;
  }

  /**
   * Sets the POPRF master key hex.
   *
   * @param poprfMasterKeyHex the poprf master key hex
   */
  public void setPoprfMasterKeyHex(String poprfMasterKeyHex) {
    this.poprfMasterKeyHex = poprfMasterKeyHex;
  }
}
