package com.codeheadsystems.hofmann.dropwizard;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.dropwizard.core.Configuration;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotEmpty;

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
   * Maximum allowed request body size in bytes.  Requests with a {@code Content-Length}
   * header exceeding this value are rejected with HTTP 413 before the body is read.
   * Defaults to 65536 (64 KiB) — well above the largest OPAQUE/OPRF message
   * but small enough to block large-payload DoS attempts.
   */
  @Min(1)
  private long maxRequestBodyBytes = 65536;

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
}
