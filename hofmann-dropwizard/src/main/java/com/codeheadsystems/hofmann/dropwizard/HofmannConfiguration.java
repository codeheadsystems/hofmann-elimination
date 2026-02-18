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

  @JsonProperty
  public String getJwtSecretHex() {
    return jwtSecretHex;
  }

  @JsonProperty
  public void setJwtSecretHex(String jwtSecretHex) {
    this.jwtSecretHex = jwtSecretHex;
  }

  @JsonProperty
  public long getJwtTtlSeconds() {
    return jwtTtlSeconds;
  }

  @JsonProperty
  public void setJwtTtlSeconds(long jwtTtlSeconds) {
    this.jwtTtlSeconds = jwtTtlSeconds;
  }

  @JsonProperty
  public String getJwtIssuer() {
    return jwtIssuer;
  }

  @JsonProperty
  public void setJwtIssuer(String jwtIssuer) {
    this.jwtIssuer = jwtIssuer;
  }

  @JsonProperty
  public String getServerKeySeedHex() {
    return serverKeySeedHex;
  }

  @JsonProperty
  public void setServerKeySeedHex(String serverKeySeedHex) {
    this.serverKeySeedHex = serverKeySeedHex;
  }

  @JsonProperty
  public String getOprfSeedHex() {
    return oprfSeedHex;
  }

  @JsonProperty
  public void setOprfSeedHex(String oprfSeedHex) {
    this.oprfSeedHex = oprfSeedHex;
  }

  @JsonProperty
  public String getContext() {
    return context;
  }

  @JsonProperty
  public void setContext(String context) {
    this.context = context;
  }

  @JsonProperty
  public int getArgon2MemoryKib() {
    return argon2MemoryKib;
  }

  @JsonProperty
  public void setArgon2MemoryKib(int argon2MemoryKib) {
    this.argon2MemoryKib = argon2MemoryKib;
  }

  @JsonProperty
  public int getArgon2Iterations() {
    return argon2Iterations;
  }

  @JsonProperty
  public void setArgon2Iterations(int argon2Iterations) {
    this.argon2Iterations = argon2Iterations;
  }

  @JsonProperty
  public int getArgon2Parallelism() {
    return argon2Parallelism;
  }

  @JsonProperty
  public void setArgon2Parallelism(int argon2Parallelism) {
    this.argon2Parallelism = argon2Parallelism;
  }

  @JsonProperty
  public String getOprfMasterKeyHex() {
    return oprfMasterKeyHex;
  }

  @JsonProperty
  public void setOprfMasterKeyHex(String oprfMasterKeyHex) {
    this.oprfMasterKeyHex = oprfMasterKeyHex;
  }

  @JsonProperty
  public String getOprfProcessorId() {
    return oprfProcessorId;
  }

  @JsonProperty
  public void setOprfProcessorId(String oprfProcessorId) {
    this.oprfProcessorId = oprfProcessorId;
  }
}
