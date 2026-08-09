package com.codeheadsystems.hofmann.springboot.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * The type Hofmann properties.
 */
@ConfigurationProperties(prefix = "hofmann")
public class HofmannProperties {

  private String opaqueCipherSuite = "P256_SHA256";
  private String oprfCipherSuite = "P256_SHA256";
  private String serverKeySeedHex = "";
  private String oprfSeedHex = "";
  private String previousServerKeySeedHex = "";
  private String previousOprfSeedHex = "";
  private String oprfMasterKeyHex = "";
  private String oprfProcessorId = "hofmann-oprf-v1";
  /**
   * VOPRF (RFC 9497 mode 0x01) master key, hex. Empty disables the verifiable endpoint.
   *
   * <p>Separate from {@code oprfMasterKeyHex} deliberately. The mode byte is part of every
   * domain-separation tag, so one secret serving two modes computes two different functions under
   * two different tag sets — sharing it buys nothing and makes a later key rotation ambiguous
   * about which mode it is rotating.
   */
  private String voprfMasterKeyHex = "";
  /** POPRF (RFC 9497 mode 0x02) master key, hex. Empty disables the partially-oblivious endpoint. */
  private String poprfMasterKeyHex = "";
  private String context = "hofmann-opaque-v1";
  private String jwtSecretHex = "";
  private String jwtPreviousSecretHex = "";
  private long jwtTtlSeconds = 3600;
  private String jwtIssuer = "hofmann";
  private int argon2MemoryKib = 65536;
  private int argon2Iterations = 3;
  private int argon2Parallelism = 1;
  private boolean allowIdentityKsf = false;

  /**
   * Whether the server may generate ephemeral key material at startup when {@code jwtSecretHex},
   * {@code serverKeySeedHex} or {@code oprfSeedHex} is unset.
   * <p>
   * Defaults to {@code false}, so a deployment missing any of them fails to start rather than
   * silently generating a fresh key per process. The generated key is random, so this is not a
   * key-disclosure risk — the failure is availability and consistency: every node signs with a
   * different key, and a restart invalidates every account. Those symptoms appear as intermittent
   * authentication failures long after the deployment, which is a poor trade for a startup
   * warning. Set to {@code true} for local development and tests.
   */
  private boolean allowEphemeralKeys = false;
  private long maxRequestBodyBytes = 65536;
  /**
   * Whether to derive the client IP from {@code X-Forwarded-For} when keying origin rate limits.
   *
   * <p>Off by default, and that default is the safe one: the header is trivially spoofable, so
   * trusting it without a proxy that overwrites it lets one source mint unlimited distinct
   * rate-limit keys and escape the limiter entirely. Turn it on only behind a trusted proxy that
   * sets the header itself rather than appending to a client-supplied one.
   *
   * <p>Declared here rather than read only through {@code @Value} so it appears in IDE completion
   * and in the generated configuration metadata alongside every other {@code hofmann.*} property.
   * It was previously invisible to both, which is how a security-relevant switch ends up
   * undiscoverable.
   */
  private boolean trustForwardedHeaders = false;

  /**
   * Creates the properties holder with the defaults documented on each field. Spring Boot
   * instantiates this and binds {@code hofmann.*} onto it; applications read it as a bean rather
   * than constructing it.
   */
  public HofmannProperties() {
  }

  /**
   * Gets opaque cipher suite.
   *
   * @return the opaque cipher suite
   */
  public String getOpaqueCipherSuite() {
    return opaqueCipherSuite;
  }

  /**
   * Sets opaque cipher suite.
   *
   * @param opaqueCipherSuite the opaque cipher suite
   */
  public void setOpaqueCipherSuite(String opaqueCipherSuite) {
    this.opaqueCipherSuite = opaqueCipherSuite;
  }

  /**
   * Gets oprf cipher suite.
   *
   * @return the oprf cipher suite
   */
  public String getOprfCipherSuite() {
    return oprfCipherSuite;
  }

  /**
   * Sets oprf cipher suite.
   *
   * @param oprfCipherSuite the oprf cipher suite
   */
  public void setOprfCipherSuite(String oprfCipherSuite) {
    this.oprfCipherSuite = oprfCipherSuite;
  }

  /**
   * Gets server key seed hex.
   *
   * @return the server key seed hex
   */
  public String getServerKeySeedHex() {
    return serverKeySeedHex;
  }

  /**
   * Sets server key seed hex.
   *
   * @param serverKeySeedHex the server key seed hex
   */
  public void setServerKeySeedHex(String serverKeySeedHex) {
    this.serverKeySeedHex = serverKeySeedHex;
  }

  /**
   * Gets oprf seed hex.
   *
   * @return the oprf seed hex
   */
  public String getOprfSeedHex() {
    return oprfSeedHex;
  }

  /**
   * Sets oprf seed hex.
   *
   * @param oprfSeedHex the oprf seed hex
   */
  public void setOprfSeedHex(String oprfSeedHex) {
    this.oprfSeedHex = oprfSeedHex;
  }

  /**
   * Gets previous server key seed hex.
   *
   * @return the previous server key seed hex
   */
  public String getPreviousServerKeySeedHex() {
    return previousServerKeySeedHex;
  }

  /**
   * Sets previous server key seed hex.
   *
   * @param previousServerKeySeedHex the previous server key seed hex
   */
  public void setPreviousServerKeySeedHex(String previousServerKeySeedHex) {
    this.previousServerKeySeedHex = previousServerKeySeedHex;
  }

  /**
   * Gets previous oprf seed hex.
   *
   * @return the previous oprf seed hex
   */
  public String getPreviousOprfSeedHex() {
    return previousOprfSeedHex;
  }

  /**
   * Sets previous oprf seed hex.
   *
   * @param previousOprfSeedHex the previous oprf seed hex
   */
  public void setPreviousOprfSeedHex(String previousOprfSeedHex) {
    this.previousOprfSeedHex = previousOprfSeedHex;
  }

  /**
   * Gets oprf master key hex.
   *
   * @return the oprf master key hex
   */
  public String getOprfMasterKeyHex() {
    return oprfMasterKeyHex;
  }

  /**
   * Sets oprf master key hex.
   *
   * @param oprfMasterKeyHex the oprf master key hex
   */
  public void setOprfMasterKeyHex(String oprfMasterKeyHex) {
    this.oprfMasterKeyHex = oprfMasterKeyHex;
  }

  /**
   * Gets oprf processor id.
   *
   * @return the oprf processor id
   */
  public String getOprfProcessorId() {
    return oprfProcessorId;
  }

  /**
   * Sets oprf processor id.
   *
   * @param oprfProcessorId the oprf processor id
   */
  public void setOprfProcessorId(String oprfProcessorId) {
    this.oprfProcessorId = oprfProcessorId;
  }

  /**
   * Gets context.
   *
   * @return the context
   */
  public String getContext() {
    return context;
  }

  /**
   * Sets context.
   *
   * @param context the context
   */
  public void setContext(String context) {
    this.context = context;
  }

  /**
   * Gets jwt secret hex.
   *
   * @return the jwt secret hex
   */
  public String getJwtSecretHex() {
    return jwtSecretHex;
  }

  /**
   * Sets jwt secret hex.
   *
   * @param jwtSecretHex the jwt secret hex
   */
  public void setJwtSecretHex(String jwtSecretHex) {
    this.jwtSecretHex = jwtSecretHex;
  }

  /**
   * Gets jwt previous secret hex.
   *
   * @return the jwt previous secret hex
   */
  public String getJwtPreviousSecretHex() {
    return jwtPreviousSecretHex;
  }

  /**
   * Sets jwt previous secret hex.
   *
   * @param jwtPreviousSecretHex the jwt previous secret hex
   */
  public void setJwtPreviousSecretHex(String jwtPreviousSecretHex) {
    this.jwtPreviousSecretHex = jwtPreviousSecretHex;
  }

  /**
   * Gets jwt ttl seconds.
   *
   * @return the jwt ttl seconds
   */
  public long getJwtTtlSeconds() {
    return jwtTtlSeconds;
  }

  /**
   * Sets jwt ttl seconds.
   *
   * @param jwtTtlSeconds the jwt ttl seconds
   */
  public void setJwtTtlSeconds(long jwtTtlSeconds) {
    this.jwtTtlSeconds = jwtTtlSeconds;
  }

  /**
   * Gets jwt issuer.
   *
   * @return the jwt issuer
   */
  public String getJwtIssuer() {
    return jwtIssuer;
  }

  /**
   * Sets jwt issuer.
   *
   * @param jwtIssuer the jwt issuer
   */
  public void setJwtIssuer(String jwtIssuer) {
    this.jwtIssuer = jwtIssuer;
  }

  /**
   * Gets argon 2 memory kib.
   *
   * @return the argon 2 memory kib
   */
  public int getArgon2MemoryKib() {
    return argon2MemoryKib;
  }

  /**
   * Sets argon 2 memory kib.
   *
   * @param argon2MemoryKib the argon 2 memory kib
   */
  public void setArgon2MemoryKib(int argon2MemoryKib) {
    this.argon2MemoryKib = argon2MemoryKib;
  }

  /**
   * Gets argon 2 iterations.
   *
   * @return the argon 2 iterations
   */
  public int getArgon2Iterations() {
    return argon2Iterations;
  }

  /**
   * Sets argon 2 iterations.
   *
   * @param argon2Iterations the argon 2 iterations
   */
  public void setArgon2Iterations(int argon2Iterations) {
    this.argon2Iterations = argon2Iterations;
  }

  /**
   * Gets argon 2 parallelism.
   *
   * @return the argon 2 parallelism
   */
  public int getArgon2Parallelism() {
    return argon2Parallelism;
  }

  /**
   * Sets argon 2 parallelism.
   *
   * @param argon2Parallelism the argon 2 parallelism
   */
  public void setArgon2Parallelism(int argon2Parallelism) {
    this.argon2Parallelism = argon2Parallelism;
  }

  /**
   * Whether the identity KSF (no key stretching) is allowed. Must be set to {@code true}
   * when {@code argon2MemoryKib} is 0, otherwise startup fails. Defaults to {@code false}
   * to prevent accidental production deployment without key stretching.
   *
   * @return true if identity KSF is allowed
   */
  public boolean isAllowIdentityKsf() {
    return allowIdentityKsf;
  }

  /**
   * Sets allow identity ksf.
   *
   * @param allowIdentityKsf the allow identity ksf
   */
  public void setAllowIdentityKsf(boolean allowIdentityKsf) {
    this.allowIdentityKsf = allowIdentityKsf;
  }

  /**
   * Whether ephemeral key generation is permitted when key material is unset.
   *
   * @return true if ephemeral keys are allowed
   */
  public boolean isAllowEphemeralKeys() {
    return allowEphemeralKeys;
  }

  /**
   * Sets whether ephemeral key generation is permitted.
   *
   * @param allowEphemeralKeys the flag
   */
  public void setAllowEphemeralKeys(boolean allowEphemeralKeys) {
    this.allowEphemeralKeys = allowEphemeralKeys;
  }

  /**
   * Maximum allowed request body size in bytes. Defaults to 65536 (64 KiB) — well above the
   * largest OPAQUE/OPRF message but small enough to block large-payload DoS attempts.
   *
   * @return the max request body bytes
   */
  public long getMaxRequestBodyBytes() {
    return maxRequestBodyBytes;
  }

  /**
   * Sets max request body bytes.
   *
   * @param maxRequestBodyBytes the max request body bytes
   */
  public void setMaxRequestBodyBytes(long maxRequestBodyBytes) {
    this.maxRequestBodyBytes = maxRequestBodyBytes;
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

  /**
   * Whether to trust {@code X-Forwarded-For} when keying origin rate limits.
   *
   * @return true if forwarded headers are trusted
   */
  public boolean isTrustForwardedHeaders() {
    return trustForwardedHeaders;
  }

  /**
   * Sets whether to trust {@code X-Forwarded-For} when keying origin rate limits.
   *
   * @param trustForwardedHeaders true to trust forwarded headers
   */
  public void setTrustForwardedHeaders(boolean trustForwardedHeaders) {
    this.trustForwardedHeaders = trustForwardedHeaders;
  }
}
