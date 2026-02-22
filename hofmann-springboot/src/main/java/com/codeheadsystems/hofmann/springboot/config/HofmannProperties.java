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
  private String oprfMasterKeyHex = "";
  private String oprfProcessorId = "hofmann-oprf-v1";
  private String context = "hofmann-opaque-v1";
  private String jwtSecretHex = "";
  private long jwtTtlSeconds = 3600;
  private String jwtIssuer = "hofmann";
  private int argon2MemoryKib = 65536;
  private int argon2Iterations = 3;
  private int argon2Parallelism = 1;

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
}
