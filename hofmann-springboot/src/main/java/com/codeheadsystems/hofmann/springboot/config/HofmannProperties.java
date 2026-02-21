package com.codeheadsystems.hofmann.springboot.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

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

  public String getOpaqueCipherSuite() {
    return opaqueCipherSuite;
  }

  public void setOpaqueCipherSuite(String opaqueCipherSuite) {
    this.opaqueCipherSuite = opaqueCipherSuite;
  }

  public String getOprfCipherSuite() {
    return oprfCipherSuite;
  }

  public void setOprfCipherSuite(String oprfCipherSuite) {
    this.oprfCipherSuite = oprfCipherSuite;
  }

  public String getServerKeySeedHex() {
    return serverKeySeedHex;
  }

  public void setServerKeySeedHex(String serverKeySeedHex) {
    this.serverKeySeedHex = serverKeySeedHex;
  }

  public String getOprfSeedHex() {
    return oprfSeedHex;
  }

  public void setOprfSeedHex(String oprfSeedHex) {
    this.oprfSeedHex = oprfSeedHex;
  }

  public String getOprfMasterKeyHex() {
    return oprfMasterKeyHex;
  }

  public void setOprfMasterKeyHex(String oprfMasterKeyHex) {
    this.oprfMasterKeyHex = oprfMasterKeyHex;
  }

  public String getOprfProcessorId() {
    return oprfProcessorId;
  }

  public void setOprfProcessorId(String oprfProcessorId) {
    this.oprfProcessorId = oprfProcessorId;
  }

  public String getContext() {
    return context;
  }

  public void setContext(String context) {
    this.context = context;
  }

  public String getJwtSecretHex() {
    return jwtSecretHex;
  }

  public void setJwtSecretHex(String jwtSecretHex) {
    this.jwtSecretHex = jwtSecretHex;
  }

  public long getJwtTtlSeconds() {
    return jwtTtlSeconds;
  }

  public void setJwtTtlSeconds(long jwtTtlSeconds) {
    this.jwtTtlSeconds = jwtTtlSeconds;
  }

  public String getJwtIssuer() {
    return jwtIssuer;
  }

  public void setJwtIssuer(String jwtIssuer) {
    this.jwtIssuer = jwtIssuer;
  }

  public int getArgon2MemoryKib() {
    return argon2MemoryKib;
  }

  public void setArgon2MemoryKib(int argon2MemoryKib) {
    this.argon2MemoryKib = argon2MemoryKib;
  }

  public int getArgon2Iterations() {
    return argon2Iterations;
  }

  public void setArgon2Iterations(int argon2Iterations) {
    this.argon2Iterations = argon2Iterations;
  }

  public int getArgon2Parallelism() {
    return argon2Parallelism;
  }

  public void setArgon2Parallelism(int argon2Parallelism) {
    this.argon2Parallelism = argon2Parallelism;
  }
}
