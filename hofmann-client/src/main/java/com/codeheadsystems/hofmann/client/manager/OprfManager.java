package com.codeheadsystems.hofmann.client.manager;

import com.codeheadsystems.hofmann.client.model.HashResult;
import javax.inject.Inject;
import javax.inject.Singleton;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Singleton
public class OprfManager {
  static private final Logger log = LoggerFactory.getLogger(OprfManager.class);

  @Inject
  public OprfManager() {
    log.info("OprfManager()");
  }

  /**
   * This process manages the OPRF hashing process that uses the server to provide a secret, via the OPRF protocol.
   *
   * @param input sensitive data to be hashed.
   * @return the RFC 9387 compliant OPRF hash of the input, using the server as the OPRF provider.
   */
  public HashResult performHash(String input, String serverIdentifier) {
    log.trace("performHashing()");
    return null;
  }

}
