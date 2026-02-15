package com.codeheadsystems.hofmann.server.manager;

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

}
