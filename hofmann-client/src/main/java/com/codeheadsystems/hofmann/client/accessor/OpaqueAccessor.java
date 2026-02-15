package com.codeheadsystems.hofmann.client.accessor;

import javax.inject.Inject;
import javax.inject.Singleton;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Singleton
public class OpaqueAccessor {

  private static final Logger log = LoggerFactory.getLogger(OpaqueAccessor.class);

  @Inject
  public OpaqueAccessor() {
    log.info("OpaqueAccessor()");
  }

}
