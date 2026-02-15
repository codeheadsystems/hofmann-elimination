package com.codeheadsystems.hofmann.client.accessor;

import javax.inject.Inject;
import javax.inject.Singleton;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Singleton
public class OprfAccessor {
  private static final Logger log = LoggerFactory.getLogger(OprfAccessor.class);

  @Inject
  public OprfAccessor() {
    log.info("OprfAccessor()");
  }

}
