package com.codeheadsystems.hofmann.server.resource;

import javax.inject.Inject;
import javax.inject.Singleton;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Singleton
public class OprfResource {
  private static final Logger log = LoggerFactory.getLogger(OprfResource.class);

  @Inject
  public OprfResource() {
    log.info("OprfResource()");
  }

}
