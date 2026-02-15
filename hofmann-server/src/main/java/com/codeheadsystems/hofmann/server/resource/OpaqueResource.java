package com.codeheadsystems.hofmann.server.resource;

import javax.inject.Inject;
import javax.inject.Singleton;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Singleton
public class OpaqueResource {
  private static final Logger log = LoggerFactory.getLogger(OpaqueResource.class);

  @Inject
  public OpaqueResource() {
    log.info("OpaqueResource()");

  }
}
