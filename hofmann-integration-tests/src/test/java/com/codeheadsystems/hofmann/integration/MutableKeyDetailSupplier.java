package com.codeheadsystems.hofmann.integration;

import com.codeheadsystems.hofmann.server.manager.OpaqueServerKeyDetail;
import com.codeheadsystems.rfc.opaque.Server;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Supplier;

/**
 * Test-only mutable supplier for {@link OpaqueServerKeyDetail} that allows
 * key rotation mid-test. Starts with a single server at version 0 and
 * supports {@link #rotateKeys(Server)} to bump to a new version while
 * preserving old servers for authentication of existing credentials.
 */
class MutableKeyDetailSupplier implements Supplier<OpaqueServerKeyDetail> {

  private final AtomicReference<OpaqueServerKeyDetail> ref;
  private final OpaqueServerKeyDetail initial;

  MutableKeyDetailSupplier(Server initialServer) {
    initial = new OpaqueServerKeyDetail(initialServer);
    ref = new AtomicReference<>(initial);
  }

  /**
   * Rotates to a new server. The old current server moves into previousServers.
   */
  void rotateKeys(Server newServer) {
    OpaqueServerKeyDetail old = ref.get();
    Map<Integer, Server> previous = new HashMap<>(old.previousServers());
    previous.put(old.currentVersion(), old.currentServer());
    ref.set(new OpaqueServerKeyDetail(
        old.currentVersion() + 1, newServer, Map.copyOf(previous)));
  }

  /**
   * Resets back to the initial single-key state (version 0).
   */
  void reset() {
    ref.set(initial);
  }

  @Override
  public OpaqueServerKeyDetail get() {
    return ref.get();
  }
}
