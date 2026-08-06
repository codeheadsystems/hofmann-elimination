package com.codeheadsystems.hofmann.client.config;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.codeheadsystems.hofmann.client.accessor.HofmannOpaqueAccessor;
import com.codeheadsystems.hofmann.client.manager.HofmannOpaqueClientManager;
import com.codeheadsystems.hofmann.client.model.ServerIdentifier;
import com.codeheadsystems.hofmann.model.opaque.OpaqueClientConfigResponse;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

/**
 * The OPAQUE context is the binding that stops a transcript from one deployment being replayed
 * against another, and USAGE.md specifies it is shared out-of-band — yet both clients read it from
 * {@code GET /opaque/config}, the channel an attacker in the middle controls. It matters more than
 * it looks here, because the client manager passes null for both identities, leaving the context
 * the only deployment-distinguishing value in the preamble.
 */
class ContextPinningTest {

  private static final String SUITE = "P256_SHA256";

  private static OpaqueClientConfigResponse serverSaying(String context) {
    return new OpaqueClientConfigResponse(SUITE, context, 65536, 3, 1);
  }

  @Test
  void matchingContextIsAccepted() {
    assertThatCode(() ->
        OpaqueClientConfig.fromServerConfig(serverSaying("prod-deployment"), false,
            "prod-deployment"))
        .doesNotThrowAnyException();
  }

  @Test
  void mismatchedContextIsRejected() {
    assertThatThrownBy(() ->
        OpaqueClientConfig.fromServerConfig(serverSaying("attacker-deployment"), false,
            "prod-deployment"))
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining("does not match")
        .hasMessageContaining("out-of-band");
  }

  @Test
  void nullExpectedContextAcceptsWhateverTheServerSends() {
    assertThatCode(() ->
        OpaqueClientConfig.fromServerConfig(serverSaying("anything"), false, null))
        .doesNotThrowAnyException();
  }

  @Test
  void acceptedConfigCarriesTheContext() {
    assertThat(OpaqueClientConfig.fromServerConfig(serverSaying("prod"), false, "prod")
        .opaqueConfig().context())
        .isEqualTo("prod".getBytes(StandardCharsets.UTF_8));
  }

  /**
   * Pinning is only worth anything if the production client path can reach it. An earlier version
   * added the check but left the manager calling the overload that passes null, so the only way to
   * pin was to fetch the config and call the method by hand — at which point the caller has done
   * the pinning themselves.
   */
  @Test
  void managerPassesTheExpectedContextThrough() {
    ServerIdentifier serverId = new ServerIdentifier("s1");
    HofmannOpaqueAccessor accessor = Mockito.mock(HofmannOpaqueAccessor.class);
    Mockito.when(accessor.getOpaqueConfig(serverId)).thenReturn(serverSaying("attacker"));

    HofmannOpaqueClientManager manager = new HofmannOpaqueClientManager(
        accessor, Collections.emptyMap(), false, "prod-deployment");

    assertThatThrownBy(() ->
        manager.register(serverId, "alice".getBytes(StandardCharsets.UTF_8),
            "pw".getBytes(StandardCharsets.UTF_8)))
        .as("a manager configured with an expected context must reject a server that disagrees")
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining("does not match");
  }

  @Test
  void managerWithoutAnExpectedContextStillWorks() {
    ServerIdentifier serverId = new ServerIdentifier("s1");
    HofmannOpaqueAccessor accessor = Mockito.mock(HofmannOpaqueAccessor.class);
    Mockito.when(accessor.getOpaqueConfig(serverId)).thenReturn(serverSaying("whatever"));

    HofmannOpaqueClientManager manager =
        new HofmannOpaqueClientManager(accessor, Collections.emptyMap(), false);

    assertThatThrownBy(() ->
        manager.register(serverId, "alice".getBytes(StandardCharsets.UTF_8),
            "pw".getBytes(StandardCharsets.UTF_8)))
        .as("should fail on the mocked HTTP call, not on a context mismatch")
        .isNotInstanceOf(IllegalStateException.class);
  }
}
