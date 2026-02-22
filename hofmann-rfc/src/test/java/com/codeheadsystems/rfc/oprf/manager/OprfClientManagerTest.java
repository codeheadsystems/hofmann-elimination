package com.codeheadsystems.rfc.oprf.manager;

import static org.assertj.core.api.Assertions.assertThat;

import com.codeheadsystems.rfc.oprf.model.BlindedRequest;
import com.codeheadsystems.rfc.oprf.model.ClientHashingContext;
import com.codeheadsystems.rfc.oprf.model.EvaluatedResponse;
import com.codeheadsystems.rfc.oprf.model.HashResult;
import com.codeheadsystems.rfc.oprf.rfc9497.CurveHashSuite;
import com.codeheadsystems.rfc.oprf.rfc9497.OprfCipherSuite;
import org.junit.jupiter.api.Test;

class OprfClientManagerTest {

  private final OprfCipherSuite suite = OprfCipherSuite.builder()
      .withSuite(CurveHashSuite.P256_SHA256).build();
  private final OprfClientManager manager = new OprfClientManager(suite);

  @Test
  void hashingContext_producesValidContext() {
    ClientHashingContext ctx = manager.hashingContext("password123");

    assertThat(ctx.requestId()).isNotNull().isNotBlank();
    assertThat(ctx.blindingFactor()).isNotNull();
    assertThat(ctx.blindingFactor().signum()).isPositive();
    assertThat(ctx.input()).isEqualTo("password123".getBytes());
  }

  @Test
  void hashingContext_differentCallsProduceDifferentRequestIds() {
    ClientHashingContext ctx1 = manager.hashingContext("test");
    ClientHashingContext ctx2 = manager.hashingContext("test");
    assertThat(ctx1.requestId()).isNotEqualTo(ctx2.requestId());
  }

  @Test
  void eliminationRequest_producesValidHexPoint() {
    ClientHashingContext ctx = manager.hashingContext("test");
    BlindedRequest req = manager.eliminationRequest(ctx);

    assertThat(req.requestId()).isEqualTo(ctx.requestId());
    assertThat(req.blindedPoint()).isNotNull().isNotBlank();
    // Hex string should be even length (byte-aligned)
    assertThat(req.blindedPoint().length() % 2).isZero();
  }

  @Test
  void fullRoundTrip_clientServerClient() {
    // Simulate: client blind → server evaluate → client finalize
    OprfServerManager serverManager = new OprfServerManager(suite,
        () -> new com.codeheadsystems.rfc.oprf.model.ServerProcessorDetail(
            suite.deriveKeyPair("server-seed-key".getBytes(), new byte[0]),
            "proc-1"));

    ClientHashingContext ctx = manager.hashingContext("my-secret");
    BlindedRequest blindedReq = manager.eliminationRequest(ctx);
    EvaluatedResponse serverResp = serverManager.process(blindedReq);
    HashResult result = manager.hashResult(serverResp, ctx);

    assertThat(result.hash()).hasSize(suite.hashOutputLength());
    assertThat(result.processIdentifier()).isEqualTo("proc-1");
  }
}
