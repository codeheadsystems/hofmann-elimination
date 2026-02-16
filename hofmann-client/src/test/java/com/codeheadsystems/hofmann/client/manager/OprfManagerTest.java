package com.codeheadsystems.hofmann.client.manager;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;

import com.codeheadsystems.hofmann.client.accessor.OprfAccessor;
import com.codeheadsystems.hofmann.client.config.OprfConfig;
import com.codeheadsystems.hofmann.client.model.HashResult;
import com.codeheadsystems.hofmann.client.model.ServerIdentifier;
import com.codeheadsystems.oprf.curve.Curve;
import org.bouncycastle.math.ec.ECPoint;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class OprfManagerTest {

  private static final Curve CURVE = Curve.P256_CURVE;
  private static final OprfConfig CONFIG = new OprfConfig();
  private static final ServerIdentifier SERVER_ID = new ServerIdentifier("test-server");
  private static final String PROCESS_ID = "proc-test";

  // A fixed valid EC point to return from the mock accessor.
  // OprfSuite.finalize() unblides this internally using the random blind,
  // so the exact hash value is non-deterministic — but it will always be 32 bytes.
  private static final ECPoint MOCK_EVALUATED_POINT = CURVE.g();

  @Mock private OprfAccessor oprfAccessor;

  private OprfManager manager;

  @BeforeEach
  void setUp() {
    manager = new OprfManager(oprfAccessor, CONFIG);
  }

  @Test
  void performHash_populatesHashResultFields() {
    when(oprfAccessor.handleRequest(eq(SERVER_ID), any(), any()))
        .thenReturn(new OprfAccessor.Response(MOCK_EVALUATED_POINT, PROCESS_ID));

    HashResult result = manager.performHash("password", SERVER_ID);

    assertThat(result.serverIdentifier()).isEqualTo(SERVER_ID);
    assertThat(result.processIdentifier()).isEqualTo(PROCESS_ID);
    assertThat(result.requestId()).isNotNull().isNotBlank();
    assertThat(result.hash()).isNotNull().hasSize(32); // SHA-256 output
  }

  @Test
  void performHash_eachCall_hasUniqueRequestId() {
    ArgumentCaptor<String> requestIdCaptor = ArgumentCaptor.forClass(String.class);

    when(oprfAccessor.handleRequest(eq(SERVER_ID), requestIdCaptor.capture(), any()))
        .thenReturn(new OprfAccessor.Response(MOCK_EVALUATED_POINT, PROCESS_ID));

    manager.performHash("password", SERVER_ID);
    manager.performHash("password", SERVER_ID);

    assertThat(requestIdCaptor.getAllValues()).hasSize(2);
    assertThat(requestIdCaptor.getAllValues().get(0))
        .isNotEqualTo(requestIdCaptor.getAllValues().get(1));
  }

  @Test
  void performHash_differentInputs_produceDifferentHashes() {
    when(oprfAccessor.handleRequest(eq(SERVER_ID), any(), any()))
        .thenReturn(new OprfAccessor.Response(MOCK_EVALUATED_POINT, PROCESS_ID));

    HashResult result1 = manager.performHash("password-one", SERVER_ID);
    HashResult result2 = manager.performHash("password-two", SERVER_ID);

    assertThat(result1.hash()).isNotEqualTo(result2.hash());
  }

}
