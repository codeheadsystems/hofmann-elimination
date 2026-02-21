package com.codeheadsystems.hofmann.client.manager;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.codeheadsystems.hofmann.client.accessor.HofmannOprfAccessor;
import com.codeheadsystems.hofmann.client.model.HofmannHashResult;
import com.codeheadsystems.hofmann.client.model.ServerIdentifier;
import com.codeheadsystems.hofmann.model.oprf.OprfRequest;
import com.codeheadsystems.hofmann.model.oprf.OprfResponse;
import com.codeheadsystems.oprf.manager.OprfClientManager;
import com.codeheadsystems.oprf.model.BlindedRequest;
import com.codeheadsystems.oprf.model.ClientHashingContext;
import com.codeheadsystems.oprf.model.EvaluatedResponse;
import com.codeheadsystems.oprf.model.HashResult;
import java.math.BigInteger;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class HofmannOprfClientManagerTest {

  private static final ServerIdentifier SERVER_ID = new ServerIdentifier("test-server");
  private static final String SENSITIVE_DATA = "my-password";
  private static final String REQUEST_ID = "req-uuid-1";
  private static final String PROCESS_ID = "proc-test";
  private static final String BLINDED_POINT_HEX = "03aabbccdd";
  private static final byte[] HASH = new byte[]{1, 2, 3, 4};

  @Mock private HofmannOprfAccessor hofmannOprfAccessor;
  @Mock private OprfClientManager oprfClientManager;
  @Mock private OprfResponse oprfResponse;
  @Mock private EvaluatedResponse evaluatedResponse;

  private HofmannOprfClientManager manager;

  @BeforeEach
  void setUp() {
    manager = new HofmannOprfClientManager(hofmannOprfAccessor, oprfClientManager);
  }

  @Test
  void performHash_success_returnsCorrectHashResult() {
    ClientHashingContext context = new ClientHashingContext(REQUEST_ID, BigInteger.TWO, SENSITIVE_DATA.getBytes());
    BlindedRequest blindedRequest = new BlindedRequest(BLINDED_POINT_HEX, REQUEST_ID);
    HashResult hashResult = new HashResult(HASH, PROCESS_ID);

    when(oprfClientManager.hashingContext(SENSITIVE_DATA)).thenReturn(context);
    when(oprfClientManager.eliminationRequest(context)).thenReturn(blindedRequest);
    when(hofmannOprfAccessor.handleRequest(eq(SERVER_ID), any(OprfRequest.class))).thenReturn(oprfResponse);
    when(oprfResponse.evaluatedResponse()).thenReturn(evaluatedResponse);
    when(oprfClientManager.hashResult(evaluatedResponse, context)).thenReturn(hashResult);

    HofmannHashResult result = manager.performHash(SENSITIVE_DATA, SERVER_ID);

    assertThat(result.serverIdentifier()).isEqualTo(SERVER_ID);
    assertThat(result.processIdentifier()).isEqualTo(PROCESS_ID);
    assertThat(result.requestId()).isEqualTo(REQUEST_ID);
    assertThat(result.hash()).isEqualTo(HASH);
  }

  @Test
  void performHash_oprfRequestWrapsBlindedRequest_fieldsNotTransposed() {
    ClientHashingContext context = new ClientHashingContext(REQUEST_ID, BigInteger.TWO, SENSITIVE_DATA.getBytes());
    BlindedRequest blindedRequest = new BlindedRequest(BLINDED_POINT_HEX, REQUEST_ID);
    HashResult hashResult = new HashResult(HASH, PROCESS_ID);

    when(oprfClientManager.hashingContext(SENSITIVE_DATA)).thenReturn(context);
    when(oprfClientManager.eliminationRequest(context)).thenReturn(blindedRequest);
    when(hofmannOprfAccessor.handleRequest(eq(SERVER_ID), any(OprfRequest.class))).thenReturn(oprfResponse);
    when(oprfResponse.evaluatedResponse()).thenReturn(evaluatedResponse);
    when(oprfClientManager.hashResult(evaluatedResponse, context)).thenReturn(hashResult);

    manager.performHash(SENSITIVE_DATA, SERVER_ID);

    ArgumentCaptor<OprfRequest> captor = ArgumentCaptor.forClass(OprfRequest.class);
    verify(hofmannOprfAccessor).handleRequest(eq(SERVER_ID), captor.capture());
    OprfRequest capturedRequest = captor.getValue();
    assertThat(capturedRequest.ecPoint()).isEqualTo(BLINDED_POINT_HEX);
    assertThat(capturedRequest.requestId()).isEqualTo(REQUEST_ID);
  }
}
