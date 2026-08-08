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
import com.codeheadsystems.rfc.oprf.manager.OprfClientManager;
import com.codeheadsystems.rfc.oprf.model.BlindedRequest;
import com.codeheadsystems.rfc.oprf.model.ClientHashingContext;
import com.codeheadsystems.rfc.oprf.model.EvaluatedResponse;
import com.codeheadsystems.rfc.oprf.model.HashResult;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

/**
 * The type Hofmann oprf client manager test.
 */
@ExtendWith(MockitoExtension.class)
class HofmannOprfClientManagerTest {

  private static final ServerIdentifier SERVER_ID = new ServerIdentifier("test-server");
  private static final String SENSITIVE_DATA = "my-password";
  private static final String REQUEST_ID = "req-uuid-1";
  private static final String PROCESS_ID = "proc-test";
  private static final String BLINDED_POINT_HEX = "03aabbccdd";
  private static final byte[] HASH = new byte[]{1, 2, 3, 4};
  private static final byte[] SENSITIVE_BYTES = SENSITIVE_DATA.getBytes(StandardCharsets.UTF_8);

  @Mock private HofmannOprfAccessor hofmannOprfAccessor;
  @Mock private OprfClientManager oprfClientManager;
  @Mock private OprfResponse oprfResponse;
  @Mock private EvaluatedResponse evaluatedResponse;

  private HofmannOprfClientManager manager;

  /**
   * Sets up.
   */
  @BeforeEach
  void setUp() {
    manager = new HofmannOprfClientManager(hofmannOprfAccessor, oprfClientManager);
  }

  /**
   * Perform hash success returns correct hash result.
   */
  @Test
  void performHash_success_returnsCorrectHashResult() {
    ClientHashingContext context = new ClientHashingContext(REQUEST_ID, BigInteger.TWO, SENSITIVE_DATA.getBytes());
    BlindedRequest blindedRequest = new BlindedRequest(BLINDED_POINT_HEX, REQUEST_ID);
    HashResult hashResult = new HashResult(HASH, PROCESS_ID);

    // The byte[] overload: performHash(String) converts and delegates, so this is the call that
    // actually lands whichever entry point the caller used.
    when(oprfClientManager.hashingContext(any(byte[].class))).thenReturn(context);
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

  /**
   * Perform hash oprf request wraps blinded request fields not transposed.
   */
  @Test
  void performHash_oprfRequestWrapsBlindedRequest_fieldsNotTransposed() {
    ClientHashingContext context = new ClientHashingContext(REQUEST_ID, BigInteger.TWO, SENSITIVE_DATA.getBytes());
    BlindedRequest blindedRequest = new BlindedRequest(BLINDED_POINT_HEX, REQUEST_ID);
    HashResult hashResult = new HashResult(HASH, PROCESS_ID);

    // The byte[] overload: performHash(String) converts and delegates, so this is the call that
    // actually lands whichever entry point the caller used.
    when(oprfClientManager.hashingContext(any(byte[].class))).thenReturn(context);
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

  /**
   * The byte[] entry point works, and does not retain or clear the caller's array.
   *
   * <p>The point of offering bytes at all is that the caller's copy is theirs to erase. That only
   * helps if this method leaves it alone — a library that cleared the argument would break any
   * caller reusing the value, and one that held onto it would leave the secret reachable through a
   * reference the caller thought they had finished with.
   */
  @Test
  void performHash_acceptsBytesAndLeavesTheCallersArrayAlone() {
    ClientHashingContext context = new ClientHashingContext(REQUEST_ID, BigInteger.TWO, SENSITIVE_BYTES);
    BlindedRequest blindedRequest = new BlindedRequest(BLINDED_POINT_HEX, REQUEST_ID);
    HashResult hashResult = new HashResult(HASH, PROCESS_ID);

    when(oprfClientManager.hashingContext(any(byte[].class))).thenReturn(context);
    when(oprfClientManager.eliminationRequest(context)).thenReturn(blindedRequest);
    when(hofmannOprfAccessor.handleRequest(eq(SERVER_ID), any(OprfRequest.class))).thenReturn(oprfResponse);
    when(oprfResponse.evaluatedResponse()).thenReturn(evaluatedResponse);
    when(oprfClientManager.hashResult(evaluatedResponse, context)).thenReturn(hashResult);

    byte[] callerSecret = SENSITIVE_DATA.getBytes(StandardCharsets.UTF_8);
    HofmannHashResult result = manager.performHash(callerSecret, SERVER_ID);

    assertThat(result.hash()).isEqualTo(HASH);
    assertThat(callerSecret)
        .as("the caller's array is theirs; this must neither clear nor mutate it")
        .isEqualTo(SENSITIVE_DATA.getBytes(StandardCharsets.UTF_8));
  }

  /**
   * The context is closed on the way out, including when the round trip throws.
   *
   * <p>The throwing path is the one that matters: the caller never receives the context, so if this
   * method does not clear it nobody can. Asserted with a real context rather than a mock, since the
   * property under test is that its bytes are zero afterwards.
   */
  @Test
  void performHash_clearsTheContextEvenWhenTheExchangeFails() {
    ClientHashingContext context = new ClientHashingContext(REQUEST_ID, BigInteger.TWO, SENSITIVE_BYTES);

    when(oprfClientManager.hashingContext(any(byte[].class))).thenReturn(context);
    when(oprfClientManager.eliminationRequest(context))
        .thenThrow(new IllegalStateException("server unreachable"));

    try {
      manager.performHash(SENSITIVE_DATA.getBytes(StandardCharsets.UTF_8), SERVER_ID);
    } catch (IllegalStateException expected) {
      // the failure is the scenario, not the assertion
    }

    assertThat(context.input())
        .as("a failed exchange must not leave the input on the heap with no handle to clear it")
        .containsOnly((byte) 0);
    assertThat(Arrays.equals(SENSITIVE_BYTES, new byte[SENSITIVE_BYTES.length]))
        .as("and the constant the context copied from is untouched, so later tests still see it")
        .isFalse();
  }
}
