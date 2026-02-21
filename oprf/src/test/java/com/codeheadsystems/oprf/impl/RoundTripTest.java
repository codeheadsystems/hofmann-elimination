package com.codeheadsystems.oprf.impl;

import static org.assertj.core.api.Assertions.assertThat;

import com.codeheadsystems.oprf.manager.OprfClientManager;
import com.codeheadsystems.oprf.manager.OprfServerManager;
import com.codeheadsystems.oprf.model.BlindedRequest;
import com.codeheadsystems.oprf.model.ClientHashingContext;
import com.codeheadsystems.oprf.model.EvaluatedResponse;
import com.codeheadsystems.oprf.model.HashResult;
import com.codeheadsystems.oprf.model.ServerProcessorDetail;
import com.codeheadsystems.oprf.rfc9497.OprfCipherSuite;
import java.util.UUID;
import java.util.stream.Stream;
import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

public class RoundTripTest {

  private static final OprfCipherSuite DEFAULT_SUITE = OprfCipherSuite.P256_SHA256;
  private static final String TEST_DATA = "test data for round trip";
  private static final String TEST_DATA2 = "Different Data";

  static Stream<OprfCipherSuite> allSuites() {
    return Stream.of(
        OprfCipherSuite.P256_SHA256,
        OprfCipherSuite.P384_SHA384,
        OprfCipherSuite.P521_SHA512
    );
  }

  /**
   * Defines the steps the client takes to convert sensitive data into a key that can be used for elimination.
   * Implements RFC 9497 OPRF mode 0 (OPRF).
   * \
   */
  public String convertToIdentityKey(final OprfClientManager oprfClientManager,
                                     final OprfServerManager oprfServerManager,
                                     final String sensitiveData) {
    final ClientHashingContext clientHashingContext = oprfClientManager.hashingContext(sensitiveData);
    final BlindedRequest blindedRequest = oprfClientManager.eliminationRequest(clientHashingContext);
    final EvaluatedResponse evaluatedResponse = oprfServerManager.process(blindedRequest);
    final HashResult result = oprfClientManager.hashResult(evaluatedResponse, clientHashingContext);
    return result.processIdentifier() + ":" + Hex.toHexString(result.hash());
  }

  private OprfServerManager oprfServerManager(OprfCipherSuite suite) {
    final ServerProcessorDetail detail = new ServerProcessorDetail(suite.randomScalar(), "SP:" + UUID.randomUUID());
    return new OprfServerManager(suite, () -> detail);
  }

  // ─── Existing P256-SHA256 tests (backward compat) ─────────────────────────

  @Test
  void testRoundTrip() {
    OprfServerManager oprfServerManager = oprfServerManager(DEFAULT_SUITE);
    OprfClientManager alice = new OprfClientManager(DEFAULT_SUITE);
    OprfClientManager bob = new OprfClientManager(DEFAULT_SUITE);

    String aliceHash = convertToIdentityKey(alice, oprfServerManager, TEST_DATA);
    String bobHash = convertToIdentityKey(bob, oprfServerManager, TEST_DATA);
    String aliceHash2 = convertToIdentityKey(alice, oprfServerManager, TEST_DATA2);
    String bobHash2 = convertToIdentityKey(bob, oprfServerManager, TEST_DATA2);

    assertThat(aliceHash).isEqualTo(bobHash)
        .isNotEqualTo(aliceHash2).isNotEqualTo(bobHash2);
    assertThat(aliceHash2).isEqualTo(bobHash2)
        .isNotEqualTo(aliceHash).isNotEqualTo(bobHash);
  }

  @Test
  void testDifferentServersHaveDifferentResults() {
    OprfServerManager oprfServerManager1 = oprfServerManager(DEFAULT_SUITE);
    OprfServerManager oprfServerManager2 = oprfServerManager(DEFAULT_SUITE);
    OprfClientManager alice = new OprfClientManager(DEFAULT_SUITE);

    String hash1 = convertToIdentityKey(alice, oprfServerManager1, TEST_DATA);
    String hash2 = convertToIdentityKey(alice, oprfServerManager2, TEST_DATA);

    assertThat(hash1).isNotEqualTo(hash2);
  }

  // ─── Parameterized multi-suite round-trip tests ────────────────────────────

  @ParameterizedTest(name = "roundTrip_{0}")
  @MethodSource("allSuites")
  void roundTripAllSuites(OprfCipherSuite suite) {
    OprfServerManager oprfServerManager = oprfServerManager(suite);
    OprfClientManager alice = new OprfClientManager(suite);
    OprfClientManager bob = new OprfClientManager(suite);

    String aliceHash = convertToIdentityKey(alice, oprfServerManager, TEST_DATA);
    String bobHash = convertToIdentityKey(bob, oprfServerManager, TEST_DATA);
    String aliceHash2 = convertToIdentityKey(alice, oprfServerManager, TEST_DATA2);
    String bobHash2 = convertToIdentityKey(bob, oprfServerManager, TEST_DATA2);

    assertThat(aliceHash).isEqualTo(bobHash)
        .isNotEqualTo(aliceHash2).isNotEqualTo(bobHash2);
    assertThat(aliceHash2).isEqualTo(bobHash2)
        .isNotEqualTo(aliceHash).isNotEqualTo(bobHash);
  }

  @ParameterizedTest(name = "differentServers_{0}")
  @MethodSource("allSuites")
  void differentServersHaveDifferentResultsAllSuites(OprfCipherSuite suite) {
    OprfServerManager oprfServerManager1 = oprfServerManager(suite);
    OprfServerManager oprfServerManager2 = oprfServerManager(suite);
    OprfClientManager alice = new OprfClientManager(suite);

    String hash1 = convertToIdentityKey(alice, oprfServerManager1, TEST_DATA);
    String hash2 = convertToIdentityKey(alice, oprfServerManager2, TEST_DATA);

    assertThat(hash1).isNotEqualTo(hash2);
  }
}
