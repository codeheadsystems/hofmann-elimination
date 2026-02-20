package com.codeheadsystems.oprf.impl;

import static org.assertj.core.api.Assertions.assertThat;

import com.codeheadsystems.oprf.Client;
import com.codeheadsystems.oprf.Server;
import com.codeheadsystems.oprf.rfc9497.OprfCipherSuite;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

public class RoundTripTest {

  private static final String TEST_DATA = "test data for round trip";
  private static final String TEST_DATA2 = "Different Data";

  static Stream<OprfCipherSuite> allSuites() {
    return Stream.of(
        OprfCipherSuite.P256_SHA256,
        OprfCipherSuite.P384_SHA384,
        OprfCipherSuite.P521_SHA512,
        OprfCipherSuite.RISTRETTO255_SHA512
    );
  }

  // ─── Existing P256-SHA256 tests (backward compat) ─────────────────────────

  @Test
  void testRoundTrip() {
    Server server = new ServerImpl();
    Client alice = new Client();
    Client bob = new Client();

    String aliceHash = alice.convertToIdentityKey(server, TEST_DATA);
    String bobHash = bob.convertToIdentityKey(server, TEST_DATA);
    String aliceHash2 = alice.convertToIdentityKey(server, TEST_DATA2);
    String bobHash2 = bob.convertToIdentityKey(server, TEST_DATA2);

    assertThat(aliceHash).isEqualTo(bobHash)
        .isNotEqualTo(aliceHash2).isNotEqualTo(bobHash2);
    assertThat(aliceHash2).isEqualTo(bobHash2)
        .isNotEqualTo(aliceHash).isNotEqualTo(bobHash);
  }

  @Test
  void testDifferentServersHaveDifferentResults() {
    Server server1 = new ServerImpl();
    Server server2 = new ServerImpl();
    Client alice = new Client();

    String hash1 = alice.convertToIdentityKey(server1, TEST_DATA);
    String hash2 = alice.convertToIdentityKey(server2, TEST_DATA);

    assertThat(hash1).isNotEqualTo(hash2);
  }

  // ─── Parameterized multi-suite round-trip tests ────────────────────────────

  @ParameterizedTest(name = "roundTrip_{0}")
  @MethodSource("allSuites")
  void roundTripAllSuites(OprfCipherSuite suite) {
    Server server = new ServerImpl(suite);
    Client alice = new Client(suite);
    Client bob = new Client(suite);

    String aliceHash = alice.convertToIdentityKey(server, TEST_DATA);
    String bobHash = bob.convertToIdentityKey(server, TEST_DATA);
    String aliceHash2 = alice.convertToIdentityKey(server, TEST_DATA2);
    String bobHash2 = bob.convertToIdentityKey(server, TEST_DATA2);

    assertThat(aliceHash).isEqualTo(bobHash)
        .isNotEqualTo(aliceHash2).isNotEqualTo(bobHash2);
    assertThat(aliceHash2).isEqualTo(bobHash2)
        .isNotEqualTo(aliceHash).isNotEqualTo(bobHash);
  }

  @ParameterizedTest(name = "differentServers_{0}")
  @MethodSource("allSuites")
  void differentServersHaveDifferentResultsAllSuites(OprfCipherSuite suite) {
    Server server1 = new ServerImpl(suite);
    Server server2 = new ServerImpl(suite);
    Client alice = new Client(suite);

    String hash1 = alice.convertToIdentityKey(server1, TEST_DATA);
    String hash2 = alice.convertToIdentityKey(server2, TEST_DATA);

    assertThat(hash1).isNotEqualTo(hash2);
  }
}
