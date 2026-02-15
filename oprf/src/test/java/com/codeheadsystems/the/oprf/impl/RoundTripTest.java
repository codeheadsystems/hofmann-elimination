package com.codeheadsystems.the.oprf.impl;

import static org.assertj.core.api.Assertions.assertThat;

import com.codeheadsystems.the.oprf.Client;
import com.codeheadsystems.the.oprf.Server;
import org.junit.jupiter.api.Test;

public class RoundTripTest {

  private static final String TEST_DATA = "test data for round trip";
  private static final String TEST_DATA2 = "Different Data";

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


}
