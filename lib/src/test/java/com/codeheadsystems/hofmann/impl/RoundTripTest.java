package com.codeheadsystems.hofmann.impl;

import static org.assertj.core.api.Assertions.assertThat;

import com.codeheadsystems.hofmann.Client;
import com.codeheadsystems.hofmann.ClientKey;
import com.codeheadsystems.hofmann.Server;
import org.junit.jupiter.api.Test;

public class RoundTripTest {

  private static final String TEST_DATA = "test data for round trip";
  private static final String TEST_DATA2 = "Different Data";

  @Test
  void testRoundTrip() {
    Server server = new ServerImpl();
    Client alice = new ClientImpl("alice");
    Client bob = new ClientImpl("bob");
    ClientKey aliceKey = alice.generateClientKey(server);
    ClientKey bobKey = bob.generateClientKey(server);

    String aliceHash = alice.covertToIdentityKey(server, aliceKey, TEST_DATA);
    String bobHash = bob.covertToIdentityKey(server, bobKey, TEST_DATA);
    String aliceHash2 = alice.covertToIdentityKey(server, aliceKey, TEST_DATA2);
    String bobHash2 = bob.covertToIdentityKey(server, bobKey, TEST_DATA2);


    assertThat(aliceHash).isEqualTo(bobHash);
    assertThat(aliceHash2).isEqualTo(bobHash2);

    assertThat(aliceHash2).isNotEqualTo(bobHash);
  }

  @Test
  void testDifferentServersHaveDifferentResults() {
    Server server1 = new ServerImpl();
    Server server2 = new ServerImpl();
    Client alice = new ClientImpl("alice");
    ClientKey aliceKey1 = alice.generateClientKey(server1);
    ClientKey aliceKey2 = alice.generateClientKey(server2);

    String hash1 = alice.covertToIdentityKey(server1, aliceKey1, TEST_DATA);
    String hash2 = alice.covertToIdentityKey(server2, aliceKey2, TEST_DATA);

    assertThat(hash1).isNotEqualTo(hash2);
  }


}
