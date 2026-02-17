package com.codeheadsystems.opaque.model;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

/**
 * Unit tests for {@link CleartextCredentials}.
 */
class CleartextCredentialsTest {

  private static final byte[] SERVER_PK = {0x01, 0x02, 0x03};
  private static final byte[] CLIENT_PK = {0x04, 0x05};
  private static final byte[] SERVER_ID = {0x0A, 0x0B};
  private static final byte[] CLIENT_ID = {0x0C};

  // ── create() identity defaulting ────────────────────────────────────────

  @Test
  void createBothIdentitiesNull_defaultsToPublicKeys() {
    CleartextCredentials cc = CleartextCredentials.create(SERVER_PK, CLIENT_PK, null, null);
    assertThat(cc.serverIdentity()).isEqualTo(SERVER_PK);
    assertThat(cc.clientIdentity()).isEqualTo(CLIENT_PK);
    assertThat(cc.serverPublicKey()).isEqualTo(SERVER_PK);
  }

  @Test
  void createBothIdentitiesProvided_usesIdentities() {
    CleartextCredentials cc = CleartextCredentials.create(SERVER_PK, CLIENT_PK, SERVER_ID, CLIENT_ID);
    assertThat(cc.serverIdentity()).isEqualTo(SERVER_ID);
    assertThat(cc.clientIdentity()).isEqualTo(CLIENT_ID);
    assertThat(cc.serverPublicKey()).isEqualTo(SERVER_PK);
  }

  @Test
  void createServerIdentityNull_defaultsServerToPublicKey() {
    CleartextCredentials cc = CleartextCredentials.create(SERVER_PK, CLIENT_PK, null, CLIENT_ID);
    assertThat(cc.serverIdentity()).isEqualTo(SERVER_PK);
    assertThat(cc.clientIdentity()).isEqualTo(CLIENT_ID);
  }

  @Test
  void createClientIdentityNull_defaultsClientToPublicKey() {
    CleartextCredentials cc = CleartextCredentials.create(SERVER_PK, CLIENT_PK, SERVER_ID, null);
    assertThat(cc.serverIdentity()).isEqualTo(SERVER_ID);
    assertThat(cc.clientIdentity()).isEqualTo(CLIENT_PK);
  }

  // ── serialize() wire format ──────────────────────────────────────────────

  @Test
  void serializeProducesCorrectWireFormat() {
    // Format: serverPublicKey || I2OSP(len(serverIdentity),2) || serverIdentity
    //      || I2OSP(len(clientIdentity),2) || clientIdentity
    //
    // SERVER_PK = [01 02 03], SERVER_ID = [0A 0B], CLIENT_ID = [0C]
    // Expected: [01 02 03] [00 02] [0A 0B] [00 01] [0C]
    CleartextCredentials cc = new CleartextCredentials(SERVER_PK, SERVER_ID, CLIENT_ID);

    byte[] wire = cc.serialize();

    int off = 0;
    // serverPublicKey
    assertThat(wire).containsSequence((byte) 0x01, (byte) 0x02, (byte) 0x03);
    off += SERVER_PK.length;
    // I2OSP(2, 2) = [00 02]
    assertThat(wire[off]).isEqualTo((byte) 0x00);
    assertThat(wire[off + 1]).isEqualTo((byte) 0x02);
    off += 2;
    // serverIdentity = [0A 0B]
    assertThat(wire[off]).isEqualTo((byte) 0x0A);
    assertThat(wire[off + 1]).isEqualTo((byte) 0x0B);
    off += SERVER_ID.length;
    // I2OSP(1, 2) = [00 01]
    assertThat(wire[off]).isEqualTo((byte) 0x00);
    assertThat(wire[off + 1]).isEqualTo((byte) 0x01);
    off += 2;
    // clientIdentity = [0C]
    assertThat(wire[off]).isEqualTo((byte) 0x0C);

    int expectedLength = SERVER_PK.length + 2 + SERVER_ID.length + 2 + CLIENT_ID.length;
    assertThat(wire).hasSize(expectedLength);
  }

  @Test
  void serializeWithEmptyIdentitiesProducesTwoZeroLengthFields() {
    byte[] emptyId = new byte[0];
    CleartextCredentials cc = new CleartextCredentials(SERVER_PK, emptyId, emptyId);

    byte[] wire = cc.serialize();

    // [01 02 03] [00 00] [00 00]
    assertThat(wire).hasSize(SERVER_PK.length + 2 + 2);
    assertThat(wire[SERVER_PK.length]).isEqualTo((byte) 0x00);
    assertThat(wire[SERVER_PK.length + 1]).isEqualTo((byte) 0x00);
    assertThat(wire[SERVER_PK.length + 2]).isEqualTo((byte) 0x00);
    assertThat(wire[SERVER_PK.length + 3]).isEqualTo((byte) 0x00);
  }

  @Test
  void differentInputsProduceDifferentSerializations() {
    CleartextCredentials cc1 = new CleartextCredentials(SERVER_PK, SERVER_ID, CLIENT_ID);
    CleartextCredentials cc2 = new CleartextCredentials(SERVER_PK, CLIENT_ID, SERVER_ID);

    assertThat(cc1.serialize()).isNotEqualTo(cc2.serialize());
  }
}
