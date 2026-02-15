package com.codeheadsystems.opaque;

import static org.assertj.core.api.Assertions.assertThat;

import com.codeheadsystems.opaque.config.OpaqueConfig;
import com.codeheadsystems.opaque.internal.OpaqueCredentials;
import com.codeheadsystems.opaque.model.AuthResult;
import com.codeheadsystems.opaque.model.ClientAuthState;
import com.codeheadsystems.opaque.model.ClientRegistrationState;
import com.codeheadsystems.opaque.model.CredentialRequest;
import com.codeheadsystems.opaque.model.KE1;
import com.codeheadsystems.opaque.model.KE2;
import com.codeheadsystems.opaque.model.RegistrationRecord;
import com.codeheadsystems.opaque.model.RegistrationResponse;
import java.math.BigInteger;
import java.util.Arrays;
import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.Test;

/**
 * Tests against CFRG OPAQUE reference test vectors (P256-SHA256, Identity KSF).
 * Source: https://github.com/cfrg/draft-irtf-cfrg-opaque
 * <p>
 * Vector 1: No explicit identities (identities default to public keys)
 * Vector 2: With explicit identities (client_identity = "alice", server_identity = "bob")
 */
class OpaqueVectorsTest {

  // ─── Shared inputs across both vectors ────────────────────────────────────

  private static final byte[] PASSWORD = hex("436f7272656374486f72736542617474657279537461706c65"); // "CorrectHorseBatteryStaple"
  private static final byte[] CREDENTIAL_IDENTIFIER = hex("31323334"); // "1234"
  private static final byte[] OPRF_SEED = hex("62f60b286d20ce4fd1d64809b0021dad6ed5d52a2c8cf27ae6582543a0a8dce2");
  private static final byte[] SERVER_PRIVATE_KEY = hex("c36139381df63bfc91c850db0b9cfbec7a62e86d80040a41aa7725bf0e79d5e5");
  private static final byte[] SERVER_PUBLIC_KEY = hex("035f40ff9cf88aa1f5cd4fe5fd3da9ea65a4923a5594f84fd9f2092d6067784874");

  // Registration inputs
  private static final BigInteger BLIND_REGISTRATION = new BigInteger(1, hex("411bf1a62d119afe30df682b91a0a33d777972d4f2daa4b34ca527d597078153"));
  private static final byte[] ENVELOPE_NONCE = hex("a921f2a014513bd8a90e477a629794e89fec12d12206dde662ebdcf65670e51f");

  // Authentication inputs
  private static final BigInteger BLIND_LOGIN = new BigInteger(1, hex("c497fddf6056d241e6cf9fb7ac37c384f49b357a221eb0a802c989b9942256c1"));
  private static final byte[] CLIENT_NONCE = hex("ab3d33bde0e93eda72392346a7a73051110674bbf6b1b7ffab8be4f91fdaeeb1");
  private static final byte[] CLIENT_KEYSHARE_SEED = hex("633b875d74d1556d2a2789309972b06db21dfcc4f5ad51d7e74d783b7cfab8dc");
  private static final byte[] MASKING_NONCE = hex("38fe59af0df2c79f57b8780278f5ae47355fe1f817119041951c80f612fdfc6d");
  private static final byte[] SERVER_NONCE = hex("71cd9960ecef2fe0d0f7494986fa3d8b2bb01963537e60efb13981e138e3d4a1");
  private static final byte[] SERVER_KEYSHARE_SEED = hex("05a4f54206eef1ba2f615bc0aa285cb22f26d1153b5b40a1e85ff80da12f982f");

  // Expected outputs for Vector 1 (no identities)
  private static final byte[] EXPECTED_REGISTRATION_REQUEST = hex("029e949a29cfa0bf7c1287333d2fb3dc586c41aa652f5070d26a5315a1b50229f8");
  private static final byte[] EXPECTED_REGISTRATION_RESPONSE = hex("0350d3694c00978f00a5ce7cd08a00547e4ab5fb5fc2b2f6717cdaa6c89136efef035f40ff9cf88aa1f5cd4fe5fd3da9ea65a4923a5594f84fd9f2092d6067784874");
  private static final byte[] EXPECTED_REGISTRATION_UPLOAD = hex("03b218507d978c3db570ca994aaf36695a731ddb2db272c817f79746fc37ae52147f0ed53532d3ae8e505ecc70d42d2b814b6b0e48156def71ea029148b2803aafa921f2a014513bd8a90e477a629794e89fec12d12206dde662ebdcf65670e51fad30bbcfc1f8eda0211553ab9aaf26345ad59a128e80188f035fe4924fad67b8");
  private static final byte[] EXPECTED_KE1 = hex("037342f0bcb3ecea754c1e67576c86aa90c1de3875f390ad599a26686cdfee6e07ab3d33bde0e93eda72392346a7a73051110674bbf6b1b7ffab8be4f91fdaeeb1022ed3f32f318f81bab80da321fecab3cd9b6eea11a95666dfa6beeaab321280b6");
  private static final byte[] EXPECTED_KE2 = hex("0246da9fe4d41d5ba69faa6c509a1d5bafd49a48615a47a8dd4b0823cc1476481138fe59af0df2c79f57b8780278f5ae47355fe1f817119041951c80f612fdfc6d2f0c547f70deaeca54d878c14c1aa5e1ab405dec833777132eea905c2fbb12504a67dcbe0e66740c76b62c13b04a38a77926e19072953319ec65e41f9bfd2ae26837b6ce688bf9af2542f04eec9ab96a1b9328812dc2f5c89182ed47fead61f09f71cd9960ecef2fe0d0f7494986fa3d8b2bb01963537e60efb13981e138e3d4a103c1701353219b53acf337bf6456a83cefed8f563f1040b65afbf3b65d3bc9a19b50a73b145bc87a157e8c58c0342e2047ee22ae37b63db17e0a82a30fcc4ecf7b");
  private static final byte[] EXPECTED_KE3 = hex("e97cab4433aa39d598e76f13e768bba61c682947bdcf9936035e8a3a3ebfb66e");
  private static final byte[] EXPECTED_SESSION_KEY = hex("484ad345715ccce138ca49e4ea362c6183f0949aaaa1125dc3bc3f80876e7cd1");
  private static final byte[] EXPECTED_EXPORT_KEY = hex("c3c9a1b0e33ac84dd83d0b7e8af6794e17e7a3caadff289fbd9dc769a853c64b");

  // Expected outputs for Vector 2 (with identities)
  private static final byte[] CLIENT_IDENTITY = hex("616c696365"); // "alice"
  private static final byte[] SERVER_IDENTITY = hex("626f62");     // "bob"
  private static final byte[] EXPECTED_REGISTRATION_UPLOAD_V2 = hex("03b218507d978c3db570ca994aaf36695a731ddb2db272c817f79746fc37ae52147f0ed53532d3ae8e505ecc70d42d2b814b6b0e48156def71ea029148b2803aafa921f2a014513bd8a90e477a629794e89fec12d12206dde662ebdcf65670e51f4d7773a36a208a866301dbb2858e40dc5638017527cf91aef32d3848eebe0971");
  private static final byte[] EXPECTED_KE2_V2 = hex("0246da9fe4d41d5ba69faa6c509a1d5bafd49a48615a47a8dd4b0823cc1476481138fe59af0df2c79f57b8780278f5ae47355fe1f817119041951c80f612fdfc6d2f0c547f70deaeca54d878c14c1aa5e1ab405dec833777132eea905c2fbb12504a67dcbe0e66740c76b62c13b04a38a77926e19072953319ec65e41f9bfd2ae268d7f106042021c80300e4c6f585980cf39fc51a4a6bba41b0729f9b240c729e5671cd9960ecef2fe0d0f7494986fa3d8b2bb01963537e60efb13981e138e3d4a103c1701353219b53acf337bf6456a83cefed8f563f1040b65afbf3b65d3bc9a19b84922c7e5d074838a8f278592c53f61fb59f031e85ad480c0c71086b871e1b24");
  private static final byte[] EXPECTED_KE3_V2 = hex("46833578cee137775f6be3f01b80748daac5a694101ad0e9e7025480552da56a");
  private static final byte[] EXPECTED_SESSION_KEY_V2 = hex("27766fabd8dd88ff37fbd0ef1a491e601d10d9f016c2b28c4bd1b0fb7511a3c3");
  private static final byte[] EXPECTED_EXPORT_KEY_V2 = hex("c3c9a1b0e33ac84dd83d0b7e8af6794e17e7a3caadff289fbd9dc769a853c64b");

  // Expected intermediate values for Vector 1
  private static final byte[] EXPECTED_RANDOMIZED_PWD = hex("06be0a1a51d56557a3adad57ba29c5510565dcd8b5078fa319151b9382258fb0");

  private static final OpaqueConfig CONFIG = OpaqueConfig.forTesting();

  // ─── Vector 1: No explicit identities ─────────────────────────────────────
  private static final byte[] V3_SERVER_PRIVATE_KEY = hex("34fbe7e830be1fe8d2187c97414e3826040cbe49b893b64229bab5e85a5888c7");
  private static final byte[] V3_SERVER_PUBLIC_KEY = hex("0221e034c0e202fe883dcfc96802a7624166fed4cfcab4ae30cf5f3290d01c88bf");
  private static final byte[] V3_OPRF_SEED = hex("bb1cd59e16ac09bc0cb6d528541695d7eba2239b1613a3db3ade77b36280f725");
  private static final byte[] V3_CREDENTIAL_ID = hex("31323334");
  private static final byte[] V3_CLIENT_IDENTITY = hex("616c696365"); // "alice"
  private static final byte[] V3_SERVER_IDENTITY = hex("626f62");     // "bob"
  private static final byte[] V3_FAKE_CLIENT_PK = hex("03b81708eae026a9370616c22e1e8542fe9dbebd36ce8a2661b708e9628f4a57fc");
  private static final byte[] V3_FAKE_MASKING_KEY = hex("caecc6ccb4cae27cb54d8f3a1af1bac52a3d53107ce08497cdd362b1992e4e5e");
  private static final byte[] V3_MASKING_NONCE = hex("9c035896a043e70f897d87180c543e7a063b83c1bb728fbd189c619e27b6e5a6");

  // ─── Vector 2: With explicit identities ───────────────────────────────────
  private static final byte[] V3_SERVER_NONCE = hex("1e10f6eeab2a7a420bf09da9b27a4639645622c46358de9cf7ae813055ae2d12");
  private static final byte[] V3_SERVER_KEYSHARE_SEED = hex("360b0937f47d45f6123a4d8f0d0c0814b6120d840ebb8bc5b4f6b62df07f78c2");
  private static final byte[] V3_KE1 = hex("0396875da2b4f7749bba411513aea02dc514a48d169d8a9531bd61d3af3fa9baae42d4e61ed3f8d64cdd3b9d153343eca15b9b0d5e388232793c6376bd2d9cfd0a02147a6583983cc9973b5082db5f5070890cb373d70f7ac1b41ed2305361009784");

  // ─── Helpers ──────────────────────────────────────────────────────────────
  private static final byte[] V3_EXPECTED_KE2 = hex("0201198dcd13f9792eb75dcfa815f61b049abfe2e3e9456d4bbbceec5f442efd049c035896a043e70f897d87180c543e7a063b83c1bb728fbd189c619e27b6e5a6facda65ce0a97b9085e7af07f61fd3fdd046d257cbf2183ce8766090b8041a8bf28d79dd4c9031ddc75bb6ddb4c291e639937840e3d39fc0d5a3d6e7723c09f7945df485bcf9aefe3fe82d149e84049e259bb5b33d6a2ff3b25e4bfb7eff0962821e10f6eeab2a7a420bf09da9b27a4639645622c46358de9cf7ae813055ae2d12023f82bbb24e75b8683fd13b843cd566efae996cd0016cffdcc24ee2bc937d026f80144878749a69565b433c1040aff67e94f79345de888a877422b9bbe21ec329");

  private static byte[] hex(String s) {
    return Hex.decode(s);
  }

  // ─── Vector 3: Fake KE2 (unregistered user, Fake=True) ────────────────────
  // Tests RFC 9807 §7.1.2 user-enumeration protection.
  // The fake vector uses a different server key pair and oprf_seed than vectors 1 and 2.

  private static byte[] concat(byte[]... parts) {
    int total = 0;
    for (byte[] p : parts) total += p.length;
    byte[] out = new byte[total];
    int off = 0;
    for (byte[] p : parts) {
      System.arraycopy(p, 0, out, off, p.length);
      off += p.length;
    }
    return out;
  }

  /**
   * Deserializes a KE1 from its 98-byte wire format (blindedElement || clientNonce || clientAkePk).
   */
  private static KE1 parseKE1(byte[] bytes) {
    byte[] blindedElement = Arrays.copyOfRange(bytes, 0, 33);
    byte[] clientNonce = Arrays.copyOfRange(bytes, 33, 65);
    byte[] clientAkePk = Arrays.copyOfRange(bytes, 65, 98);
    return new KE1(new CredentialRequest(blindedElement), clientNonce, clientAkePk);
  }

  /**
   * Serialize KE2: credentialResponse || serverNonce || serverAkePk || serverMac
   */
  private static byte[] concatKE2(KE2 ke2) {
    return concat(
        ke2.serializeCredentialResponse(),
        ke2.serverNonce(),
        ke2.serverAkePublicKey(),
        ke2.serverMac()
    );
  }

  @Test
  void vector1_registrationRequest() {
    OpaqueClient client = new OpaqueClient(CONFIG);
    ClientRegistrationState state = client.createRegistrationRequestDeterministic(PASSWORD, BLIND_REGISTRATION);
    assertThat(state.request().blindedElement()).isEqualTo(EXPECTED_REGISTRATION_REQUEST);
  }

  @Test
  void vector1_registrationResponse() {
    OpaqueServer server = new OpaqueServer(SERVER_PRIVATE_KEY, SERVER_PUBLIC_KEY, OPRF_SEED, CONFIG);
    // Build the expected registration request first
    OpaqueClient client = new OpaqueClient(CONFIG);
    ClientRegistrationState state = client.createRegistrationRequestDeterministic(PASSWORD, BLIND_REGISTRATION);

    RegistrationResponse response = server.createRegistrationResponse(state.request(), CREDENTIAL_IDENTIFIER);

    // registration_response = evaluatedElement || serverPublicKey
    byte[] expected = concat(response.evaluatedElement(), response.serverPublicKey());
    assertThat(expected).isEqualTo(EXPECTED_REGISTRATION_RESPONSE);
  }

  @Test
  void vector1_registrationUpload() {
    OpaqueClient client = new OpaqueClient(CONFIG);
    OpaqueServer server = new OpaqueServer(SERVER_PRIVATE_KEY, SERVER_PUBLIC_KEY, OPRF_SEED, CONFIG);

    ClientRegistrationState regState = client.createRegistrationRequestDeterministic(PASSWORD, BLIND_REGISTRATION);
    RegistrationResponse response = server.createRegistrationResponse(regState.request(), CREDENTIAL_IDENTIFIER);
    RegistrationRecord record = client.finalizeRegistrationDeterministic(
        regState, response, null, null, ENVELOPE_NONCE);

    // registration_upload = clientPublicKey || maskingKey || envelope_nonce || auth_tag
    byte[] actual = concat(record.clientPublicKey(), record.maskingKey(), record.envelope().serialize());
    assertThat(actual).isEqualTo(EXPECTED_REGISTRATION_UPLOAD);
  }

  @Test
  void vector1_ke1() {
    OpaqueClient client = new OpaqueClient(CONFIG);
    ClientAuthState authState = client.generateKE1Deterministic(
        PASSWORD, BLIND_LOGIN, CLIENT_NONCE, CLIENT_KEYSHARE_SEED);
    assertThat(authState.ke1().serialize()).isEqualTo(EXPECTED_KE1);
  }

  @Test
  void vector1_randomizedPassword() {
    // Verifies the critical intermediate value that all envelope and key material flows from.
    OpaqueClient client = new OpaqueClient(CONFIG);
    OpaqueServer server = new OpaqueServer(SERVER_PRIVATE_KEY, SERVER_PUBLIC_KEY, OPRF_SEED, CONFIG);

    ClientRegistrationState regState = client.createRegistrationRequestDeterministic(PASSWORD, BLIND_REGISTRATION);
    RegistrationResponse response = server.createRegistrationResponse(regState.request(), CREDENTIAL_IDENTIFIER);

    byte[] randomizedPwd = OpaqueCredentials.deriveRandomizedPwd(
        PASSWORD, BLIND_REGISTRATION, response.evaluatedElement(), CONFIG);
    assertThat(randomizedPwd).isEqualTo(EXPECTED_RANDOMIZED_PWD);
  }

  @Test
  void vector1_ke2() {
    OpaqueClient client = new OpaqueClient(CONFIG);
    OpaqueServer server = new OpaqueServer(SERVER_PRIVATE_KEY, SERVER_PUBLIC_KEY, OPRF_SEED, CONFIG);

    // Registration
    ClientRegistrationState regState = client.createRegistrationRequestDeterministic(PASSWORD, BLIND_REGISTRATION);
    RegistrationResponse response = server.createRegistrationResponse(regState.request(), CREDENTIAL_IDENTIFIER);
    RegistrationRecord record = client.finalizeRegistrationDeterministic(
        regState, response, null, null, ENVELOPE_NONCE);

    // Auth: KE1
    ClientAuthState authState = client.generateKE1Deterministic(
        PASSWORD, BLIND_LOGIN, CLIENT_NONCE, CLIENT_KEYSHARE_SEED);

    // Auth: KE2
    Object[] ke2Result = server.generateKE2Deterministic(
        null, record, CREDENTIAL_IDENTIFIER, authState.ke1(),
        null, MASKING_NONCE, SERVER_KEYSHARE_SEED, SERVER_NONCE);
    KE2 ke2 = (KE2) ke2Result[1];

    // Serialize KE2: credentialResponse || serverNonce || serverAkePk || serverMac
    byte[] actual = concatKE2(ke2);
    assertThat(actual).isEqualTo(EXPECTED_KE2);
  }

  @Test
  void vector1_ke3_and_sessionKey() {
    OpaqueClient client = new OpaqueClient(CONFIG);
    OpaqueServer server = new OpaqueServer(SERVER_PRIVATE_KEY, SERVER_PUBLIC_KEY, OPRF_SEED, CONFIG);

    // Registration
    ClientRegistrationState regState = client.createRegistrationRequestDeterministic(PASSWORD, BLIND_REGISTRATION);
    RegistrationResponse response = server.createRegistrationResponse(regState.request(), CREDENTIAL_IDENTIFIER);
    RegistrationRecord record = client.finalizeRegistrationDeterministic(
        regState, response, null, null, ENVELOPE_NONCE);

    // Auth
    ClientAuthState authState = client.generateKE1Deterministic(
        PASSWORD, BLIND_LOGIN, CLIENT_NONCE, CLIENT_KEYSHARE_SEED);
    Object[] ke2Result = server.generateKE2Deterministic(
        null, record, CREDENTIAL_IDENTIFIER, authState.ke1(),
        null, MASKING_NONCE, SERVER_KEYSHARE_SEED, SERVER_NONCE);
    KE2 ke2 = (KE2) ke2Result[1];

    AuthResult authResult = client.generateKE3(authState, null, null, ke2);
    assertThat(authResult.ke3().clientMac()).isEqualTo(EXPECTED_KE3);
    assertThat(authResult.sessionKey()).isEqualTo(EXPECTED_SESSION_KEY);
    assertThat(authResult.exportKey()).isEqualTo(EXPECTED_EXPORT_KEY);
  }

  @Test
  void vector1_serverFinishVerifiesSessionKey() {
    OpaqueClient client = new OpaqueClient(CONFIG);
    OpaqueServer server = new OpaqueServer(SERVER_PRIVATE_KEY, SERVER_PUBLIC_KEY, OPRF_SEED, CONFIG);

    ClientRegistrationState regState = client.createRegistrationRequestDeterministic(PASSWORD, BLIND_REGISTRATION);
    RegistrationResponse response = server.createRegistrationResponse(regState.request(), CREDENTIAL_IDENTIFIER);
    RegistrationRecord record = client.finalizeRegistrationDeterministic(
        regState, response, null, null, ENVELOPE_NONCE);

    ClientAuthState authState = client.generateKE1Deterministic(
        PASSWORD, BLIND_LOGIN, CLIENT_NONCE, CLIENT_KEYSHARE_SEED);
    Object[] ke2Result = server.generateKE2Deterministic(
        null, record, CREDENTIAL_IDENTIFIER, authState.ke1(),
        null, MASKING_NONCE, SERVER_KEYSHARE_SEED, SERVER_NONCE);
    KE2 ke2 = (KE2) ke2Result[1];
    com.codeheadsystems.opaque.model.ServerAuthState serverAuthState =
        (com.codeheadsystems.opaque.model.ServerAuthState) ke2Result[0];

    AuthResult authResult = client.generateKE3(authState, null, null, ke2);
    byte[] serverSessionKey = server.serverFinish(serverAuthState, authResult.ke3());
    assertThat(serverSessionKey).isEqualTo(EXPECTED_SESSION_KEY);
    assertThat(authResult.sessionKey()).isEqualTo(EXPECTED_SESSION_KEY);
  }

  @Test
  void vector2_registrationUpload() {
    OpaqueClient client = new OpaqueClient(CONFIG);
    OpaqueServer server = new OpaqueServer(SERVER_PRIVATE_KEY, SERVER_PUBLIC_KEY, OPRF_SEED, CONFIG);

    ClientRegistrationState regState = client.createRegistrationRequestDeterministic(PASSWORD, BLIND_REGISTRATION);
    RegistrationResponse response = server.createRegistrationResponse(regState.request(), CREDENTIAL_IDENTIFIER);
    RegistrationRecord record = client.finalizeRegistrationDeterministic(
        regState, response, SERVER_IDENTITY, CLIENT_IDENTITY, ENVELOPE_NONCE);

    byte[] actual = concat(record.clientPublicKey(), record.maskingKey(), record.envelope().serialize());
    assertThat(actual).isEqualTo(EXPECTED_REGISTRATION_UPLOAD_V2);
  }

  @Test
  void vector2_ke3_and_sessionKey() {
    OpaqueClient client = new OpaqueClient(CONFIG);
    OpaqueServer server = new OpaqueServer(SERVER_PRIVATE_KEY, SERVER_PUBLIC_KEY, OPRF_SEED, CONFIG);

    // Registration with identities
    ClientRegistrationState regState = client.createRegistrationRequestDeterministic(PASSWORD, BLIND_REGISTRATION);
    RegistrationResponse response = server.createRegistrationResponse(regState.request(), CREDENTIAL_IDENTIFIER);
    RegistrationRecord record = client.finalizeRegistrationDeterministic(
        regState, response, SERVER_IDENTITY, CLIENT_IDENTITY, ENVELOPE_NONCE);

    // Auth
    ClientAuthState authState = client.generateKE1Deterministic(
        PASSWORD, BLIND_LOGIN, CLIENT_NONCE, CLIENT_KEYSHARE_SEED);
    Object[] ke2Result = server.generateKE2Deterministic(
        SERVER_IDENTITY, record, CREDENTIAL_IDENTIFIER, authState.ke1(),
        CLIENT_IDENTITY, MASKING_NONCE, SERVER_KEYSHARE_SEED, SERVER_NONCE);
    KE2 ke2 = (KE2) ke2Result[1];

    byte[] actualKe2 = concatKE2(ke2);
    assertThat(actualKe2).isEqualTo(EXPECTED_KE2_V2);

    AuthResult authResult = client.generateKE3(authState, CLIENT_IDENTITY, SERVER_IDENTITY, ke2);
    assertThat(authResult.ke3().clientMac()).isEqualTo(EXPECTED_KE3_V2);
    assertThat(authResult.sessionKey()).isEqualTo(EXPECTED_SESSION_KEY_V2);
    assertThat(authResult.exportKey()).isEqualTo(EXPECTED_EXPORT_KEY_V2);
  }

  @Test
  void vector3_fakeKE2() {
    OpaqueServer server = new OpaqueServer(V3_SERVER_PRIVATE_KEY, V3_SERVER_PUBLIC_KEY, V3_OPRF_SEED, CONFIG);
    KE1 ke1 = parseKE1(V3_KE1);

    Object[] ke2Result = server.generateFakeKE2Deterministic(ke1, V3_CREDENTIAL_ID,
        V3_SERVER_IDENTITY, V3_CLIENT_IDENTITY,
        V3_FAKE_CLIENT_PK, V3_FAKE_MASKING_KEY,
        V3_MASKING_NONCE, V3_SERVER_KEYSHARE_SEED, V3_SERVER_NONCE);
    KE2 ke2 = (KE2) ke2Result[1];

    assertThat(concatKE2(ke2)).isEqualTo(V3_EXPECTED_KE2);
  }

  @Test
  void vector2_serverFinishVerifiesSessionKey() {
    OpaqueClient client = new OpaqueClient(CONFIG);
    OpaqueServer server = new OpaqueServer(SERVER_PRIVATE_KEY, SERVER_PUBLIC_KEY, OPRF_SEED, CONFIG);

    ClientRegistrationState regState = client.createRegistrationRequestDeterministic(PASSWORD, BLIND_REGISTRATION);
    RegistrationResponse response = server.createRegistrationResponse(regState.request(), CREDENTIAL_IDENTIFIER);
    RegistrationRecord record = client.finalizeRegistrationDeterministic(
        regState, response, SERVER_IDENTITY, CLIENT_IDENTITY, ENVELOPE_NONCE);

    ClientAuthState authState = client.generateKE1Deterministic(
        PASSWORD, BLIND_LOGIN, CLIENT_NONCE, CLIENT_KEYSHARE_SEED);
    Object[] ke2Result = server.generateKE2Deterministic(
        SERVER_IDENTITY, record, CREDENTIAL_IDENTIFIER, authState.ke1(),
        CLIENT_IDENTITY, MASKING_NONCE, SERVER_KEYSHARE_SEED, SERVER_NONCE);
    KE2 ke2 = (KE2) ke2Result[1];
    com.codeheadsystems.opaque.model.ServerAuthState serverAuthState =
        (com.codeheadsystems.opaque.model.ServerAuthState) ke2Result[0];

    AuthResult authResult = client.generateKE3(authState, CLIENT_IDENTITY, SERVER_IDENTITY, ke2);
    byte[] serverSessionKey = server.serverFinish(serverAuthState, authResult.ke3());
    assertThat(serverSessionKey).isEqualTo(EXPECTED_SESSION_KEY_V2);
  }
}
