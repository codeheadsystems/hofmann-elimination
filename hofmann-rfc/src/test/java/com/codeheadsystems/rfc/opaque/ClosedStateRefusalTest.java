package com.codeheadsystems.rfc.opaque;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.codeheadsystems.rfc.common.ClosedContextException;
import com.codeheadsystems.rfc.opaque.config.OpaqueConfig;
import com.codeheadsystems.rfc.opaque.model.AuthResult;
import com.codeheadsystems.rfc.opaque.model.ClientAuthState;
import com.codeheadsystems.rfc.opaque.model.ClientRegistrationState;
import com.codeheadsystems.rfc.opaque.model.KE2;
import com.codeheadsystems.rfc.opaque.model.RegistrationRecord;
import com.codeheadsystems.rfc.opaque.model.RegistrationResponse;
import com.codeheadsystems.rfc.opaque.model.ServerKE2Result;
import com.codeheadsystems.rfc.opaque.testfixtures.OpaqueTestConfigs;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * A closed OPAQUE client state is refused, and the registration case is reproduced rather than
 * argued.
 *
 * <p>Authentication at least failed before the guard existed — the envelope MAC did not verify and
 * {@code recoverCredentials} threw. It threw {@code SecurityException("Authentication failed")}
 * though, which is what a wrong password throws, so the user was told their password was bad when
 * the fault was a lifetime bug in the caller. That distinguishability is asserted below.
 *
 * <p>Registration had no such check, which is why it was the worse case and why it is reproduced
 * here in full: nothing rejected an all-zero OPRF input, so a closed state produced a complete,
 * valid registration record that the client then uploaded.
 */
class ClosedStateRefusalTest {

  private static final byte[] CREDENTIAL_IDENTIFIER = "user@example.com".getBytes(StandardCharsets.UTF_8);
  private static final byte[] PASSWORD = "correct-password".getBytes(StandardCharsets.UTF_8);
  private static final OpaqueConfig CONFIG = OpaqueTestConfigs.forTesting();

  private Client client;
  private Server server;

  @BeforeEach
  void setUp() {
    client = new Client(CONFIG);
    server = Server.generate(CONFIG);
  }

  // ─── registration ───────────────────────────────────────────────────────────

  @Test
  void finalizeRegistrationRefusesAClosedState() {
    ClientRegistrationState state = client.createRegistrationRequest(PASSWORD);
    RegistrationResponse response =
        server.createRegistrationResponse(state.request(), CREDENTIAL_IDENTIFIER);
    state.close();

    assertThatThrownBy(() -> client.finalizeRegistration(state, response, null, null))
        .isInstanceOf(ClosedContextException.class)
        .hasMessageContaining("ClientRegistrationState");
  }

  /**
   * What used to happen, reconstructed — and what it actually cost, measured rather than assumed.
   *
   * <p>The guard makes the real sequence unreachable, so the state a closed one was in is rebuilt
   * by hand: the blind and the request as computed from the real password, because those are fixed
   * at request time and {@code close()} never touched them, paired with a zeroed password, because
   * that is what {@code finalizeRegistration} would have read.
   *
   * <p><strong>The record is produced. Nothing fails.</strong> That much was the finding, and it
   * holds: {@code OprfCipherSuite.finalize} hashes whatever input it is given with no all-zero
   * rejection, and {@code OpaqueEnvelope.store} never sees the password at all.
   *
   * <p><strong>But the account is not registered under the all-zero password, and a review draft
   * that said so was wrong.</strong> It reasoned that the credential became publicly known and the
   * account trivially takeable. It does not, because the two halves of the OPRF disagree: the
   * evaluated element the server returned was computed from {@code blind · H(realPassword)}, fixed
   * before the close, while {@code Finalize} consumed zeroes. The stored envelope is keyed by
   * {@code H(zeros || k · H(realPassword))}, and an ordinary login with any password {@code P}
   * produces {@code H(P || k · H(P))}. Matching those requires {@code P} to be both the all-zero
   * string and the real password at once.
   *
   * <p>So the account opens for <em>no password at all</em>: not the attacker's, not the legitimate
   * user's. A silent lockout written at registration time with no self-service way out —
   * {@code changePassword} needs a JWT from a successful {@code authenticate} — leaving only
   * out-of-band account recovery. And because {@code changePassword} runs this same code, a
   * rotation reports success and destroys the account. Serious, and worth the guard. Not an
   * authentication bypass.
   */
  @Test
  void aClosedStateUsedToRegisterAnAccountNobodyCanLogInTo() {
    ClientRegistrationState honest = client.createRegistrationRequest(PASSWORD);
    RegistrationResponse response =
        server.createRegistrationResponse(honest.request(), CREDENTIAL_IDENTIFIER);

    // Positive control first. Both load-bearing assertions below are "authentication throws", and
    // this test is the cited authority for a *corrected* severity claim — so a broken helper would
    // let it pass while proving a lockout that was not there. Register honestly through the same
    // path and confirm the helper can open an account before asserting that it cannot open this one.
    RegistrationRecord honestRecord = client.finalizeRegistration(
        new ClientRegistrationState(honest.blind(), PASSWORD, honest.request()),
        response, null, null);
    assertThatCode(() -> authenticate(honestRecord, PASSWORD))
        .as("control: the same helper opens an account registered honestly")
        .doesNotThrowAnyException();

    ClientRegistrationState asIfClosed = new ClientRegistrationState(
        honest.blind(), new byte[PASSWORD.length], honest.request());
    RegistrationRecord record = client.finalizeRegistration(asIfClosed, response, null, null);

    assertThat(record.envelope())
        .as("a complete registration record, differing from the honest one, with nothing "
            + "anywhere reporting a problem")
        .isNotEqualTo(honestRecord.envelope());

    assertThatThrownBy(() -> authenticate(record, PASSWORD))
        .as("the legitimate user is locked out of their own account")
        .isInstanceOf(SecurityException.class);

    assertThatThrownBy(() -> authenticate(record, new byte[PASSWORD.length]))
        .as("and the all-zero password does not open it either — the OPRF halves disagree, so "
            + "this is a lockout rather than a publicly known credential")
        .isInstanceOf(SecurityException.class);
  }

  // ─── authentication ─────────────────────────────────────────────────────────

  @Test
  void generateKE3RefusesAClosedState() {
    RegistrationRecord record = register(PASSWORD);
    ClientAuthState authState = client.generateKE1(PASSWORD);
    ServerKE2Result ke2Result =
        server.generateKE2(null, record, CREDENTIAL_IDENTIFIER, authState.ke1(), null);
    authState.close();

    assertThatThrownBy(() -> client.generateKE3(authState, null, null, ke2Result.ke2()))
        .isInstanceOf(ClosedContextException.class)
        .hasMessageContaining("ClientAuthState");
  }

  /**
   * The reason the OPAQUE half of this finding was worth fixing even though it already failed.
   *
   * <p>A closed state and a wrong password both ended at
   * {@code SecurityException("Authentication failed")}, so an application could not tell a bug in
   * its own lifetime handling from a user typing the wrong thing — and it reported the latter.
   */
  @Test
  void aClosedStateNoLongerLooksLikeAWrongPassword() {
    RegistrationRecord record = register(PASSWORD);

    ClientAuthState closed = client.generateKE1(PASSWORD);
    ServerKE2Result forClosed =
        server.generateKE2(null, record, CREDENTIAL_IDENTIFIER, closed.ke1(), null);
    closed.close();

    byte[] wrongPassword = "wrong-password".getBytes(StandardCharsets.UTF_8);
    ClientAuthState wrong = client.generateKE1(wrongPassword);
    ServerKE2Result forWrong =
        server.generateKE2(null, record, CREDENTIAL_IDENTIFIER, wrong.ke1(), null);

    assertThatThrownBy(() -> client.generateKE3(closed, null, null, forClosed.ke2()))
        .isInstanceOf(ClosedContextException.class);
    assertThatThrownBy(() -> client.generateKE3(wrong, null, null, forWrong.ke2()))
        .isInstanceOf(SecurityException.class)
        .isNotInstanceOf(ClosedContextException.class);
  }

  /**
   * The guard fires at {@code generateKE3}'s first read of the state — before
   * {@code recoverCredentials}, before the KSF stretch, before any server-supplied value is
   * consumed. That is what keeps it invisible to a remote party, and it is why the check belongs in
   * the accessor rather than anywhere downstream.
   */
  @Test
  void theRefusalHappensBeforeAnythingServerSuppliedIsTouched() {
    RegistrationRecord record = register(PASSWORD);
    ClientAuthState authState = client.generateKE1(PASSWORD);
    ServerKE2Result ke2Result =
        server.generateKE2(null, record, CREDENTIAL_IDENTIFIER, authState.ke1(), null);
    authState.close();

    // A KE2 that is structurally fine but cryptographically garbage. If the guard ran anywhere
    // downstream of the server's data, this would fail as a MAC or decode error instead.
    KE2 tampered = new KE2(ke2Result.ke2().credentialResponse(), ke2Result.ke2().serverNonce(),
        ke2Result.ke2().serverAkePublicKey(), new byte[ke2Result.ke2().serverMac().length]);

    assertThatThrownBy(() -> client.generateKE3(authState, null, null, tampered))
        .isInstanceOf(ClosedContextException.class);
  }

  // ─── AuthResult ─────────────────────────────────────────────────────────────

  /**
   * A closed result must not hand back an all-zero export key. It is a long-term client secret, so
   * a caller reading one back and using it as a key is the failure this prevents.
   *
   * <p>{@code ke3()} stays available on purpose: {@code close()} does not zero it, it is a MAC over
   * a public transcript that has already been sent, and refusing it would remove the one legitimate
   * post-close read on this type.
   */
  @Test
  void aClosedAuthResultRefusesItsKeysButStillYieldsKe3() {
    RegistrationRecord record = register(PASSWORD);
    AuthResult result = authenticate(record, PASSWORD);
    result.close();

    assertThatThrownBy(result::exportKey).isInstanceOf(ClosedContextException.class);
    assertThatThrownBy(result::sessionKey).isInstanceOf(ClosedContextException.class);
    assertThatCode(() -> assertThat(result.ke3().clientMac()).isNotNull())
        .doesNotThrowAnyException();
  }

  /**
   * The one thing the guard cannot fix, pinned so nobody mistakes it for something it does.
   *
   * <p>{@code AuthResult} does not copy on construction — the arrays are freshly derived and have
   * no other owner — so a caller who takes the export key before closing keeps a live reference
   * that {@code close()} zeroes under them. That is a different bug from use-after-close and it is
   * inherent to the type's contract. Copying on read would only trade it for an unerasable copy of
   * a long-term secret per access.
   */
  @Test
  void aReferenceTakenBeforeCloseIsStillZeroedUnderTheCaller() {
    RegistrationRecord record = register(PASSWORD);
    AuthResult result = authenticate(record, PASSWORD);

    byte[] takenEarly = result.exportKey();
    assertThat(takenEarly).isNotEqualTo(new byte[takenEarly.length]);

    result.close();

    assertThat(takenEarly)
        .as("documented, not guarded: take what you need before closing means take a copy")
        .containsOnly((byte) 0);
  }

  // ─── helpers ────────────────────────────────────────────────────────────────

  private RegistrationRecord register(byte[] password) {
    try (ClientRegistrationState state = client.createRegistrationRequest(password)) {
      RegistrationResponse response =
          server.createRegistrationResponse(state.request(), CREDENTIAL_IDENTIFIER);
      return client.finalizeRegistration(state, response, null, null);
    }
  }

  private AuthResult authenticate(RegistrationRecord record, byte[] password) {
    try (ClientAuthState authState = client.generateKE1(password)) {
      ServerKE2Result ke2Result =
          server.generateKE2(null, record, CREDENTIAL_IDENTIFIER, authState.ke1(), null);
      return client.generateKE3(authState, null, null, ke2Result.ke2());
    }
  }
}
