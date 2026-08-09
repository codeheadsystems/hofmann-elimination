package com.codeheadsystems.rfc.opaque.model;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.codeheadsystems.rfc.common.ClosedContextException;
import java.math.BigInteger;
import org.junit.jupiter.api.Test;

class ClientRegistrationStateTest {

  /**
   * Observed through a reference taken before the close, because {@code password()} refuses
   * afterwards. See {@link ClientAuthStateTest#close_zerosItsOwnCopy()}.
   */
  @Test
  void close_zerosItsOwnCopy() {
    byte[] password = {1, 2, 3};
    RegistrationRequest req = new RegistrationRequest(new byte[33]);
    ClientRegistrationState state = new ClientRegistrationState(BigInteger.ONE, password, req);
    byte[] statesOwnArray = state.password();

    state.close();

    assertThat(statesOwnArray).containsOnly((byte) 0);
  }

  /** See {@link ClientAuthStateTest#close_doesNotTouchTheCallersArray()} for why this matters. */
  @Test
  void close_doesNotTouchTheCallersArray() {
    byte[] password = {1, 2, 3};
    RegistrationRequest req = new RegistrationRequest(new byte[33]);
    ClientRegistrationState state = new ClientRegistrationState(BigInteger.ONE, password, req);

    state.close();

    assertThat(password).containsExactly(1, 2, 3);
  }

  @Test
  void mutatingTheCallersArrayAfterConstruction_doesNotAffectTheState() {
    byte[] password = {7, 7};
    RegistrationRequest req = new RegistrationRequest(new byte[33]);
    ClientRegistrationState state = new ClientRegistrationState(BigInteger.ONE, password, req);

    password[0] = 99;

    assertThat(state.password()).containsExactly(7, 7);
  }

  @Test
  void tryWithResources_zerosTheCopyOnExit() {
    byte[] password = {10, 20};
    RegistrationRequest req = new RegistrationRequest(new byte[33]);

    byte[] statesOwnArray;
    try (ClientRegistrationState state = new ClientRegistrationState(BigInteger.ONE, password, req)) {
      statesOwnArray = state.password();
      assertThat(statesOwnArray).containsExactly(10, 20);
    }

    assertThat(statesOwnArray).containsOnly((byte) 0);
    assertThat(password).containsExactly(10, 20);
  }

  /**
   * <strong>This is the guard that matters most in the library.</strong>
   *
   * <p>Registration has no envelope MAC to fail against, unlike authentication. Before this guard,
   * {@code finalizeRegistration} against a closed state derived {@code randomizedPwd} from a run of
   * zeroes, produced a complete and valid registration record, and the client uploaded it —
   * creating an account no password can ever open. {@code ClosedStateRefusalTest} reproduces that
   * end to end, including the part that shows it is a lockout rather than the publicly-known
   * credential it first looks like.
   */
  @Test
  void everyAccessorRefusesAfterClose() {
    RegistrationRequest req = new RegistrationRequest(new byte[33]);
    ClientRegistrationState state = new ClientRegistrationState(BigInteger.ONE, new byte[]{1}, req);
    state.close();

    assertThat(state.isClosed()).isTrue();
    assertThatThrownBy(state::password).isInstanceOf(ClosedContextException.class);
    assertThatThrownBy(state::blind).isInstanceOf(ClosedContextException.class);
    assertThatThrownBy(state::request).isInstanceOf(ClosedContextException.class);
  }

  @Test
  void closeIsIdempotent() {
    RegistrationRequest req = new RegistrationRequest(new byte[33]);
    ClientRegistrationState state = new ClientRegistrationState(BigInteger.ONE, new byte[]{1, 2}, req);
    byte[] statesOwnArray = state.password();

    state.close();
    state.close();

    assertThat(statesOwnArray).containsOnly((byte) 0);
  }

  /**
   * The generated {@code toString} printed {@code blind} in full decimal. Here both halves of the
   * verifier sat in the same object — the blind printed, the blinded element one field away in
   * {@code request} — so the disclosure needed no second source at all.
   */
  @Test
  void toStringDoesNotDiscloseTheBlind() {
    BigInteger blind = new BigInteger("31415926535897932384626433832795028841971");
    RegistrationRequest req = new RegistrationRequest(new byte[33]);
    ClientRegistrationState state = new ClientRegistrationState(blind, new byte[]{1}, req);

    assertThat(state.toString())
        .doesNotContain(blind.toString())
        .contains("<redacted>");
  }

  @Test
  void accessors_returnCorrectValues() {
    BigInteger blind = BigInteger.valueOf(7);
    byte[] password = {5};
    RegistrationRequest req = new RegistrationRequest(new byte[1]);
    ClientRegistrationState state = new ClientRegistrationState(blind, password, req);

    assertThat(state.blind()).isEqualTo(blind);
    assertThat(state.password()).isNotSameAs(password).containsExactly(5);
    assertThat(state.request()).isSameAs(req);
  }
}
