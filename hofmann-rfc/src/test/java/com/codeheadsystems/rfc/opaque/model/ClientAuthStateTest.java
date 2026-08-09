package com.codeheadsystems.rfc.opaque.model;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.codeheadsystems.rfc.common.ClosedContextException;
import java.math.BigInteger;
import org.junit.jupiter.api.Test;

class ClientAuthStateTest {

  private static KE1 ke1() {
    return new KE1(new CredentialRequest(new byte[33]), new byte[32], new byte[33]);
  }

  /**
   * The zeroing is observed through a reference taken <em>before</em> the close, because
   * {@code password()} refuses to answer afterwards. That is not a workaround for the guard — it
   * is the only honest way to assert the zeroing now, and it also pins the aliasing contract:
   * {@code password()} hands out the state's own array rather than a copy, so the reference the
   * test holds is the one {@code close()} clears.
   */
  @Test
  void close_zerosItsOwnCopy() {
    byte[] password = {1, 2, 3, 4, 5};
    ClientAuthState state = new ClientAuthState(BigInteger.ONE, password, ke1(), BigInteger.TEN);
    byte[] statesOwnArray = state.password();

    state.close();

    assertThat(statesOwnArray).containsOnly((byte) 0);
  }

  /**
   * The behaviour that makes the {@link AutoCloseable} usable at all.
   *
   * <p>These previously asserted the opposite — that {@code close()} zeroed the caller's array —
   * and that is exactly why nothing in {@code src/main} could call it: {@code authenticate()}
   * hands the same password to {@code changePassword} afterwards on the key-rotation path, so
   * closing would have destroyed a live buffer. The copy is what lets the callers close.
   */
  @Test
  void close_doesNotTouchTheCallersArray() {
    byte[] password = {1, 2, 3, 4, 5};
    ClientAuthState state = new ClientAuthState(BigInteger.ONE, password, ke1(), BigInteger.TEN);

    state.close();

    assertThat(password).containsExactly(1, 2, 3, 4, 5);
  }

  @Test
  void mutatingTheCallersArrayAfterConstruction_doesNotAffectTheState() {
    byte[] password = {7, 7, 7};
    ClientAuthState state = new ClientAuthState(BigInteger.ONE, password, ke1(), BigInteger.TEN);

    password[0] = 99;

    // The copy is taken at construction, so the blind already computed from the original bytes
    // stays consistent with what the state reports.
    assertThat(state.password()).containsExactly(7, 7, 7);
  }

  @Test
  void tryWithResources_zerosTheCopyOnExit() {
    byte[] password = {10, 20, 30};

    byte[] statesOwnArray;
    try (ClientAuthState state = new ClientAuthState(BigInteger.ONE, password, ke1(), BigInteger.TEN)) {
      statesOwnArray = state.password();
      assertThat(statesOwnArray).containsExactly(10, 20, 30);
    }

    assertThat(statesOwnArray).containsOnly((byte) 0);
    assertThat(password).containsExactly(10, 20, 30);
  }

  /**
   * Every accessor refuses after close, not merely {@code password()}.
   *
   * <p>The narrow version — guard only the field that gets zeroed — would leave {@code ke1()} and
   * {@code blind()} answering normally, and those are what a caller reaches for when reconstructing
   * a request. A closed state is not a state missing one field.
   */
  @Test
  void everyAccessorRefusesAfterClose() {
    ClientAuthState state = new ClientAuthState(BigInteger.ONE, new byte[]{1}, ke1(), BigInteger.TEN);
    state.close();

    assertThat(state.isClosed()).isTrue();
    assertThatThrownBy(state::password).isInstanceOf(ClosedContextException.class);
    assertThatThrownBy(state::blind).isInstanceOf(ClosedContextException.class);
    assertThatThrownBy(state::ke1).isInstanceOf(ClosedContextException.class);
    assertThatThrownBy(state::clientAkePrivateKey).isInstanceOf(ClosedContextException.class);
  }

  /**
   * A caller who wants to distinguish this from a hostile server's malformed hex must be able to.
   *
   * <p>{@code ClosedContextException} extends {@link IllegalStateException} so the broad catch
   * still works, but BouncyCastle's {@code DecoderException} is also an {@code IllegalStateException}
   * and this library wraps it into {@link SecurityException} precisely so a server cannot choose
   * the exception type an application sees. A bare {@code IllegalStateException} here would have
   * put a local lifetime bug into the same bucket.
   */
  @Test
  void theClosedExceptionIsDistinguishableFromTheOtherFailureTypes() {
    ClientAuthState state = new ClientAuthState(BigInteger.ONE, new byte[]{1}, ke1(), BigInteger.TEN);
    state.close();

    assertThatThrownBy(state::password)
        .isInstanceOf(ClosedContextException.class)
        .isInstanceOf(IllegalStateException.class)
        .isNotInstanceOf(SecurityException.class);
  }

  /** close() stays idempotent, so a try-with-resources around a caller that also closes is fine. */
  @Test
  void closeIsIdempotent() {
    byte[] password = {1, 2, 3};
    ClientAuthState state = new ClientAuthState(BigInteger.ONE, password, ke1(), BigInteger.TEN);
    byte[] statesOwnArray = state.password();

    state.close();
    state.close();

    assertThat(statesOwnArray).containsOnly((byte) 0);
    assertThat(state.isClosed()).isTrue();
  }

  /**
   * The generated {@code toString} printed two BigIntegers in full decimal — {@code blind}, which
   * with the blinded element recovers {@code H(password)} and admits an offline dictionary attack,
   * and {@code clientAkePrivateKey}, which yields this session's dh1 and dh2. Both are asserted
   * because redaction regresses silently otherwise.
   */
  @Test
  void toStringDisclosesNeitherScalar() {
    BigInteger blind = new BigInteger("31415926535897932384626433832795028841971");
    BigInteger akePriv = new BigInteger("27182818284590452353602874713526624977572");
    ClientAuthState state = new ClientAuthState(blind, new byte[]{1}, ke1(), akePriv);

    assertThat(state.toString())
        .doesNotContain(blind.toString())
        .doesNotContain(akePriv.toString())
        .contains("<redacted>");
  }

  /** toString stays answerable on a closed state; a throwing one turns a bug into two. */
  @Test
  void toStringStillWorksAfterClose() {
    ClientAuthState state = new ClientAuthState(BigInteger.ONE, new byte[]{1}, ke1(), BigInteger.TEN);
    state.close();

    assertThat(state.toString()).contains("closed=true");
  }

  @Test
  void accessors_returnCorrectValues() {
    BigInteger blind = BigInteger.valueOf(42);
    byte[] password = {1};
    KE1 ke1 = new KE1(new CredentialRequest(new byte[1]), new byte[1], new byte[1]);
    BigInteger akePriv = BigInteger.valueOf(99);
    ClientAuthState state = new ClientAuthState(blind, password, ke1, akePriv);

    assertThat(state.blind()).isEqualTo(blind);
    // Copied, not aliased — the identity assertion here is the point, not incidental.
    assertThat(state.password()).isNotSameAs(password).containsExactly(1);
    assertThat(state.ke1()).isSameAs(ke1);
    assertThat(state.clientAkePrivateKey()).isEqualTo(akePriv);
  }
}
