# 5. A closed context refuses use rather than answering from zeroes

- **Status:** Accepted (2026-08-08). In force.
- **Decided in:** `8b2883b` (PR #98)
- **Implements:** [`ClosedContextException`](../../hofmann-rfc/src/main/java/com/codeheadsystems/rfc/common/ClosedContextException.java),
  [`ClientHashingContext`](../../hofmann-rfc/src/main/java/com/codeheadsystems/rfc/oprf/model/ClientHashingContext.java),
  [`ClientAuthState`](../../hofmann-rfc/src/main/java/com/codeheadsystems/rfc/opaque/model/ClientAuthState.java),
  [`ClientRegistrationState`](../../hofmann-rfc/src/main/java/com/codeheadsystems/rfc/opaque/model/ClientRegistrationState.java),
  [`AuthResult`](../../hofmann-rfc/src/main/java/com/codeheadsystems/rfc/opaque/model/AuthResult.java),
  and the two VOPRF/POPRF client contexts
- **Related:** [ADR-0008](0008-sealed-opaque-package.md) — both are about a guarantee that a
  comment cannot hold.

## Context

Six client-side `AutoCloseable` types zeroed their copy of the caller's secret on `close()`, and
none refused use afterwards. A context used after closing derived from a run of zeroes and
returned a well-formed value computed from the wrong input.

The verifiable OPRF modes hid it best. `eliminationRequest` returns the blinded elements the
context already holds rather than recomputing them, so against a closed context the server
received correct elements, evaluated them correctly, and returned a DLEQ proof that verified. The
check that exists to catch a misbehaving server was silent, because the server had not misbehaved.
Only the final hash was wrong, a round trip late.

Registration was worse, because it reported nothing at all: it has no envelope MAC to fail
against, so a closed state produced a complete registration record that the client uploaded.
`changePassword` runs the same code, so the bug on a rotation destroyed a working account while
reporting success.

## Decision

Every accessor that returns protocol state throws `ClosedContextException` once `close()` has run.
The guard covers `blindedElements()` and `info()` too — guarding only the zeroed field would leave
the verifiable-mode case fully intact and merely move the failure to after the request reached the
server.

`requestId()`, `size()`, `isClosed()` and `toString()` stay open, so a closed context can still be
logged about, as does `AuthResult.ke3()`, which `close()` does not zero.

`ClosedContextException` **subclasses** `IllegalStateException` rather than being one. BouncyCastle's
`DecoderException` is also an `IllegalStateException`, and this library wraps that into
`SecurityException`; a distinct type stops a hostile server from picking the exception an
application sees. The guard sits in the accessors, upstream of anything a peer controls, so it is
neither inducible nor observable remotely.

## Alternatives rejected

- **Guard only the accessor for the zeroed field.** Leaves the verifiable-mode failure intact.
- **Keep the six types as records.** A `closed` flag is mutable state, which a record cannot
  carry. All six became final classes with every field explicitly final — without that a
  hand-written class loses the JMM final-field freeze the records gave implicitly, and an
  asynchronous round trip is exactly the cross-thread publication this guard exists for.
- **Re-implement value equality on the new classes.** Deliberately not done: over a secret, that
  is a variable-time comparison of secret material. `equals`/`hashCode` are identity-based.

## Consequences

- **A source-compatible but semantically visible change.** Constructor signatures and accessor
  names are unchanged, but record patterns no longer deconstruct these types and value equality is
  gone.
- `toString()` had to be written by hand, which surfaced four separate disclosures of private
  scalars in full decimal that the generated implementations had been printing.

## Superseded analyses

- **"This is an account-takeover primitive."** A review draft read the registration case as the
  account becoming registered under the publicly known all-zero password. That is wrong: the two
  halves of the OPRF disagree — the evaluated element was computed from `blind * H(realPassword)`
  before the close, while `Finalize` consumed zeroes — so the envelope is keyed to a value no
  client can reproduce. It is a lockout with no self-service way out, not a bypass.
  `ClosedStateRefusalTest` reproduces the real outcome rather than arguing it.
- **"Four types are affected."** The `TODO` entry named four; there are six.
  `ClientRegistrationState` and `AuthResult` have the same defect, and registration was the only
  case that reported nothing at all.
