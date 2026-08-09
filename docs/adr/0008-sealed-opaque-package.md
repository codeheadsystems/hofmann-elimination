# 8. The OPAQUE package is folded into one and sealed in the jar

- **Status:** Accepted (2026-08-08). In force.
- **Decided in:** `a9a5cfe` (PR #96)
- **Implements:** `com.codeheadsystems.rfc.opaque` (`OpaqueOprf`, `OpaqueCredentials`,
  `OpaqueEnvelope`, `OpaqueAke`), `PackageBoundaryTest`, and `verifyOpaquePackageSealed` in
  [`hofmann-rfc/build.gradle.kts`](../../hofmann-rfc/build.gradle.kts)
- **Related:** [ADR-0005](0005-closed-contexts-refuse-use.md),
  [ADR-0007](0007-spring-security-autoconfiguration.md)

## Context

Five deterministic entry points were made package-private on `Client` and `Server` — the ones that
let a caller fix a nonce or a blind — and the same capabilities stayed public one package over in
`...opaque.internal`. `createRegistrationRequestWithBlind` and `finalizeRegistrationWithNonce` had
identical bodies; `generateKE2Deterministic` was the exact call the removed wrapper made; and
`OpaqueAke.generateKE2` took `maskingNonce` and `serverAkeKeySeed` as ordinary parameters, which
is invisible to a name-based check by construction.

A reviewer rebuilt all five from another package using public API and no reflection, replay
included.

## Decision

Fold the four `internal` classes into `com.codeheadsystems.rfc.opaque` as package-private and
final. Folding rather than bridging: a bridge leaves a second entry point to keep in step with the
first.

Two mechanisms hold it, because the previous attempt was held by a comment:

- **`PackageBoundaryTest`** enumerates the compiled package off its code source and pins the
  public methods, constructors *and fields* by signature. Signatures because `generateKE2` hid
  behind its parameter list; fields because a reviewer added a public `RFC_TEST_BLIND` constant to
  `Client` against a draft that read only methods, and the build stayed green.
- **The jar seals `com/codeheadsystems/rfc/opaque/`.** Package-private access is keyed on the
  package *name*, so a class declared into it from another jar compiled and called straight
  through — reproduced, and reproduced as refused with the seal in place.
  `verifyOpaquePackageSealed` asserts the refusal by loading a second code source in front of the
  built jar, not by reading the manifest string, and runs as part of `check`.

## Alternatives rejected

- **`module-info.java`.** Inert on the class path, which is how this library is consumed.
- **A bridge package delegating into the folded one.** Leaves the second entry point in place.
- **Sealing the whole jar.** Only this package is sealed; sealing is enforced per code source and
  a blanket seal constrains consumers for no gain here.
- **A comment saying "internal, do not use".** What the previous attempt relied on.

## Consequences

- **One build-level consequence, inside this project.** `java-test-fixtures` puts the project's own
  jar on its test runtime classpath instead of the classes directory, and the OPAQUE tests are
  white-box and live in the sealed package — so `Client` failed to load before any test ran.
  `tasks.test` substitutes the classes directory back, verified to drop exactly that one entry.
- Consumers who were calling `...opaque.internal` have no supported replacement, which is the
  intent.

## Superseded analyses

- **"The server-side capabilities are not reconstructable at all."** An earlier draft's claim, and
  too strong. They are, through the injectable `SecureRandom`, which fixes every nonce at once
  from any package. That residual was already reviewed and accepted on `OprfCipherSuite.withRandom`
  and is cross-referenced rather than re-filed. What this decision changes is the accident
  surface, not the capability.
- **A name-based boundary check is not a boundary check.** Two independent escapes proved it:
  `generateKE2` hid behind its parameter list rather than its name, and a public constant on
  `Client` passed a draft that read only methods. Both are why the pin is by signature and covers
  fields.
