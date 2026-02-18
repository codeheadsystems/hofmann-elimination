# Security TODO

Remaining items from the security review (Feb 2026). Items marked DONE have been
addressed; the rest are listed by priority.

## DONE

- [x] **P0: Constant-time MAC comparison** — replaced `Arrays.equals` with
      `MessageDigest.isEqual` in `OpaqueAke`, `OpaqueEnvelope`, and `Server`.
- [x] **P0: EC point validation** — `OpaqueCrypto.deserializePoint` and
      `OctetStringUtils.toEcPoint` now reject identity and off-curve points.
- [x] **P1: Deserialization bounds checks** — `KE2.deserialize` and
      `Envelope.deserialize` validate input length before `System.arraycopy`.
- [x] **P1: Session store DoS protection** — `OpaqueResource.pendingSessions` is
      capped at 10,000 entries with per-entry TTL instead of bulk clear.
- [x] **P1: Base64 decode error handling** — all `B64D.decode` calls wrapped in
      `decodeBase64()` helper returning HTTP 400 for malformed input.
- [x] **Input validation** — null/blank checks on all REST endpoint inputs;
      OPRF resource validates hex EC point input.
- [x] **Unified error messages** — all MAC/envelope failures throw generic
      "Authentication failed" to prevent protocol state leakage.

## P2: Important

- [ ] **Add TLS enforcement** — No HTTPS configuration exists. Add TLS config
      fields to `HofmannConfiguration` and document that production deployments
      MUST use HTTPS. Consider enforcing `https://` scheme in
      `OpaqueAccessor.baseUri()`.

- [ ] **Add authentication to REST endpoints** — All endpoints are unauthenticated.
      Add bearer token, API key, or mutual TLS authentication. At minimum, the
      `DELETE /opaque/registration` and OPRF endpoints need access control.

- [ ] **Implement key material cleanup** — `ClientAuthState` and
      `ClientRegistrationState` records hold plaintext `password`, `blind`, and
      `clientAkePrivateKey` with no zeroing after use. Consider implementing
      `AutoCloseable` with `Arrays.fill(0)` cleanup, or switching to a mutable
      holder that can be wiped.
      Files: `opaque/model/ClientAuthState.java`, `ClientRegistrationState.java`

- [ ] **Shut down sessionReaper on app shutdown** — The `ScheduledExecutorService`
      in `OpaqueResource` is never shut down. Register it with Dropwizard's
      `Managed` lifecycle or add a `@PreDestroy` hook.
      File: `hofmann-server/resource/OpaqueResource.java`

- [ ] **Add request size limits** — No `Content-Length` limit on incoming requests.
      Configure max request body size in Dropwizard to prevent large-payload DoS.

- [ ] **Add rate limiting** — No rate limiting on any endpoint. Add per-IP or
      per-credential rate limits, especially on `/auth/start` and the OPRF
      endpoint (to limit oracle calls against the server's OPRF key).

## P3: Good to have

- [ ] **Constant-time modular inverse** — `OprfCipherSuite.java:166` uses
      `BigInteger.modInverse()` which is not constant-time. Consider replacing
      with Fermat inversion (`blind.modPow(n.subtract(TWO), n)`) for
      constant-time behavior.

- [ ] **Secrets manager integration** — `HofmannConfiguration` stores
      `serverKeySeedHex`, `oprfSeedHex`, `oprfMasterKeyHex` in plaintext YAML.
      Add support for environment variable substitution or a secrets manager.

- [ ] **Subgroup membership checks** — EC points are validated for on-curve and
      non-identity but not for prime-order subgroup membership. For P-256/P-384/P-521
      (cofactor 1) this is not exploitable, but documenting the assumption is prudent.

- [ ] **Production KSF enforcement** — The identity KSF is correctly flagged for
      test use only. Consider adding a runtime check that rejects identity KSF
      in non-test configurations to prevent accidental production deployment.
