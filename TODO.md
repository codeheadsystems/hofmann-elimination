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

## P1: Implement ristretto255-SHA512 OPRF Suite

- [ ] **Add ristretto255-SHA512 cipher suite** — RFC 9497 §4.4 defines a ristretto255-SHA512
      OPRF suite that was partially implemented but not completed. See `ristretto255.md` for
      full details, test vectors, known bugs, and a recommended debug approach.

      What is needed:
      - `ElligatorMap.java` in `rfc9380/`: field arithmetic, Elligator map, ristretto255
        encode/decode, point addition/doubling (Edwards25519)
      - `Ristretto255GroupSpec.java` in `rfc9380/`: implements `GroupSpec` using `ElligatorMap`
      - `OprfCipherSuite.RISTRETTO255_SHA512` constant and `buildRistretto255Sha512()` method
      - `Ristretto255Sha512` nested class in `OprfVectorsTest` (vectors in `ristretto255.md`)

      Key issues from the previous attempt (details in `ristretto255.md`):
      - Several constants and sign conventions are tricky; see the notes for correct formulas
      - `encodeRistretto255` was producing wrong output; the encode algorithm is the main
        remaining bug — `sqrtRatioM1` returns `wasSquare=false` for a case where it should
        be true
      - `hashToScalar` must use little-endian byte interpretation (not OS2IP/big-endian)

      The `GroupSpec` interface is already the right extension point; `OprfCipherSuite` needs
      no structural changes beyond adding the constant and builder.

## P2: Important

- [ ] **Add TLS enforcement** — No HTTPS configuration exists. Add TLS config
      fields to `HofmannConfiguration` and document that production deployments
      MUST use HTTPS. Consider enforcing `https://` scheme in
      `OpaqueAccessor.baseUri()`.

- [ ] **Add authentication to REST endpoints** — All endpoints are unauthenticated.
      Add bearer token, API key, or mutual TLS authentication. At minimum, the
      `DELETE /opaque/registration` and OPRF endpoints need access control.

- [x] **Implement key material cleanup** — `ClientAuthState` and `ClientRegistrationState`
      now implement `AutoCloseable`; `close()` zeros the `password` byte array via
      `Arrays.fill`. `BigInteger` fields (`blind`, `clientAkePrivateKey`) are immutable
      and cannot be zeroed at the Java level.
      Files: `opaque/model/ClientAuthState.java`, `ClientRegistrationState.java`

- [x] **Shut down sessionReaper on app shutdown** — Added `HofmannOpaqueServerManager.shutdown()`
      which calls `sessionReaper.shutdown()`. `HofmannBundle` registers a Dropwizard `Managed`
      lifecycle component that calls it on stop. `HofmannAutoConfiguration` declares the bean
      with `@Bean(destroyMethod = "shutdown")` for Spring Boot.
      Files: `hofmann-server/manager/HofmannOpaqueServerManager.java`,
             `hofmann-dropwizard/HofmannBundle.java`,
             `hofmann-springboot/config/HofmannAutoConfiguration.java`

- [x] **Add request size limits** — Added `maxRequestBodyBytes` field to
      `HofmannConfiguration` (default 65536 bytes / 64 KiB). `HofmannBundle` registers
      a JAX-RS `ContainerRequestFilter` that checks `Content-Length` and returns HTTP 413
      if the header exceeds the configured limit.
      Files: `hofmann-dropwizard/HofmannConfiguration.java`, `HofmannBundle.java`

- [ ] **Add rate limiting** — No rate limiting on any endpoint. Add per-IP or
      per-credential rate limits, especially on `/auth/start` and the OPRF
      endpoint (to limit oracle calls against the server's OPRF key).

## P3: Good to have

- [x] **Constant-time modular inverse** — `OprfCipherSuite.finalize()` now uses
      Fermat inversion `blind.modPow(n-2, n)` instead of `BigInteger.modInverse()`.
      `modPow` with a fixed-length exponent (n-2 has the same bit-length as n) is
      significantly more constant-time than the Extended Euclidean Algorithm.

- [ ] **Secrets manager integration** — `HofmannConfiguration` stores
      `serverKeySeedHex`, `oprfSeedHex`, `oprfMasterKeyHex` in plaintext YAML.
      Add support for environment variable substitution or a secrets manager.

- [x] **Subgroup membership checks** — `WeierstrassGroupSpecImpl.deserializePoint()`
      now documents the cofactor-1 assumption explicitly. For P-256/P-384/P-521/secp256k1
      (h=1) every non-identity on-curve point is automatically in the prime-order subgroup.
      A guarded runtime check (`n·P = O`) is included for defense-in-depth should a
      cofactor>1 curve be added in the future.

- [ ] **Production KSF enforcement** — The identity KSF is correctly flagged for
      test use only. Consider adding a runtime check that rejects identity KSF
      in non-test configurations to prevent accidental production deployment.
