# oprf — RFC 9497 Oblivious Pseudorandom Functions

This module implements all three [RFC 9497](https://www.rfc-editor.org/rfc/rfc9497.html) modes — OPRF (base), VOPRF (verifiable), and POPRF (partially oblivious) — built on the module's `ellipticcurve.rfc9380` package (RFC 9380 hash-to-curve).

## What It Provides

An OPRF lets a client compute a pseudorandom function of a private input using a server's secret key, without the server ever learning the input. The client blinds its input before sending it to the server, the server evaluates the function on the blinded value, and the client unblinds the result to obtain a consistent pseudorandom output.

**Use cases**: password hashing, private set intersection, anonymous tokens, and as a building block for OPAQUE (see `OPAQUE.md`).

## Modes

| Mode | Byte | What it adds | Managers |
|---|---|---|---|
| `OprfMode.OPRF` | `0x00` | Nothing — the base protocol. The client cannot tell whether the server used the right key. | `OprfClientManager`, `OprfServerManager` |
| `OprfMode.VOPRF` | `0x01` | The server proves it evaluated with the key it publicly committed to. | `VoprfClientManager`, `VoprfServerManager` |
| `OprfMode.POPRF` | `0x02` | A **public** input, agreed by both parties, that separates evaluations. Also verifiable. | `PoprfClientManager`, `PoprfServerManager` |

The mode is chosen on the cipher suite and defaults to `OPRF`:

```java
OprfCipherSuite suite = OprfCipherSuite.builder()
    .withSuite(CurveHashSuite.P256_SHA256)
    .withMode(OprfMode.VOPRF)
    .build();
```

The mode byte is folded into `contextString`, which every domain-separation tag derives from — `HashToGroup-`, `HashToScalar-`, `DeriveKeyPair`, and the `Seed-` value inside the proof composites. Two modes therefore produce different outputs, different proof transcripts, and **different keys from the same seed**. Managers reject a suite in the wrong mode at construction, because the mismatch is otherwise silent: everything still computes, it just computes a different function.

### One key per mode

Do not configure one secret for two modes. Cross-mode *confusion* is already impossible — the context string separates every tag, so a VOPRF proof cannot be replayed as a POPRF one — but two things do not separate:

- RFC 9497 §7.2.3's static Diffie-Hellman security budget degrades with the number of evaluations under a key, and sharing a key pools that count. §4 flags P-256 and ristretto255 for particular care here.
- POPRF hands clients an *inversion* oracle while OPRF and VOPRF hand them a *multiplication* oracle. §7.2.2 rests on One-More Gap SDHI and §7.2.1 on One-More Gap CDH, and no analysis covers an adversary holding both under one key.

`VerifiableProcessorDetail.deriveFromSeed` makes this self-enforcing: `deriveKeyPairDst` embeds the mode-bearing context string, so one seed provably cannot yield the same scalar in two modes.

## Cipher Suites

All four cipher suites from RFC 9497 are supported, in every mode:

| Suite | Curve | Hash | Element (Ne) | Scalar (Ns) | Output (Nh) | Scalar encoding |
|---|---|---|---|---|---|---|
| `CurveHashSuite.P256_SHA256` | P-256 | SHA-256 | 33 | 32 | 32 | Big-endian |
| `CurveHashSuite.P384_SHA384` | P-384 | SHA-384 | 49 | 48 | 48 | Big-endian |
| `CurveHashSuite.P521_SHA512` | P-521 | SHA-512 | 67 | 66 | 64 | Big-endian |
| `CurveHashSuite.RISTRETTO255_SHA512` | ristretto255 | SHA-512 | 32 | 32 | 64 | Little-endian |

The first three use Weierstrass curves via BouncyCastle. ristretto255 uses pure `BigInteger` Edwards25519 arithmetic with the ristretto255 group abstraction (RFC 9496). See `HASH_TO_CURVE.md` for how they differ. RFC 9497's remaining suite, decaf448-SHAKE256 (§4.2), is not implemented here. Note the RFC orders its suites ristretto255 (§4.1), decaf448 (§4.2), P-256 (§4.3), P-384 (§4.4), P-521 (§4.5), so its section numbers are not contiguous with the list above.

## Protocol Flows

### OPRF — base mode

```
Client                          Server
────────                        ───────
1. P = HashToGroup(input)
2. Q = P · r             (blind)
3. Send Q ──────────────────►  R = Q · s = P · r · s   (evaluate)
          ◄──────────────────  R
4. N = R · r⁻¹ = P · s  (unblind)
5. output = Finalize(input, N)
```

`r` is the client's random blind, `s` the server's secret key. `N` is independent of `r`, so the output is stable across evaluations of the same input.

**The client has no way to check `s`.** A server that answers with a different key, or with a garbage element, produces output the client cannot distinguish from correct. If that matters, use VOPRF.

### VOPRF — mode 0x01

```
Client (holds pkS)              Server (holds skS, pkS = skS · G)
──────────────────              ─────────────────────────────────
1. P = HashToGroup(input)
2. Q = P · r             (blind)
3. Send Q ──────────────────►  R = Q · skS
                                proof = GenerateProof(skS, G, pkS, [Q], [R])
          ◄──────────────────  R, proof
4. VerifyProof(G, pkS, [Q], [R], proof)   ← fails closed
5. N = R · r⁻¹
6. output = Finalize(input, N)
```

The proof is a batched Chaum–Pedersen discrete-log-equality proof (RFC 9497 §2.2): it attests that the same `skS` relates `pkS` to `G` as relates each `R` to its `Q`, without revealing `skS`.

### POPRF — mode 0x02

```
Client (holds pkS, info)        Server (holds skS, receives info)
────────────────────────        ─────────────────────────────────
1. m = HashToScalar("Info" ‖ len(info) ‖ info)
2. tweakedKey = m · G + pkS      ← client's own derivation
3. P = HashToGroup(input);  Q = P · r
4. Send Q, info ────────────►  m = HashToScalar(...same...)
                                t = skS + m         (reject if 0)
                                R = Q · t⁻¹
                                B = t · G
                                proof = GenerateProof(t, G, B, [R], [Q])
          ◄──────────────────  R, proof
5. VerifyProof(G, tweakedKey, [R], [Q], proof)
6. N = R · r⁻¹
7. output = Finalize(input, info, N)
```

Three things differ from VOPRF, and all three are easy to get wrong in ways that still round-trip against a matching counterpart:

- The evaluation is an **inverse** multiplication under the tweaked key `t = skS + m`.
- The proof therefore covers the element lists in the **opposite order** — `(evaluated, blinded)`, because the attested relation is `Q = t · R`.
- `Finalize` hashes `info` **between** the input and the unblinded element. This applies even when `info` is empty, whose two length bytes the other modes omit entirely — which is why `finalizeWithInfo` is a separate method rather than a nullable parameter on `finalize`.

The client grades the proof against a tweaked key it derived itself, from the `pkS` it already trusts and the `info` it chose. That is what binds a response to the requested public input: a server answering under different `info` proves against a different tweaked key and verification fails.

## Security requirements for the verifiable modes

### `pkS` must be authenticated out of band

The client is constructed with the server's public key and never reads one from a response — the response types have no field for one. A key travelling alongside the proof it authenticates would let the server choose the standard it is judged against, and every response would verify.

Obtaining the key is not enough; it must be **authenticated**. An attacker who can substitute it can run a distinct key per client, producing proofs that verify while partitioning users into individually identifiable buckets. RFC 9497 §7.3 treats key consistency as an application responsibility and nothing in the protocol detects a violation.

### `HashResult.processIdentifier` is not authenticated

The hash is trustworthy — it is only produced after a proof has been checked against the client's configured key — but the accompanying label is whatever the server attached. Treat it as a routing hint; do not persist results keyed by it in a way that would let a server mislabel which key produced a stored value.

### POPRF `info` is public, and should be domain-separated

The server sees `info` in the clear; that is what "partially oblivious" means. Do not put anything confidentiality-sensitive in it. RFC 9497 §5.4 further recommends that applications construct it with higher-level, prefix-free domain separation rather than passing raw user-controlled text, so that two different application contexts cannot produce the same `info`. Length is capped at 65534 bytes (§5.1).

### A POPRF `t == 0` in the logs means rotate the key

`PoprfServerManager` refuses a request whose public input tweaks the server key to zero, and logs it at ERROR. This is not a bad-input condition. Per RFC 9497 §3.3.3, `t = skS + m` is zero only when the public input hashes to the negation of the secret key, so a client that triggers it "should be assumed to know the server private key" and the server "should replace its private key". Treat the log line as an intrusion signal, not a validation failure.

### Residual: proof generation is not fully constant-time

The group operations run on a constant-time ladder, but `s = r − c·k` in `GenerateProof` does not — `BigInteger` multiplication and reduction are variable-time in their operands, and RFC 9497 §7.4 names `GenerateProof` as an operation that should be constant time. The exposure is much smaller than the scalar-multiplication leaks this module closes: the operands are fixed width after the first reduction, and `s` is published in the proof anyway. Removing it entirely needs constant-time scalar-field arithmetic that `BigInteger` does not provide.

### Batching is bounded by policy, not by cryptography

Batch proofs are sound at any size. The servers cap a request at 64 elements by default (1024 absolute) purely as a resource bound, checked before any curve operation. That cap fires only after the whole request has been deserialized, so both integrations also enforce a transport-level body-size bound in front of it — `VerifiableOprfLimits.maxRequestBodyBytes(maxBatchSize)`, wired by the Dropwizard bundle and the Spring auto-configuration. At the default batch size of 64 that bound is 17,024 bytes per endpoint.

## Usage

### Base mode

```java
OprfCipherSuite suite = OprfCipherSuite.builder().withSuite(CurveHashSuite.P256_SHA256).build();

OprfClientManager client = new OprfClientManager(suite);

byte[] secret = "my-sensitive-input".getBytes(StandardCharsets.UTF_8);

// The context copies the input, so `secret` is yours to clear as soon as this returns;
// try-with-resources clears the context's own copy.
try (ClientHashingContext ctx = client.hashingContext(secret)) {
  BlindedRequest request = client.eliminationRequest(ctx);

  // server side
  OprfServerManager server = new OprfServerManager(suite, () ->
      new ServerProcessorDetail(serverPrivateKey, "key-v1"));
  EvaluatedResponse response = server.process(request);

  HashResult result = client.hashResult(response, ctx);
}
```

**Pass the input as `byte[]`, not `String`.** A `String` holding a secret cannot be erased — it is
immutable, so the value stays on the heap until the collector reclaims it, and any interning or
substring on the way has already made copies nobody holds a reference to. The `String` overloads
remain for callers who already have one in hand, where the damage is done before the call and
refusing it would only move the conversion. Every client context implements `AutoCloseable` and
zeroes its copy of the input on close; the blinding scalars are `BigInteger` and cannot be cleared
at all, which is why closing shortens a window rather than emptying the context.

**Scope the `try`-with-resources to the whole exchange.** A closed context refuses to be used:
every accessor that returns protocol state throws `ClosedContextException`, so a lifetime mistake
fails at the first call rather than travelling. An asynchronous round trip, where the response
arrives after the block has exited, is the shape to watch for.

That guard is newer than the `close()` it protects, and what it replaced is worth knowing if you
are upgrading. A closed context used to answer *wrongly* rather than fail. Both `eliminationRequest`
and `hashResult` read the input, so a closed context finalized over zeroes and returned a
well-formed hash derived from the wrong value, with no exception anywhere. The verifiable modes hid
it best: the blinded elements are stored rather than recomputed, so the server evaluated correctly
and **the proof verified** — only the hash was wrong. That is why the guard covers
`blindedElements()` and `info()`, not just the input it zeroes; guarding only the zeroed field
would leave that case intact and merely move the failure to after the network call.

`requestId()`, `size()`, `isClosed()` and `toString()` keep working on a closed context, so you can
still log about one.

### VOPRF

```java
OprfCipherSuite suite = OprfCipherSuite.builder()
    .withSuite(CurveHashSuite.P256_SHA256).withMode(OprfMode.VOPRF).build();

VerifiableProcessorDetail key =
    VerifiableProcessorDetail.deriveFromSeed(suite, seed, keyInfo, "key-v1");
key.validateConsistency(suite);   // startup check

VoprfServerManager server = new VoprfServerManager(suite, () -> key);
VoprfClientManager client = new VoprfClientManager(suite, key.publicKey());  // authenticated pkS

byte[] secret = "my-sensitive-input".getBytes(StandardCharsets.UTF_8);

try (VoprfClientContext ctx = client.hashingContext(List.of(secret))) {
  HashResult result = client.hashResult(server.process(client.eliminationRequest(ctx)), ctx);
  // throws SecurityException if the proof does not verify
}
```

### POPRF

```java
OprfCipherSuite suite = OprfCipherSuite.builder()
    .withSuite(CurveHashSuite.P256_SHA256).withMode(OprfMode.POPRF).build();

byte[] info = "billing-2026-Q3".getBytes(StandardCharsets.UTF_8);

// A POPRF key, derived separately from the VOPRF one above — see "One key per mode".
VerifiableProcessorDetail key =
    VerifiableProcessorDetail.deriveFromSeed(suite, seed, keyInfo, "key-v1");

PoprfServerManager server = new PoprfServerManager(suite, () -> key);
PoprfClientManager client = new PoprfClientManager(suite, key.publicKey());

byte[] secret = "my-sensitive-input".getBytes(StandardCharsets.UTF_8);

try (PoprfClientContext ctx = client.hashingContext(List.of(secret), info)) {
  HashResult result = client.hashResult(server.process(client.eliminationRequest(ctx)), ctx);
}
```

### Batching

Every verifiable manager takes a list of inputs and covers them with one proof:

```java
VoprfClientContext ctx = client.hashingContext(List.of(input1, input2, input3));
List<HashResult> results = client.hashResults(server.process(client.eliminationRequest(ctx)), ctx);
```

Results are positionally aligned with the inputs. The client rejects a response whose length differs from the request before doing anything else, and a reordered response fails proof verification — the composite coefficients bind each element pair to its batch index.

## Model Types

| Type | Purpose |
|---|---|
| `BlindedRequest(blindedPoint, requestId)` | OPRF client → server |
| `EvaluatedResponse(evaluatedPoint, processIdentifier)` | OPRF server → client |
| `ClientHashingContext(requestId, blindingFactor, input)` | OPRF client state — `AutoCloseable` final class, not a record |
| `ServerProcessorDetail(masterKey, processorIdentifier)` | OPRF server key material |
| `VerifiableBlindedRequest(blindedPoints, requestId)` | VOPRF client → server |
| `VerifiableEvaluatedResponse(evaluatedPoints, proof, processIdentifier)` | VOPRF server → client |
| `VoprfClientContext(requestId, inputs, blinds, blindedElements)` | VOPRF client state — `AutoCloseable` final class, not a record |
| `PartiallyBlindedRequest(blindedPoints, info, requestId)` | POPRF client → server |
| `PartiallyEvaluatedResponse(evaluatedPoints, proof, processIdentifier)` | POPRF server → client |
| `PoprfClientContext(requestId, inputs, blinds, blindedElements, info, tweakedKey)` | POPRF client state — `AutoCloseable` final class, not a record |
| `VerifiableProcessorDetail(masterKey, publicKey, processorIdentifier, mode)` | VOPRF/POPRF server key material |
| `HashResult(hash, processIdentifier)` | Final output (see the caveat above) |

The three client contexts are final classes rather than records, so they can carry a `closed` flag
and refuse use after `close()`. That costs record equality — `equals`/`hashCode` are identity-based
and record patterns do not deconstruct them. See the upgrade note in `MIGRATION.md`. Everything else
in this table is a record.

The client contexts hold their lists positionally aligned and immutable, so alignment cannot be broken after construction. All wire values are hex-encoded: compressed SEC1 for Weierstrass suites, 32-byte canonical encodings for ristretto255.

**The verifiable modes additionally reject non-compressed encodings**, because their proof transcripts hash element *bytes* — an element re-encoded in flight from compressed to uncompressed would leave the server proving over bytes the client never sent, and the client could not distinguish that from a faulty server. Base mode does not enforce this: BouncyCastle accepts SEC1 uncompressed and hybrid forms, and mode 0x00 has no transcript, so a re-encoded element yields byte-identical output and there is nothing to exploit.

## Key Classes

### `OprfCipherSuite`

Encapsulates the mode, hash algorithm, domain-separation strings, group spec, and the cryptographic operations shared by all three modes.

```java
BigInteger skS = suite.deriveKeyPair(seed, info);
byte[] pkS     = suite.derivePublicKey(skS);
byte[] output  = suite.finalize(input, blind, evaluatedElement);
byte[] withInfo = suite.finalizeWithInfo(input, info, blind, evaluatedElement);  // POPRF
```

`finalize` and `finalizeWithInfo` perform **no proof verification**. In the verifiable modes, go through the managers.

### The DLEQ layer — `rfc9497.proof`

`DleqProver`, `DleqVerifier`, `DleqProof`, and the batched `Composites`. Used by both verifiable modes; not normally called directly.

`verifyProof` returns a boolean and returns `false` for every attacker-influenced failure — bad encoding, non-canonical scalar, identity result, wrong challenge — so none can be told apart. Batch-shape errors throw instead, because a null, empty, or length-mismatched batch is a caller bug rather than a proof failure.

Proof randomness must be fresh for every proof: two proofs sharing `r` under one key expose it as `k = (s₁ − s₂)/(c₂ − c₁)`, the same break ECDSA nonce reuse gives. The only way to supply your own `r` is a package-private overload that exists solely to reproduce the RFC's fixed `ProofRandomScalar` values, and a test asserts no production code reaches it.

## Injectable SecureRandom

For auditing and deterministic testing, the random source used by `randomScalar()` is injectable:

```java
OprfCipherSuite testSuite = suite.withRandom(fixedRandom);
```

This does not affect any deterministic operation (hash-to-curve, key derivation, finalize).

## Dependencies

- `ellipticcurve.rfc9380` — RFC 9380 `BcWeierstrassHashToCurve`, `ExpandMessageXmd`, `GroupSpec`
- BouncyCastle — EC arithmetic for Weierstrass curves (not used by ristretto255)

## Tests

| Test | Coverage |
|---|---|
| `OprfVectorsTest` | RFC 9497 Appendix A base-mode vectors, all four suites |
| `OprfModeTest` | Mode separation; `skSm` for all 12 (suite, mode) pairs and `pkSm` for the 8 verifiable ones |
| `GroupSpecArithmeticTest` | Element addition, multi-scalar accumulation, scalar and element encoding |
| `DleqVectorsTest` | Appendix A proof vectors, both verifiable modes, batch sizes 1 and 2 |
| `DleqProofTest` | Proof round-trip and negatives |
| `VoprfVectorsTest` / `PoprfVectorsTest` | End-to-end Appendix A conformance through the real managers |
| `VoprfManagerTest` / `PoprfManagerTest` | Manager behaviour and negatives |
| `RoundTripTest` | Base-mode round-trip over all cipher suites |

Test vectors live in `src/test/resources/rfc9497/vectors.json`, transcribed mechanically from the published RFC text rather than vendored from the CFRG proof-of-concept repository, which is an unpinned draft artifact carrying decaf448 vectors this module has no suite for.

Note the RFC orders its suites ristretto255 (A.1), decaf448 (A.2), P-256 (A.3), P-384 (A.4), P-521 (A.5), and within each, OPRF/VOPRF/POPRF as `.1`/`.2`/`.3`. Since decaf448 is not implemented, the numbering is not contiguous with this module's suite list.
