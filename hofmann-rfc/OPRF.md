# oprf — RFC 9497 Oblivious Pseudorandom Functions

This module implements [RFC 9497](https://www.rfc-editor.org/rfc/rfc9497.html) OPRF (Oblivious Pseudorandom Function) mode 0 (base mode), built on top of the `hash-to-curve` module (RFC 9380).

## What It Provides

An OPRF lets a client compute a pseudorandom function of a private input using a server's secret key, without the server ever learning the input. The client blinds its input before sending it to the server, the server evaluates the function on the blinded value, and the client unblinds the result to obtain a consistent pseudorandom output.

**Use cases**: password hashing, private set intersection, anonymous tokens, and as a building block for OPAQUE (see `opaque/`).

## Cipher Suites

All four cipher suites are supported:

| Constant | Curve | Hash | Element Size |
|---|---|---|---|
| `OprfCipherSuite.P256_SHA256` | P-256 | SHA-256 | 33 bytes |
| `OprfCipherSuite.P384_SHA384` | P-384 | SHA-384 | 49 bytes |
| `OprfCipherSuite.P521_SHA512` | P-521 | SHA-512 | 67 bytes |
| `OprfCipherSuite.RISTRETTO255_SHA512` | Ristretto255 | SHA-512 | 32 bytes |

## Protocol Flow

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

- `r`: random blinding scalar chosen by client
- `s`: server's secret key (`skS`)
- `P`: hash of input to a group element (RFC 9380 `HashToGroup`)
- `N`: the OPRF evaluation result, independent of `r`

## Key Classes

### `OprfCipherSuite`

The central abstraction. Encapsulates hash algorithm, domain-separation strings, group spec, and all cryptographic operations.

```java
OprfCipherSuite suite = OprfCipherSuite.P256_SHA256;

// Derive a server key pair from a seed
KeyPair kp = suite.deriveKeyPair(seed, info);

// OPRF output (used internally by managers)
byte[] output = suite.finalize(input, blind, evaluatedElement);

// Hash and HMAC (delegated to suite's algorithm)
byte[] hash = suite.hash(data);
byte[] mac  = suite.hmac(key, data);
```

For testing with a fixed random source:
```java
OprfCipherSuite deterministic = suite.withRandom(mySecureRandom);
```

### `OprfClientManager`

Stateless client-side OPRF. Produces a blinded request and recovers the final hash.

```java
OprfClientManager client = new OprfClientManager(OprfCipherSuite.P256_SHA256);

// Step 1: create blinding context
ClientHashingContext ctx = client.hashingContext("my-sensitive-input");

// Step 2: build the wire request
BlindedRequest request = client.eliminationRequest(ctx);
// → request.blindedPoint() is the hex-encoded blinded group element
// → request.requestId() is a UUID for correlating the response

// Step 3: after receiving EvaluatedResponse from server:
HashResult result = client.hashResult(evaluatedResponse, ctx);
// → result.hash() is the OPRF output bytes
// → result.processIdentifier() identifies which server key was used
```

### `OprfServerManager`

Stateless server-side OPRF. Evaluates the blinded request using the server key.

```java
// Server key material is loaded via a Supplier (supports key rotation)
Supplier<ServerProcessorDetail> keySupplier = () ->
    new ServerProcessorDetail(serverPrivateKey, "key-v1");

OprfServerManager server = new OprfServerManager(OprfCipherSuite.P256_SHA256, keySupplier);

EvaluatedResponse response = server.process(blindedRequest);
// → response.evaluatedPoint() is the hex-encoded result
// → response.processIdentifier() comes from ServerProcessorDetail
```

## Model Records

| Record | Purpose |
|---|---|
| `BlindedRequest(blindedPoint, requestId)` | Client → Server: hex-encoded blinded element |
| `EvaluatedResponse(evaluatedPoint, processIdentifier)` | Server → Client: hex-encoded evaluated element |
| `ClientHashingContext(requestId, blindingFactor, input)` | Client state held between blind and finalize |
| `ServerProcessorDetail(masterKey, processorIdentifier)` | Server key material (provided via `Supplier`) |
| `HashResult(hash, processIdentifier)` | Final OPRF output |

All wire values (blinded/evaluated points) are hex-encoded.

## Server Key Derivation

Server keys can be derived deterministically from a seed using `deriveKeyPair`:

```java
// RFC 9497 §3.2.1 DeriveKeyPair
BigInteger privateKey = suite.deriveKeyPair(seed, info).privateKey();
```

This supports OPAQUE's per-credential key derivation pattern, where each user gets a unique OPRF key derived from a shared OPRF seed.

## Injectable SecureRandom

For auditing and deterministic testing, the random source used by `randomScalar()` is injectable:

```java
OprfCipherSuite testSuite = OprfCipherSuite.P256_SHA256.withRandom(fixedRandom);
```

This does not affect any deterministic operations (hash-to-curve, key derivation, finalize).

## Dependencies

- `hash-to-curve` — elliptic curve math, RFC 9380 `HashToCurve`, `ExpandMessageXmd`
- BouncyCastle — underlying EC arithmetic

## Tests

| Test | Coverage |
|---|---|
| `OprfVectorsTest` | RFC 9497 Appendix A test vectors for P256, P384, P521, Ristretto255 |
| `RoundTripTest` | Round-trip correctness parameterized over all cipher suites |

Test vectors are sourced from the [CFRG reference implementation](https://github.com/cfrg/draft-irtf-cfrg-voprf) (`poc/vectors/allVectors.json`).
