# Elliptic Curve Hashing

Java 21 implementation of **RFC 9380 — Hashing to Elliptic Curves**, built on 
BouncyCastle.

This security primitive provides for a deterministic way to generate a point on
an elliptic curve from arbitrary input data. It operates as a one-way hashing 
function making it difficult to reverse. This primitive is used for other cryptographic
protocols.

On the NIST curves the RFC 9380 arithmetic itself is **BouncyCastle's**, from its
`org.bouncycastle.crypto.hash2curve` package. This module supplies the wiring, the group
abstraction, the constant-time scalar multiplication and the validation rules. ristretto255 is
implemented here in full, because BouncyCastle has no ristretto255 or decaf448 support.

## Supported Curves

### Weierstrass curves

| Curve      | Hash    | Suite constant                        | RFC 9380 section |
|------------|---------|---------------------------------------|------------------|
| P-256      | SHA-256 | `WeierstrassGroupSpecImpl.P256_SHA256`    | §8.2             |
| P-384      | SHA-384 | `WeierstrassGroupSpecImpl.P384_SHA384`    | §8.3             |
| P-521      | SHA-512 | `WeierstrassGroupSpecImpl.P521_SHA512`    | §8.4             |

### Non-Weierstrass curves

| Curve         | Hash    | Suite constant                    | Specification    |
|---------------|---------|-----------------------------------|------------------|
| ristretto255  | SHA-512 | `Ristretto255GroupSpec.INSTANCE`  | RFC 9496 / 9380 Appendix B |

These four are exactly the OPRF (RFC 9497) and OPAQUE (RFC 9807) cipher suites — see
[`OPRF.md`](OPRF.md) and [`OPAQUE.md`](OPAQUE.md).

**secp256k1 was removed** when hashing moved to BouncyCastle. It was never an OPRF or OPAQUE
suite — it existed only to exercise the RFC 9380 §8.7 isogeny path — and BouncyCastle cannot
serve it: secp256k1 has `A = 0`, so the Simplified SWU map has to run on a 3-isogenous curve, and
the only isogeny BouncyCastle implements is the BLS12-381 G1 one. Nothing in the wire format, the
stored registration records, or the TypeScript and Rust clients referred to it, so its removal is
not a compatibility event.

### Domain separation tags

DSTs cross this API as `byte[]`, not `String`, because RFC 9497 §3.1 builds the context string as
`"OPRFV1-" || I2OSP(mode, 1) || "-" || suiteID` — it carries a raw mode byte.

One limit is worth knowing: on the NIST curves a DST **longer than 255 bytes is rejected** with
`IllegalArgumentException` rather than being rewritten as `H2C-OVERSIZE-DST-` per RFC 9380 §5.3.3.
That is BouncyCastle's `XmdMessageExpansion` behaviour. ristretto255 still goes through this
module's own `ExpandMessageXmd` and still performs the rewrite. No DST this library generates comes
close to 255 bytes.

## Package Structure

### `curve/`

Low-level curve wrappers and encoding utilities.

- **`Curve`** — Immutable record wrapping BouncyCastle `ECDomainParameters`. Exposes the curve field, generator `G`, group order `n`, and cofactor `h`. Static constants: `P256_CURVE`, `P384_CURVE`, `P521_CURVE`.

### `common/`

- **`ByteUtils`** — Encoding primitives shared across the codebase:
  - `I2OSP(int, int)` — Integer to octet string (RFC 8017). **Throws** above `2^(8*length) - 1`
    rather than truncating, which is what keeps a length prefix from colliding in a transcript.
  - `concat(byte[]...)` — Byte array concatenation
  - `scalarToFixedBytes(BigInteger, int)` — Fixed-width big-endian scalar encoding. Note this is
    *not* the canonical per-suite encoding; for that use `GroupSpec.serializeScalar`, which is
    big-endian on the NIST curves and little-endian on ristretto255 per RFC 9496.
  - `xor(byte[], byte[])` — Fixed-length XOR, used for the credential masking pad
  - `isAllZero(byte[])` — Pre-check for the ristretto255 identity encoding, so callers can reject
    it with their own exception type before decoding
  - `dhECDH(BigInteger, ECPoint)` — Raw ECDH. **Not used by any production path, and not
    constant-time**: it calls `ECPoint.multiply`, which is window-NAF on the NIST curves —
    the multiplier the ladder exists to avoid. Everything that touches a real
    private key goes through `GroupSpec.scalarMultiply` instead. Retained for tests; do not reach
    for it because the parameter is named `privateKey`.

- **Point decoding with validation** is not a shared utility. It lives on each group —
  `WeierstrassGroupSpecImpl.deserializePoint` (public) and `Ristretto255GroupSpec.decodeRistretto255`
  (package-private, reached through `scalarMultiply` and `validateElement`). The split is
  deliberate: the two groups reject different things — canonical compressed SEC1 and on-curve for
  one, RFC 9496 §4.3.1 canonicity for the other — so a single helper would have to be a lowest
  common denominator.

### `rfc9380/`

Full hash-to-curve pipeline from RFC 9380 Section 3.

- **`GroupSpec`** — Interface abstracting a cryptographic group over serialized `byte[]` elements. Methods: `hashToGroup`, `hashToScalar`, `scalarMultiply`, `scalarMultiplyGenerator`, `serializeScalar`, `groupOrder`, `elementSize`. All group elements cross the interface as opaque `byte[]`, making it agnostic to the underlying curve type.

- **`WeierstrassGroupSpecImpl`** — `GroupSpec` implementation for the NIST curves. Delegates hashing to `BcWeierstrassHashToCurve` and to BouncyCastle's `OPRFHashToScalar`, serializes points as compressed SEC1 (33 bytes for P-256, 49 for P-384, 67 for P-521), and scalars as big-endian. Validates deserialized points against the curve and rejects the identity element. Uses BouncyCastle `ECPoint` internally.

- **`Ristretto255GroupSpec`** — `GroupSpec` implementation for the ristretto255 group (RFC 9496), built on Edwards25519. See [Ristretto255 vs Weierstrass](#ristretto255-vs-weierstrass-curves) for how it differs from the Weierstrass implementation.

- **`BcWeierstrassHashToCurve`** — Orchestrates the four-step `hash_to_curve` pipeline (RFC 9380 §3) over BouncyCastle's `HashToField`, `SimplifiedShallueVanDeWoestijneMapToCurve` and `NistCurveProcessor`. Built once per curve, since the SSWU map precomputes its `sqrt_ratio` constants with several modular exponentiations; only the DST-bound `HashToField` is per call. Throws `ArithmeticException` if the result is the identity.

  It composes those three by hand rather than calling `HashToEllipticCurve.getInstance(profile, dst)`, because that facade binds the DST at construction and accepts it only as a `String` — and see [Domain separation tags](#domain-separation-tags) for why these DSTs must stay `byte[]`.

- **`ExpandMessageXmd`** — Implements `expand_message_xmd` (RFC 9380 §5.3.1). Produces a uniformly random byte string from a message and domain separation tag. Now used only by `Ristretto255GroupSpec`; the NIST curves use BouncyCastle's `XmdMessageExpansion`. Unlike that one, this implementation performs the RFC 9380 §5.3.3 oversize-DST rewrite.

  | Hash    | `bInBytes` | `rInBytes` |
  |---------|-----------|-----------|
  | SHA-256 | 32        | 64        |
  | SHA-384 | 48        | 128       |
  | SHA-512 | 64        | 128       |

  Note: SHA-384 uses `rInBytes=128`, not 104, because SHA-384 shares the 1024-bit (128-byte) block size with SHA-512.

## Hash-to-Curve Pipeline (Weierstrass)

Every step below is BouncyCastle's; `BcWeierstrassHashToCurve` sequences them. All three NIST
curves have `A != 0`, so Simplified SWU lands on the target curve directly and no isogeny is
involved.

```
message + DST
    │
    ▼  XmdMessageExpansion (SHA-256/384/512)          [BC]
    │
    ▼  HashToField  (two field elements u0, u1)       [BC]
    │
    ▼  SimplifiedShallueVanDeWoestijneMapToCurve ×2   [BC]  →  Q0, Q1
    │
    ▼  Q0 + Q1  (EC point addition)                   [BC NistCurveProcessor]
    │
    ▼  clear_cofactor (h = 1, normalises)  →  ECPoint on target curve
```

## Hash-to-Group Pipeline (ristretto255)

The ristretto255 pipeline is structurally different from the Weierstrass pipeline. It uses the Elligator MAP (RFC 9496 §4.3.4) instead of Simplified SWU, operates over Edwards25519 extended coordinates, and produces a 32-byte canonical encoding instead of a compressed SEC1 point.

```
message + DST
    │
    ▼  ExpandMessageXmd (SHA-512, 64 bytes)
    │
    ▼  split into two 32-byte halves
    │
    ▼  mask bit 255, decode little-endian mod p  →  u0, u1
    │
    ▼  Elligator MAP  ×2  →  Q0, Q1  (extended Edwards coordinates)
    │
    ▼  Q0 + Q1  (Edwards point addition)
    │
    ▼  ristretto255 encode  →  32-byte canonical encoding
```

## Ristretto255 vs Weierstrass Curves

The `Ristretto255GroupSpec` differs from `WeierstrassGroupSpecImpl` in several fundamental ways:

| Aspect | Weierstrass (P-256/P-384/P-521) | Ristretto255 |
|---|---|---|
| **Curve type** | Short Weierstrass: `y² = x³ + ax + b` | Twisted Edwards: `-x² + y² = 1 + dx²y²` (Edwards25519) |
| **Group construction** | Points on the curve directly | Quotient group over Edwards25519 (RFC 9496) |
| **Underlying library** | BouncyCastle `ECPoint` | Pure `BigInteger` arithmetic (no BouncyCastle EC) |
| **Element encoding** | Compressed SEC1 (33/49/67 bytes) | Canonical ristretto255 encoding (32 bytes) |
| **Scalar encoding** | Big-endian | Little-endian |
| **Hash-to-group map** | Simplified SWU (RFC 9380 §6.6.2) | Elligator MAP (RFC 9496 §4.3.4) |
| **Hash algorithm** | SHA-256 / SHA-384 / SHA-512 | SHA-512 only |
| **Point arithmetic** | BouncyCastle affine/projective | Extended coordinates (X, Y, Z, T) where T = XY/Z |
| **Cofactor** | 1 (prime-order curves) | Cofactor handled by ristretto255 abstraction |
| **Identity** | EC point at infinity | All-zeros 32-byte encoding |

Key implications for callers:
- `serializeScalar()` returns **little-endian** bytes for ristretto255 vs **big-endian** for Weierstrass. Code that manually interprets scalar bytes must account for this.
- `elementSize()` returns 32 for ristretto255, matching `Nsk`. For Weierstrass curves, `elementSize()` (= `Npk`) is always larger than `Nsk`.
- The `GroupSpec` interface hides these differences behind opaque `byte[]` elements — callers that use only the interface methods are curve-agnostic.

## Test Vectors

- `BcWeierstrassHashToCurveTest` — RFC 9380 Appendix J vectors, all five messages for each NIST
  curve: **J.1.1** (P-256), **J.2.1** (P-384), **J.3.1** (P-521). Appendix J.1 is NIST P-256;
  earlier tests here cited these one section high, a numbering carried over from a pre-publication
  draft.
- `ExpandMessageXmdTest` — SHA-256/384/512 expand_message_xmd vectors (RFC 9380 Appendix K.1 and
  K.2, the latter covering the oversize-DST rewrite).
- `Ristretto255GroupSpecTest` — RFC 9496 generator encoding, identity, group order, encode/decode round-trips, scalar multiply, hashToGroup/hashToScalar determinism, addition commutativity, invalid encoding rejection.
