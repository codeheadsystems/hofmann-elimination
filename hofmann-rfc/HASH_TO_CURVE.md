# Elliptic Curve Hashing

Java 21 implementation of **RFC 9380 — Hashing to Elliptic Curves**, built on 
BouncyCastle.

This security primitive provides for a deterministic way to generate a point on
an elliptic curve from arbitrary input data. It operates as a one-way hashing 
function making it difficult to reverse. This primitive is used for other cryptographic
protocols.

## Supported Curves

### Weierstrass curves

| Curve      | Hash    | Suite constant                        | RFC 9380 section |
|------------|---------|---------------------------------------|------------------|
| P-256      | SHA-256 | `WeierstrassGroupSpec.P256_SHA256`    | §8.2             |
| P-384      | SHA-384 | `WeierstrassGroupSpec.P384_SHA384`    | §8.3             |
| P-521      | SHA-512 | `WeierstrassGroupSpec.P521_SHA512`    | §8.4             |
| secp256k1  | SHA-256 | `WeierstrassGroupSpec.forSecp256k1()` | §8.7             |

### Non-Weierstrass curves

| Curve         | Hash    | Suite constant                    | Specification    |
|---------------|---------|-----------------------------------|------------------|
| ristretto255  | SHA-512 | `Ristretto255GroupSpec.INSTANCE`  | RFC 9496 / 9380 Appendix B |

## Package Structure

### `curve/`

Low-level curve wrappers and encoding utilities.

- **`Curve`** — Immutable record wrapping BouncyCastle `ECDomainParameters`. Exposes the curve field, generator `G`, group order `n`, and cofactor `h`. Static constants: `P256_CURVE`, `P384_CURVE`, `P521_CURVE`, `SECP256K1_CURVE`.

- **`OctetStringUtils`** — Encoding primitives shared across the codebase:
  - `I2OSP(int, int)` — Integer to octet string (RFC 8017)
  - `toHex(ECPoint)` / `toEcPoint(Curve, String)` — Compressed SEC1 hex encoding/decoding with point validation
  - `concat(byte[]...)` — Byte array concatenation

### `rfc9380/`

Full hash-to-curve pipeline from RFC 9380 Section 3.

- **`GroupSpec`** — Interface abstracting a cryptographic group over serialized `byte[]` elements. Methods: `hashToGroup`, `hashToScalar`, `scalarMultiply`, `scalarMultiplyGenerator`, `serializeScalar`, `groupOrder`, `elementSize`. All group elements cross the interface as opaque `byte[]`, making it agnostic to the underlying curve type.

- **`WeierstrassGroupSpecImpl`** — `GroupSpec` implementation for Weierstrass curves. Delegates to `HashToCurve` for hashing, serializes points as compressed SEC1 (33 bytes for P-256, 49 for P-384, 67 for P-521), and scalars as big-endian. Validates deserialized points against the curve and rejects the identity element. Uses BouncyCastle `ECPoint` internally.

- **`Ristretto255GroupSpec`** — `GroupSpec` implementation for the ristretto255 group (RFC 9496), built on Edwards25519. See [Ristretto255 vs Weierstrass](#ristretto255-vs-weierstrass-curves) for how it differs from the Weierstrass implementation.

- **`HashToCurve`** — Orchestrates the four-step hash_to_curve pipeline (RFC 9380 §3). Factory methods: `forP256()`, `forP384()`, `forP521()`, `forSecp256k1()`.

- **`HashToField`** — Implements `hash_to_field` (RFC 9380 §5.3): expands a message to uniform bytes via `ExpandMessageXmd`, then reduces modulo the field prime. Factory methods for both the base field and scalar field of each supported curve.

- **`ExpandMessageXmd`** — Implements `expand_message_xmd` (RFC 9380 §5.3.1). Produces a uniformly random byte string from a message and domain separation tag.

  | Hash    | `bInBytes` | `rInBytes` |
  |---------|-----------|-----------|
  | SHA-256 | 32        | 64        |
  | SHA-384 | 48        | 128       |
  | SHA-512 | 64        | 128       |

  Note: SHA-384 uses `rInBytes=128`, not 104, because SHA-384 shares the 1024-bit (128-byte) block size with SHA-512.

- **`SimplifiedSWU`** — Implements the Simplified SWU map (RFC 9380 §6.6.2, Appendix F.2). Maps a field element to a candidate curve point. For curves with `A != 0` (P-256, P-384, P-521) the result is a point on the target curve directly. For secp256k1 (`A = 0`) the result is a point on an isogenous curve.

- **`IsogenyMap`** — Applies the 3-isogeny from the auxiliary secp256k1 curve `E'` to secp256k1 (RFC 9380 §E.1). Only used for the secp256k1 pipeline; P-256/P-384/P-521 do not need an isogeny.

## Hash-to-Curve Pipeline (Weierstrass)

```
message + DST
    │
    ▼  ExpandMessageXmd (SHA-256/384/512)
    │
    ▼  HashToField  (two field elements u0, u1)
    │
    ▼  SimplifiedSWU  ×2  →  (x0,y0), (x1,y1)
    │
    ▼  [IsogenyMap  ×2]   (secp256k1 only)
    │
    ▼  Q0 + Q1  (EC point addition)
    │
    ▼  normalize  →  ECPoint on target curve
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

- `P256HashToCurveTest`, `P384HashToCurveTest`, `P521HashToCurveTest` — RFC 9380 Appendix J vectors for each curve.
- `HashToCurveTest`, `ComponentTest` — secp256k1 vectors (RFC 9380 Appendix J.8).
- `ExpandMessageXmdTest` — SHA-256/384/512 expand_message_xmd vectors.
- `Ristretto255GroupSpecTest` — RFC 9496 generator encoding, identity, group order, encode/decode round-trips, scalar multiply, hashToGroup/hashToScalar determinism, addition commutativity, invalid encoding rejection.
