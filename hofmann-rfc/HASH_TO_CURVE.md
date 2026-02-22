# Elliptic Curve Hashing

Java 21 implementation of **RFC 9380 — Hashing to Elliptic Curves**, built on 
BouncyCastle.

This security primitive provides for a deterministic way to generate a point on
an elliptic curve from arbitrary input data. It operates as a one-way hashing 
function making it difficult to reverse. This primitive is used for other cryptographic
protocols.

## Supported Curves

| Curve      | Hash    | Suite constant                        | RFC 9380 section |
|------------|---------|---------------------------------------|------------------|
| P-256      | SHA-256 | `WeierstrassGroupSpec.P256_SHA256`    | §8.2             |
| P-384      | SHA-384 | `WeierstrassGroupSpec.P384_SHA384`    | §8.3             |
| P-521      | SHA-512 | `WeierstrassGroupSpec.P521_SHA512`    | §8.4             |
| secp256k1  | SHA-256 | `WeierstrassGroupSpec.forSecp256k1()` | §8.7             |

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

- **`GroupSpec`** — Interface abstracting a cryptographic group over serialized `byte[]` elements. Methods: `hashToGroup`, `hashToScalar`, `scalarMultiply`, `scalarMultiplyGenerator`, `randomScalar`, `serializeScalar`, `groupOrder`, `elementSize`.

- **`WeierstrassGroupSpec`** — `GroupSpec` implementation for Weierstrass curves. Delegates to `HashToCurve` for hashing, serializes points as compressed SEC1 (33 bytes for P-256, 49 for P-384, 67 for P-521). Validates deserialized points against the curve and rejects the identity element.

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

## Hash-to-Curve Pipeline

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

## Test Vectors

- `P256HashToCurveTest`, `P384HashToCurveTest`, `P521HashToCurveTest` — RFC 9380 Appendix J vectors for each curve.
- `HashToCurveTest`, `ComponentTest` — secp256k1 vectors (RFC 9380 Appendix J.8).
- `ExpandMessageXmdTest` — SHA-256/384/512 expand_message_xmd vectors.
