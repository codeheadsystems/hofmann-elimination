# Ristretto255 Implementation Notes

This document captures what was learned during an incomplete implementation attempt
of the `ristretto255-SHA512` OPRF cipher suite (RFC 9497 §4.4). Use it as a guide
when resuming the work.

## Background

Ristretto255 is a prime-order group built on Edwards25519 (the same curve as Ed25519).
It uses equivalence classes to produce a clean prime-order group (no cofactor issues)
with a canonical 32-byte encoding. See [RFC 9496](https://www.rfc-editor.org/rfc/rfc9496).

The OPRF suite identifier is `ristretto255-SHA512` and it is defined in RFC 9497 §4.4.

---

## Relevant RFCs and References

- **RFC 9496** — The ristretto255 and decaf448 Groups (encoding/decoding, arithmetic)
- **RFC 9380 Appendix B** — `hash_to_ristretto255` (map_to_ristretto255 via Elligator)
- **RFC 9497 §4.4** — OPRF suite ristretto255-SHA512
- **CFRG PoC test vectors**: `github.com/cfrg/draft-irtf-cfrg-voprf` → `poc/vectors/allVectors.json`
  - Suite identifier: `ristretto255-SHA512`
  - Seed: `a3a3...a3` (32 bytes), Info: `"test key"`

---

## Architecture: Where to Add It

The `GroupSpec` interface (in `rfc9380/`) is the extension point. A new
`Ristretto255GroupSpec` class implementing `GroupSpec` is all that's needed for
the OPRF layer — no other files need to change. Once it exists:

1. Add `Ristretto255GroupSpec.INSTANCE` to `OprfCipherSuite.buildRistretto255Sha512()`
2. Add `RISTRETTO255_SHA512` constant to `OprfCipherSuite`
3. Add `Ristretto255Sha512` nested test class to `OprfVectorsTest`

The test vectors and test structure were already written and are preserved below.

---

## Key Constants (Verified Correct)

All constants are in `GF(p)` where `p = 2^255 - 19`.

```
D = -121665 * modInverse(121666, p) mod p
SQRT_M1 = 2^((p-1)/4) mod p     (= sqrt(-1))
```

**INVSQRT_A_MINUS_D** = `1 / sqrt(-(1+d))` (since a = -1 on Edwards25519)
- Computed as: `sqrtRatioM1(1, p - (1+d))[1]`  (note: `-(1+d)` = `p - (1+d)`)
- Canonical value: `54469307008909316920995813868745141605393597292927456921205312896311721017578`
- This value has LSB=0 (even/"positive"), so `ctabs()` result is correct as-is

**SQRT_AD_MINUS_ONE** = `sqrt(-(d+1))` (the "negative"/odd square root)
- Computed as the NEGATION of `sqrtRatioM1(p-d-1, 1)[1]`
  - i.e., `p - sqrtRatioM1(p-d-1, 1)[1]`
  - Because `sqrtRatioM1` returns `ctabs()` which gives the even root (LSB=0),
    but the canonical constant requires the odd root (LSB=1)
- Canonical value: `25063068953384623474111414158702152701244531502492656460079210482610430750235`
- This value has LSB=1 (odd/"negative")

**Group order** L = `2^252 + 27742317777372353535851937790883648493`

---

## Critical Implementation Details

### hashToScalar: Use Little-Endian
Ristretto255 uses **little-endian** scalar encoding throughout (per RFC 9496 convention).
The P-256/P-384/P-521 suites use big-endian (OS2IP). This is a per-suite difference.

```java
// CORRECT for ristretto255:
byte[] uniformBytes = XMD.expand(msg, dst, 64);
return decodeLE32(uniformBytes).mod(L);  // little-endian!

// WRONG (would be correct for Weierstrass suites):
return new BigInteger(1, uniformBytes).mod(L);  // big-endian
```

Test: `testDeriveKeyPair` was passing with this fix in place.

### decodeRistretto255: v-sign
In the decode algorithm (RFC 9496 §4.3.3), `v = a*d*u1^2 - u2^2`.
With `a = -1`: `v = -d*u1^2 - u2^2`.

The bug that was present (and fixed): computing `d*u1^2 - u2^2` instead of `-d*u1^2 - u2^2`.

```java
// CORRECT:
BigInteger dU1sq = D.multiply(u1).mod(P).multiply(u1).mod(P);
BigInteger v = P.subtract(dU1sq).subtract(u2sq).mod(P);  // -d*u1^2 - u2^2
```

### hashToGroup: 128-byte expand, big-endian field elements
RFC 9380 Appendix B says to expand to 128 bytes, split into two 64-byte halves,
and interpret each half as a **big-endian** integer mod p (standard OS2IP), then
apply the Elligator map to each, add the two points, and encode.

Note: the little-endian convention is specific to *scalars*, not field elements
for hash-to-group.

---

## SQRT_RATIO_M1 Function (p ≡ 5 mod 8)

Based on RFC 9380 §F.2.1:

```
r = u*v^3 * (u*v^7)^((p-5)/8)
check = v * r^2
correct_sign: check == u
flipped_sign: check == -u  (→ r_prime = SQRT_M1 * r is the actual sqrt)
wasSquare = correct_sign OR flipped_sign
root = r_prime if flipped_sign, else r
return [wasSquare, ctabs(root)]
```

When `wasSquare = false` (neither case), `ctabs(SQRT_M1 * r)` is returned.
This is a valid `sqrt(SQRT_M1 * u/v)` (useful for the Elligator map but not a
true square root of u/v).

---

## Known Remaining Bug: encodeRistretto255

At the time of abandoning the implementation, `encodeRistretto255` was producing
wrong output. Specifically:

- `scalarMultiplyGenerator(1)` returned `d6941cb684770ac09340d0ae4657eb566f819db316073a36b3884ff938516d7a`
  instead of the expected base point `e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76`
- `hashToGroup(0x00, dst)` produced `8a2536b7...` which failed round-trip decoding

Debug showed `sqrtRatioM1 wasSquare = 0` for `u1 * u2^2` when encoding the
Edwards25519 base point (X:Y:Z:T = Bx:By:1:Bx*By). This is unexpected since
the base point is a valid curve point; `u1 * u2^2` should be a perfect square.

The encode algorithm (RFC 9496 §4.3.2) being implemented:
```
u1 = (Z+Y)*(Z-Y)
u2 = X*Y
(was_square, invsqrt) = SQRT_RATIO_M1(1, u1*u2^2)
den1 = invsqrt * u1
den2 = invsqrt * u2
z_inv = den1 * den2 * T     ← NOTE: T here is the extended coordinate T=X*Y/Z (projective)
rotate = is_negative(T * z_inv)
if rotate: X = Y*SQRT_M1, Y = X*SQRT_M1, z = den1 * INVSQRT_A_MINUS_D
else:       z = den2
if is_negative(X * z_inv): Y = -Y
s = ctabs(z * (Z - Y))
```

Likely root cause hypotheses to investigate:
1. The SQRT_RATIO_M1 function may have a subtle sign issue when `check ≡ -u` (flipped case)
   that causes it to return a root of `SQRT_M1 * u/v` rather than `u/v` for certain inputs
2. The Z coordinate handling when Z ≠ 1 (for intermediate points from mapToRistretto255
   or scalarMul) may require different treatment than for the affine base point
3. The addition formula or doubling formula in `addPoints`/`doublePoint` may have
   a sign error in the `a=-1` adaption

### Recommended Debug Approach
1. Decode the known-valid base point encoding `e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76`
   → verify decode works correctly (returns X, Y, Z=1, T=X*Y)
2. Re-encode the decoded point → verify we get back the same bytes (round-trip test)
3. If round-trip fails: step through encode line by line with concrete numbers,
   checking against a reference implementation (e.g., libsodium, dalek-cryptography)
4. Test `addPoints` with known vectors from RFC 9496 or the ristretto255 test suite

---

## Test Vectors

From `poc/vectors/allVectors.json` in `github.com/cfrg/draft-irtf-cfrg-voprf`:

```
Suite:   ristretto255-SHA512, mode=0 (OPRF)
Seed:    a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3
Info:    7465737420 6b6579  ("test key")
skSm:    5ebcea5ee37023ccb9fc2d2019f9d7737be85591ae8652ffa9ef0f4d37063b0e  (LE)

HashToGroup DST:
  48617368546f47726f75702d4f50524656312d002d72697374726574746f3235352d534841353132

Vector 1:
  Input:            00
  Blind (LE):       64d37aed22a27f5191de1c1d69fadb899d8862b58eb4220029e036ec4c1f6706
  BlindedElement:   609a0ae68c15a3cf6903766461307e5c8bb2f95e7e6550e1ffa2dc99e412803c
  EvalElement:      7ec6578ae5120958eb2db1745758ff379e77cb64fe77b0b2d8cc917ea0869c7e
  Output:           527759c3d9366f277d8c6020418d96bb393ba2afb20ff90df23fb7708264e2f3
                    ab9135e3bd69955851de4b1f9fe8a0973396719b7912ba9ee8aa7d0b5e24bcf6

Vector 2:
  Input:            5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a  (17 bytes of 0x5a)
  Blind (LE):       64d37aed22a27f5191de1c1d69fadb899d8862b58eb4220029e036ec4c1f6706
  BlindedElement:   da27ef466870f5f15296299850aa088629945a17d1f5b7f5ff043f76b3c06418
  EvalElement:      b4cbf5a4f1eeda5a63ce7b77c7d23f461db3fcab0dd28e4e17cecb5c90d02c25
  Output:           f4a74c9c592497375e796aa837e907b1a045d34306a749db9f34221f7e750cb4
                    f2a6413a6bf6fa5e19ba6348eb673934a722a7ede2e7621306d18951e7cf2c73
```

Note: All ristretto255 element encodings are 32 bytes. All scalars are 32 bytes little-endian.

---

## Reference Implementations

For comparison during debugging, these open-source implementations of ristretto255 are useful:
- **dalek-cryptography/curve25519-dalek** (Rust): canonical reference, well-commented
- **libsodium**: C implementation, includes ristretto255 since 1.0.18
- **ristretto.group** (Python): pure Python, easy to read
