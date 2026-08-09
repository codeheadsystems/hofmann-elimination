# Ristretto255 Implementation Notes

**Status: implemented and shipping.** `ristretto255-SHA512` is one of the four supported OPRF
cipher suites, in all three modes. The implementation is
[`Ristretto255GroupSpec`](hofmann-rfc/src/main/java/com/codeheadsystems/rfc/ellipticcurve/rfc9380/Ristretto255GroupSpec.java),
reached as `CurveHashSuite.RISTRETTO255_SHA512`, and it passes the RFC 9497 Appendix A vectors
end to end. See [OPRF.md](hofmann-rfc/OPRF.md#cipher-suites) for the suite table and
[HASH_TO_CURVE.md](hofmann-rfc/HASH_TO_CURVE.md#hash-to-group-pipeline-ristretto255) for how the
pipeline differs from the Weierstrass curves.

This document is a retrospective on why it was hard, kept because the traps are real and the
first attempt's *diagnosis of them was wrong in every specific* — which is the more useful half.

Ristretto255 is a prime-order group built on Edwards25519, using equivalence classes to give a
clean prime-order group with no cofactor issues and a canonical 32-byte encoding. It is defined
in [RFC 9496](https://www.rfc-editor.org/rfc/rfc9496); the OPRF suite is RFC 9497 **§4.1**.

> **On section numbers.** RFC 9497 orders its suites ristretto255 (§4.1), decaf448 (§4.2), P-256
> (§4.3), P-384 (§4.4), P-521 (§4.5). An earlier version of this document cited §4.4 for
> ristretto255 throughout, which is P-384. The same ordering applies to the Appendix A vectors.

---

## Why it was hard

BouncyCastle covers the three Weierstrass suites. It does not provide ristretto255, so this is
the one suite implemented as pure `BigInteger` Edwards25519 arithmetic — every field operation,
the extended-coordinate group law, the Elligator map, and the encode/decode pair, written out.

That alone is a lot of surface. What makes it *hard* rather than merely long is that almost every
way of getting it wrong still produces well-formed 32-byte output. A sign error in one branch of
the encoder yields a valid-looking encoding that simply is not the point you meant. There is no
type error, no exception, and no partial credit — you get a wrong answer that looks exactly like
a right one, and the only oracle is a test vector.

---

## The two real traps

### Scalars are little-endian; field elements in hash-to-group are not

Ristretto255 uses **little-endian** scalar encoding throughout, per RFC 9496. The P-256, P-384
and P-521 suites use big-endian (OS2IP). This is a per-suite difference, and it is the trap that
catches people first because both encodings produce a 32-byte array.

```java
// Correct for ristretto255 — hashToScalar:
byte[] uniform = XMD_SHA512.expand(msg, dst, 64);
return decodeLittleEndian(uniform).mod(L);

// Correct for the Weierstrass suites, wrong here:
return new BigInteger(1, uniform).mod(L);
```

`GroupSpec.serializeScalar` exists so callers never have to know which suite they are on — see
[HASH_TO_CURVE.md](hofmann-rfc/HASH_TO_CURVE.md), and note that `Server`'s constructor decodes a
fixed-width scalar in exactly this per-suite encoding.

**`hashToGroup` is the exception, and not in the direction the first attempt recorded.** The
shipped pipeline expands to **64** bytes, splits into two **32**-byte halves, masks bit 255 of
each, and decodes each as a **little-endian** field element mod p:

```java
byte[] uniform = XMD_SHA512.expand(msg, dst, 64);
byte[] b0 = Arrays.copyOfRange(uniform, 0, 32);
byte[] b1 = Arrays.copyOfRange(uniform, 32, 64);
b0[31] &= 0x7F;
b1[31] &= 0x7F;
BigInteger u0 = decodeLittleEndian(b0).mod(P);
```

An earlier version of this document stated the opposite under a heading reading "Critical
Implementation Details" — 128-byte expand, two 64-byte **big-endian** halves. That was never what
the code did, in the abandoned attempt or since. Follow the source.

### The two square roots have opposite parity, and both are "correct"

`INVSQRT_A_MINUS_D` and `SQRT_AD_MINUS_ONE` are square roots of related quantities, and the spec
wants a *specific* one of each pair. `sqrtRatioM1` returns `CT_ABS(...)`, which is always the even
root, so one of the two constants has to be negated after computing it. Getting this backwards
gives you a constant that is a genuine square root of the right value and still wrong.

| Constant | Value | Parity | How to derive |
|---|---|---|---|
| `INVSQRT_A_MINUS_D` = `1/sqrt(-(1+d))` | `54469307008909316920995813868745141605393597292927456921205312896311721017578` | LSB 0 (even) | `sqrtRatioM1(1, p-(1+d))[1]` directly |
| `SQRT_AD_MINUS_ONE` = `sqrt(-(d+1))` | `25063068953384623474111414158702152701244531502492656460079210482610430750235` | LSB 1 (odd) | `p - sqrtRatioM1(p-d-1, 1)[1]` — **negate** |

The other constants are unremarkable, in `GF(p)` with `p = 2^255 - 19`:

```
D              = -121665 * modInverse(121666, p) mod p
SQRT_M1        = 2^((p-1)/4) mod p            (= sqrt(-1))
ONE_MINUS_D_SQ = 1 - d^2   mod p              (NOT (1-d)^2)
D_MINUS_ONE_SQ = (d-1)^2   mod p
L              = 2^252 + 27742317777372353535851937790883648493
```

`ONE_MINUS_D_SQ` is worth its parenthesis. The first attempt hardcoded the correct value under a
comment reading `(1 - d)^2`, which is a different quantity — the value was right and the comment
was wrong, which is the shape of error that survives review. Both are now derived from `D` rather
than transcribed, so the comment cannot drift from the arithmetic again.

### `SQRT_RATIO_M1`, for reference

`p ≡ 5 (mod 8)`, so per RFC 9380 §F.2.1:

```
r = u*v^3 * (u*v^7)^((p-5)/8)
check = v * r^2
correct_sign: check == u
flipped_sign: check == -u        (→ r_prime = SQRT_M1 * r is the actual sqrt)
wasSquare = correct_sign OR flipped_sign
root = r_prime if flipped, else r
return [wasSquare, ctabs(root)]
```

When `wasSquare` is false, `ctabs(SQRT_M1 * r)` is returned: a valid `sqrt(SQRT_M1 * u/v)`, which
the Elligator map needs and which is not a square root of `u/v`.

---

## Superseded analysis: the bug that was not there

The first attempt was abandoned with a section titled **"Known Remaining Bug: encodeRistretto255"**
and three ranked root-cause hypotheses. The reported symptoms were real —
`scalarMultiplyGenerator(1)` returned `d6941cb6...` rather than the base point
`e2f2ae0a...`, and `hashToGroup(0x00)` produced output that failed to decode.

Every named suspect turned out to be innocent. Comparing that abandoned source against what
ships today:

| The note said | Actually |
|---|---|
| `encodeRistretto255` is producing wrong output | Statement-for-statement identical to the shipping version; only trailing comments differ |
| Hypothesis 1: `SQRT_RATIO_M1` has a sign issue in the flipped case | Unchanged but for an algebraic rearrangement of one comparison |
| Hypothesis 2: `Z ≠ 1` handling in encode needs different treatment | Unchanged |
| Hypothesis 3: `addPoints` / `doublePoint` have an `a = -1` sign error | Unchanged |
| Constants "Verified Correct" | Correct, and still the shipping values |
| `hashToGroup`: 128-byte expand, big-endian halves | Never true; 64-byte, little-endian, then and now |

So the confident sections were the wrong ones, and the section hedged as "likely root cause
hypotheses to investigate" pointed at three pieces of code that needed no investigation. The
encoder was not broken. What that leaves is a lesson rather than a diagnosis: with an algorithm
where every wrong answer is well-formed, a symptom localises nothing, and reasoning about which
function "must" be at fault is worth less than bisecting against a known-good vector one
operation at a time — decode a published encoding, re-encode it, and compare, before forming any
theory about why.

The debugging procedure the note closed with was sound, and is the part worth keeping:

1. Decode the known-valid base point encoding
   `e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76` and verify it returns
   `X, Y, Z=1, T=X*Y`.
2. Re-encode it and check you get the same bytes back.
3. If the round trip fails, step through encode with concrete numbers against a reference
   implementation.
4. Test `addPoints` against known vectors before trusting anything built on it.

---

## Test vectors

Vectors live in
[`hofmann-rfc/src/test/resources/rfc9497/vectors.json`](hofmann-rfc/src/test/resources/rfc9497/vectors.json)
and run through `OprfVectorsTest`, `OprfModeTest`, `VoprfVectorsTest`, `PoprfVectorsTest` and
`DleqVectorsTest`.

They are transcribed from the published RFC 9497 text, **not** vendored from the CFRG
proof-of-concept repository — that is an unpinned draft artifact, and it carries decaf448 vectors
this module has no suite for. An earlier version of this document cited
`poc/vectors/allVectors.json` as the source and inlined a copy of two vectors; the values agreed
with the RFC, but the citation pointed the reader at the source the project had decided against.
Read the vectors from the repository.

The ristretto255 suite is additionally covered by `GroupSpecArithmeticTest` for element addition,
multi-scalar accumulation, and both encodings, and by the per-suite integration tests in
`hofmann-integration-tests`.

---

## References

- **RFC 9496** — The ristretto255 and decaf448 Groups: encoding, decoding, arithmetic
- **RFC 9380 Appendix B** — `hash_to_ristretto255` via the Elligator map
- **RFC 9497 §4.1** — OPRF suite `ristretto255-SHA512`
- **RFC 8032 §5.1** — Edwards25519 parameters and the base point

Implementations useful for differential debugging: `dalek-cryptography/curve25519-dalek` (Rust,
well commented), libsodium (C, ristretto255 since 1.0.18), and `ristretto.group` (Python, short
enough to read in one sitting).
