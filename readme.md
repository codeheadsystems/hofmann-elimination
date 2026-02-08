# the Hofmann Elimination

## Purpose

This project is an implementation of the the OPRF ([Oblivious Pseudo-Random Function](https://en.wikipedia.org/wiki/Oblivious_pseudorandom_function)) protocol to create consistent, reusable keys across multiple clients without sharing the
information used to create the key. This results in an identifier that can be used with services without those services knowing the origins of the key. Useful when
the identifier is based on information to hide from the service or even other clients.

# Protocol

The protocol relies on the following data types:
- `P`: A point on an elliptic curve derived from the input text using a hash-to-curve function.
- `kᵢ`: A secret key unique to each client `i`.
- `r`: A random blinding factor chosen by the client to ensure that the blinded point `Q` is different for each submission, even for the same input.
- `Q`: The blinded point computed by the client as `Q = kᵢ · P · r`.
- `s`: A master secret key held by the service.
- `R`: The blinded result computed by the service as `R = (s/kᵢ) · Q = s · P · r`.
- `U`: The unblinded result computed by the client as `U = r⁻¹ · R = s·P`.

The protocol flow is as follows:

```
Client                           Service
────────                         ───────
1. P = HashToCurve(text)
2. Q = kᵢ · P · r
3. Send Q  ──────────────────►   R = (s/kᵢ) · Q
           ◄─────────────────    R = s · P · r
4. U = r⁻¹ · R = s·P
5. idenentityKey = BLAKE3(U)
``` 

## Details for each step

1. The client takes the input text and applies a hash-to-curve function to derive a point `P` on the elliptic curve.
2. The client computes the blinded point `Q` by multiplying `P` with their client key `kᵢ` and a random blinding factor `r`.
3. The client sends the blinded point `Q` to the service. The service computes `R` by multiplying `Q` with the master key `s` and divided by the customer's key `kᵢ`. This effectively cancels out the customer's key, resulting in `R = s · P · P`.
4. The client receives `R` and unblinds it by multiplying with the inverse of the blinding factor `r`, yielding `U = s·P`.
5. Finally, the client can derive a consistent identity key from `U` using the hash function BLAKE3.

# References

## OPRF

- [Oblivious Pseudorandom Function - Wikipedia](https://en.wikipedia.org/wiki/Oblivious_pseudorandom_function)
- [RFC 9497](https://www.rfc-editor.org/rfc/rfc9497.html)

## Hash-to-Curve
- [RFC 9380](https://www.rfc-editor.org/rfc/rfc9380.html)

## Origins of the name

The [Hofmann Elimination](https://en.wikipedia.org/wiki/Hofmann_elimination) is a chemical reaction that involves the elimination of a anime to produce an alkene. This reaction is named after the German chemist August Wilhelm von Hofmann, who first described it in the 19th century. The Hofmann elimination is often used to synthesize alkenes from amines. It does this by treating the quaternary ammonium salt with a strong base, such as sodium hydroxide, which leads to the elimination of the ammonium group and the formation of an alkene. The reaction is typically carried out under heat to facilitate the elimination process.

Unlike other elimination reactions, the Hofmann elimination produces the least substituted alkene as the major product, which is a result of the steric hindrance around the quaternary ammonium salt. This makes it a useful reaction for synthesizing specific alkenes that may be difficult to obtain through other methods.
