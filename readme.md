# the Hofmann Elimination

## Purpose

This project provides a protocol to create consistent, 
reusable identifier across multiple clients without sharing the
key data used to make up that identifier. This results in an identifier that can 
be used with services without those services knowing the origins of the data used. 
Useful when that data is based on information one does not want to expose
outside of the owning client. This makes uses of OPRF (Oblivious Pseudorandom Function) 
and hash-to-curve techniques to achieve this goal.

Note that OPRF is extended to limit the ability of the service 
to compute the same blinded point for different clients. This allows for multiple 
clients to use the same input text and get the same output, but without the service 
being able to link those outputs together. It also reduces the ability to brute-force 
attack the server secret key from just the data transmitted between client and server.

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
Client                          Service
────────                        ───────
1. P = HashToCurve(text)
2. Q = kᵢ · P · r
3. Send Q  ─────────────────►   R = (s/kᵢ) · Q
           ◄─────────────────   R = s · P · r
4. U = r⁻¹ · R = s · P
5. idenentityKey = BLAKE3(U)
``` 

## Details for each step

1. The client takes the input text and applies a hash-to-curve function to derive a point `P` on the elliptic curve.
2. The client computes the blinded point `Q` by multiplying `P` with their client key `kᵢ` and a random blinding factor `r`.
3. The client sends the blinded point `Q` to the service. The service computes `R` by multiplying `Q` with the master key `s` and divided by the customer's key `kᵢ`. This effectively cancels out the customer's key, resulting in `R = s · P · r`.
4. The client receives `R` and unblinds it by multiplying with the inverse of the blinding factor `r`, yielding `U = s·P`.
5. Finally, the client can derive a consistent identity key from `U` using the hash function BLAKE3.

## Useful classes

- `Client` : Shows in detail what the client is doing for the protocol.
- `Server` : The API requirements for a basic system to allow for clients to create new keys.
- `ServerImpl` : Naive implementation that implements the protocol in a basic way.
- `Curve` : Default behavior needed from any Curve implementation. Uses Bouncy Castle as that should be C# compatible.
- `RoundTripTest` : Examples of how it works and to verify the code is sound.

# References

## OPAQUE / aPAKE
The origins of the OPAQUE Augmented Password-Authenticated Key Exchange (aPAKE) 
Protocol protocol is largely what this project is based on. 
This protocol allows two parties to cooperate to securely compute a pseudorandom function
over an insecure channel without revealing the input to the other party.
The OPRF is a key component of the OPAQUE protocol, as it allows the client to 
compute a blinded version of the password without revealing it to the server. 
- [Original Paper](https://eprint.iacr.org/2018/163.pdf)
- [Password-authenticated key exchange - Wikipedia](https://en.wikipedia.org/wiki/Password-authenticated_key_exchange)
- [RFC 9807](https://www.rfc-editor.org/rfc/rfc9807.html)

## OPRF
Oblivious Pseudorandom Function (OPRF) is a cryptographic mechanism that allows 
one party (the client) to compute a pseudorandom function on an input without 
revealing the input to the other party (the server). The server holds a secret 
key that is used to compute the pseudorandom function, but it does not learn 
anything about the client's input. This is used for things like password hashing 
and secure multi-party computation.
- [Oblivious Pseudorandom Function - Wikipedia](https://en.wikipedia.org/wiki/Oblivious_pseudorandom_function)
- [RFC 9497](https://www.rfc-editor.org/rfc/rfc9497.html)

## Hash-to-Curve
Hash-to-curve is a technique used in elliptic curve cryptography to map arbitrary 
input data (such as a string) to a point on an elliptic curve. 
Protocols like OPRF uses this technique to derive a point on the curve from the 
input text. The hash-to-curve process ensures that the resulting point is 
uniformly distributed on the curve. That uniform distribution is needed for security applications.
- [RFC 9380](https://www.rfc-editor.org/rfc/rfc9380.html)

## Origins of the name

The [Hofmann Elimination](https://en.wikipedia.org/wiki/Hofmann_elimination) is a chemical reaction that involves the elimination of a anime to produce an alkene. This reaction is named after the German chemist August Wilhelm von Hofmann, who first described it in the 19th century. The Hofmann elimination is often used to synthesize alkenes from amines. It does this by treating the quaternary ammonium salt with a strong base, such as sodium hydroxide, which leads to the elimination of the ammonium group and the formation of an alkene. The reaction is typically carried out under heat to facilitate the elimination process.

Unlike other elimination reactions, the Hofmann elimination produces the least substituted alkene as the major product, which is a result of the steric hindrance around the quaternary ammonium salt. This makes it a useful reaction for synthesizing specific alkenes that may be difficult to obtain through other methods.
