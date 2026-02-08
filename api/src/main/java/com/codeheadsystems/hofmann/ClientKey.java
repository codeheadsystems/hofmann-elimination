package com.codeheadsystems.hofmann;

import java.math.BigInteger;

/**
 * The client key record holds the client's unique identifier and the scalar value used in the blinding process.
 * The server knows this key as well. The scalar is used to mitigate against attacks as different clients will have
 * different scalars. Also allows for rotation as needed by policy.
 *
 * @param keyIdentifier
 * @param clientScalar
 */
public record ClientKey(String keyIdentifier, BigInteger clientScalar) {
}
