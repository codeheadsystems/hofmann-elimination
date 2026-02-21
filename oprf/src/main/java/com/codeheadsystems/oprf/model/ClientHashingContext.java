package com.codeheadsystems.oprf.model;

import java.math.BigInteger;

public record ClientHashingContext(String requestId, BigInteger blindingFactor, byte[] input) {
}
