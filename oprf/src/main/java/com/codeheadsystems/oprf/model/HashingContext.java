package com.codeheadsystems.oprf.model;

import java.math.BigInteger;

public record HashingContext(String requestId, BigInteger blindingFactor, byte[] input) {
}
