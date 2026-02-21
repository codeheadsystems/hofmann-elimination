package com.codeheadsystems.oprf.model;

import java.io.Serializable;
import java.math.BigInteger;

public record ServerProcessorDetail(BigInteger masterKey, String processorIdentifier) implements Serializable {
}
