package com.codeheadsystems.hofmann.server.model;

import java.io.Serializable;
import java.math.BigInteger;

public record ProcessorDetail(BigInteger masterKey, String processorIdentifier) implements Serializable {
}
