package com.codeheadsystems.rfc.oprf.model;

import java.io.Serializable;
import java.math.BigInteger;

/**
 * The type Server processor detail.
 */
public record ServerProcessorDetail(BigInteger masterKey, String processorIdentifier) implements Serializable {
}
