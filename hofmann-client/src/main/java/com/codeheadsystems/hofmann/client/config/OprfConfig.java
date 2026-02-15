package com.codeheadsystems.hofmann.client.config;

import com.codeheadsystems.oprf.curve.Curve;
import com.codeheadsystems.oprf.rfc9380.HashToCurve;

public record OprfConfig(Curve curve, HashToCurve hashToCurve) {

  public OprfConfig() {
    this(Curve.P256_CURVE, HashToCurve.forP256());
  }
}
