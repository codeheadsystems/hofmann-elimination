package com.codeheadsystems.hofman;

import java.util.function.Function;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.ec.CustomNamedCurves;
import org.bouncycastle.crypto.params.ECDomainParameters;

public interface Curve {

  String DEFAULT_CURVE_NAME = "secp256k1";
  ECDomainParameters DEFAULT_CURVE = FACTORY().apply(DEFAULT_CURVE_NAME);

  static Function<String, ECDomainParameters> FACTORY() {
    return name -> {
      X9ECParameters params = CustomNamedCurves.getByName(name);
      if (params == null) {
        throw new IllegalArgumentException("Unsupported curve: " + name);
      }
      return new ECDomainParameters(
          params.getCurve(),
          params.getG(),
          params.getN(),
          params.getH()
      );
    };
  }

}
