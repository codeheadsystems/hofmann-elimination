package com.codeheadsystems.rfc.oprf.manager;

import static org.assertj.core.api.Assertions.assertThat;

import com.codeheadsystems.rfc.oprf.model.BlindedRequest;
import com.codeheadsystems.rfc.oprf.model.EvaluatedResponse;
import com.codeheadsystems.rfc.oprf.model.ServerProcessorDetail;
import com.codeheadsystems.rfc.oprf.rfc9497.CurveHashSuite;
import com.codeheadsystems.rfc.oprf.rfc9497.OprfCipherSuite;
import java.math.BigInteger;
import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.Test;

class OprfServerManagerTest {

  private final OprfCipherSuite suite = OprfCipherSuite.builder()
      .withSuite(CurveHashSuite.P256_SHA256).build();

  @Test
  void process_returnsValidHexPoint() {
    BigInteger serverKey = suite.deriveKeyPair("server-key".getBytes(), new byte[0]);
    ServerProcessorDetail detail = new ServerProcessorDetail(serverKey, "proc-1");
    OprfServerManager manager = new OprfServerManager(suite, () -> detail);

    // Create a valid blinded point (k * G)
    BigInteger k = BigInteger.valueOf(42);
    byte[] point = suite.groupSpec().scalarMultiplyGenerator(k);
    String hexPoint = Hex.toHexString(point);

    BlindedRequest req = new BlindedRequest(hexPoint, "req-1");
    EvaluatedResponse resp = manager.process(req);

    assertThat(resp.processIdentifier()).isEqualTo("proc-1");
    assertThat(resp.evaluatedPoint()).isNotNull().isNotBlank();
    byte[] evaluated = Hex.decode(resp.evaluatedPoint());
    // Should be a valid compressed SEC1 point
    assertThat(evaluated).hasSize(33);
    assertThat(evaluated[0]).isIn((byte) 0x02, (byte) 0x03);
  }

  @Test
  void process_isDeterministic() {
    BigInteger serverKey = BigInteger.valueOf(77);
    ServerProcessorDetail detail = new ServerProcessorDetail(serverKey, "proc-1");
    OprfServerManager manager = new OprfServerManager(suite, () -> detail);

    byte[] point = suite.groupSpec().scalarMultiplyGenerator(BigInteger.TEN);
    BlindedRequest req = new BlindedRequest(Hex.toHexString(point), "req-1");

    EvaluatedResponse r1 = manager.process(req);
    EvaluatedResponse r2 = manager.process(req);

    assertThat(r1.evaluatedPoint()).isEqualTo(r2.evaluatedPoint());
  }
}
