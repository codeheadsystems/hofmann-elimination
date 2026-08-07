package com.codeheadsystems.rfc.oprf.rfc9497.proof;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.codeheadsystems.rfc.oprf.rfc9497.CurveHashSuite;
import com.codeheadsystems.rfc.oprf.rfc9497.OprfCipherSuite;
import com.codeheadsystems.rfc.oprf.rfc9497.OprfMode;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import org.bouncycastle.util.encoders.Hex;

/**
 * Loads the RFC 9497 Appendix A test vectors from {@code rfc9497/vectors.json}.
 * <p>
 * The JSON was transcribed mechanically from the published RFC text rather than vendored from the
 * CFRG proof-of-concept repository. The PoC is an unpinned draft artifact and carries decaf448
 * vectors this module has no suite for; the RFC is the normative document. Transcription had to
 * handle two traps in the text format: hex values wrap mid-value across lines, so they must be
 * de-wrapped by column rather than by whitespace, and batch entries are comma-separated lists that
 * can wrap in the middle of an entry. Every value was length-checked against the suite's Ns and Ne
 * on extraction, and the batch entry counts against the declared batch size.
 * <p>
 * Note the field is spelled {@code EvaluationElement}. Appendix A's prose says "EvaluatedElement"
 * exactly once; no actual vector uses that spelling, so a parser keyed on the prose would silently
 * find nothing.
 */
final class Rfc9497Vectors {

  private static final Map<String, CurveHashSuite> SUITES = Map.of(
      "ristretto255-SHA512", CurveHashSuite.RISTRETTO255_SHA512,
      "P256-SHA256", CurveHashSuite.P256_SHA256,
      "P384-SHA384", CurveHashSuite.P384_SHA384,
      "P521-SHA512", CurveHashSuite.P521_SHA512);

  private static final JsonNode ROOT = load();

  private Rfc9497Vectors() {
  }

  private static JsonNode load() {
    try (InputStream in = Rfc9497Vectors.class.getResourceAsStream("/rfc9497/vectors.json")) {
      if (in == null) {
        throw new IllegalStateException("rfc9497/vectors.json is not on the test classpath");
      }
      return new ObjectMapper().readTree(in);
    } catch (IOException e) {
      throw new IllegalStateException("Could not read rfc9497/vectors.json", e);
    }
  }

  /**
   * One Appendix A test vector, with its suite and server key material.
   *
   * @param suiteName  the RFC's name for the suite, e.g. "P256-SHA256"
   * @param curve      the corresponding suite enum
   * @param mode       the protocol mode
   * @param number     the vector's number within its section, 1-based
   * @param batchSize  the declared batch size
   * @param seed       the key-derivation seed
   * @param keyInfo    the key-derivation info
   * @param skSm       the expected serialized server secret key
   * @param pkSm       the expected serialized server public key, null in base mode
   * @param fields     the vector's remaining fields, hex-encoded and comma-separated for batches
   */
  record Vector(String suiteName,
                CurveHashSuite curve,
                OprfMode mode,
                int number,
                int batchSize,
                byte[] seed,
                byte[] keyInfo,
                byte[] skSm,
                byte[] pkSm,
                Map<String, String> fields) {

    /** Builds the cipher suite this vector applies to. */
    OprfCipherSuite suite() {
      return OprfCipherSuite.builder().withSuite(curve).withMode(mode).build();
    }

    /** A single-valued field, decoded from hex. */
    byte[] bytes(String field) {
      String value = fields.get(field);
      if (value == null) {
        throw new IllegalArgumentException("Vector has no field " + field);
      }
      return Hex.decode(value);
    }

    /** A batch field, split on commas and decoded. */
    byte[][] list(String field) {
      String value = fields.get(field);
      if (value == null) {
        throw new IllegalArgumentException("Vector has no field " + field);
      }
      return Arrays.stream(value.split(",")).map(Hex::decode).toArray(byte[][]::new);
    }

    boolean has(String field) {
      return fields.containsKey(field);
    }

    @Override
    public String toString() {
      return suiteName + " " + mode + " vector " + number + " (batch " + batchSize + ")";
    }
  }

  /** Every vector for the given mode, across all four suites. */
  static List<Vector> forMode(OprfMode mode) {
    List<Vector> out = new ArrayList<>();
    ROOT.fieldNames().forEachRemaining(suiteName -> {
      JsonNode section = ROOT.get(suiteName).get(mode.name());
      if (section == null) {
        return;
      }
      JsonNode keys = section.get("keys");
      JsonNode vectors = section.get("vectors");
      for (int i = 0; i < vectors.size(); i++) {
        JsonNode v = vectors.get(i);
        Map<String, String> fields = new java.util.LinkedHashMap<>();
        v.fieldNames().forEachRemaining(f -> {
          if (!"batchSize".equals(f)) {
            fields.put(f, v.get(f).asText());
          }
        });
        out.add(new Vector(
            suiteName,
            SUITES.get(suiteName),
            mode,
            i + 1,
            v.get("batchSize").asInt(),
            Hex.decode(keys.get("Seed").asText()),
            Hex.decode(keys.get("KeyInfo").asText()),
            Hex.decode(keys.get("skSm").asText()),
            keys.has("pkSm") ? Hex.decode(keys.get("pkSm").asText()) : null,
            fields));
      }
    });
    if (out.isEmpty()) {
      throw new IllegalStateException("No vectors found for mode " + mode);
    }
    return out;
  }
}
