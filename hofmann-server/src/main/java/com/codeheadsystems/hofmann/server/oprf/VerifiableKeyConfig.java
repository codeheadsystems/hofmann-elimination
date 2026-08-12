package com.codeheadsystems.hofmann.server.oprf;

import com.codeheadsystems.hofmann.model.oprf.OprfClientConfigResponse;
import com.codeheadsystems.hofmann.model.oprf.OprfModeInfo;
import com.codeheadsystems.rfc.oprf.manager.PoprfServerManager;
import com.codeheadsystems.rfc.oprf.manager.VoprfServerManager;
import com.codeheadsystems.rfc.oprf.model.VerifiableProcessorDetail;
import com.codeheadsystems.rfc.oprf.rfc9497.OprfCipherSuite;
import com.codeheadsystems.rfc.oprf.rfc9497.OprfMode;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;

/**
 * Builds the VOPRF/POPRF key material both framework adapters need from configuration.
 *
 * <p>Shared rather than written out twice. The two adapters had otherwise identical copies of
 * "parse a hex key, build a mode-specific suite, derive the detail" — the same shape that let the
 * OPAQUE field-length cap exist in one wire model and not another.
 */
public final class VerifiableKeyConfig {

  private VerifiableKeyConfig() {
  }

  /**
   * Returns whether a key is configured at all.
   *
   * @param masterKeyHex the configured value, possibly null or empty
   * @return true if a key is present
   */
  public static boolean isConfigured(final String masterKeyHex) {
    return masterKeyHex != null && !masterKeyHex.isBlank();
  }

  /**
   * Builds a mode-specific cipher suite.
   *
   * <p>A separate suite per mode is not an optimisation to skip: RFC 9497 puts the mode byte in
   * every domain-separation tag, so a base-mode suite handed to a verifiable manager computes a
   * different function under a different tag set. {@code assertMode} inside the managers refuses
   * that, which is why this exists rather than callers reusing the base suite.
   *
   * @param curveHashSuiteName the configured curve/hash suite name
   * @param mode               the RFC 9497 mode
   * @param secureRandom       the random source
   * @return the suite
   */
  public static OprfCipherSuite suiteFor(final String curveHashSuiteName,
                                         final OprfMode mode,
                                         final SecureRandom secureRandom) {
    return OprfCipherSuite.builder()
        .withSuite(curveHashSuiteName)
        .withMode(mode)
        .withRandom(secureRandom)
        .build();
  }

  /**
   * Derives the processor detail from a configured hex master key.
   *
   * <p>Parsing is done here so a malformed key fails at startup with a message naming the property,
   * rather than as {@code NumberFormatException: Zero length BigInteger} from somewhere in bean
   * construction.
   *
   * <p><strong>An empty value means the mode is disabled, on both adapters.</strong> That took
   * arranging: Spring's {@code @ConditionalOnProperty} treats a set-but-empty property as present,
   * so {@code voprf-master-key-hex:} with nothing after it used to reach this method and fail
   * startup, while Dropwizard's identically-shaped config disabled the mode and answered 404. The
   * same YAML meaning two different things across adapters is the kind of divergence a shared
   * helper is supposed to remove, so the Spring condition now tests for a non-empty value.
   * Reaching this method with an empty key is therefore a wiring bug rather than a configuration
   * one, and it says so.
   *
   * <p>A key congruent to zero is rejected by {@code VerifiableProcessorDetail.derive}, which
   * normalises through {@code validateSecretKey} — every evaluation under such a key would return
   * the identity element. Not re-checked here, so there is one place that decides it.
   *
   * @param suite               the mode-specific suite
   * @param masterKeyHex        the configured hex key
   * @param processorIdentifier the processor identifier to record in the detail
   * @param propertyName        the configuration property name, for the error message
   * @return the derived detail
   * @throws IllegalStateException if the key is absent or not valid hex
   */
  public static VerifiableProcessorDetail detailFrom(final OprfCipherSuite suite,
                                                     final String masterKeyHex,
                                                     final String processorIdentifier,
                                                     final String propertyName) {
    if (!isConfigured(masterKeyHex)) {
      throw new IllegalStateException(
          propertyName + " is empty, but this method was reached anyway — the caller should have "
              + "checked isConfigured() and disabled the mode. An empty or absent value disables "
              + "the mode on both adapters.");
    }
    final BigInteger masterKey;
    try {
      masterKey = new BigInteger(masterKeyHex.trim(), 16);
    } catch (NumberFormatException e) {
      throw new IllegalStateException(propertyName + " is not valid hex", e);
    }
    return VerifiableProcessorDetail.derive(suite, masterKey, processorIdentifier);
  }

  /**
   * Builds the {@code GET /oprf/config} response, advertising whichever verifiable modes are
   * enabled.
   *
   * <p>Here for the same reason the rest of this class is: the two adapters would otherwise each
   * decide independently what to advertise, and the failure mode of them disagreeing is a client
   * that cross-checks its pinned key successfully against one adapter and fatally against the
   * other.
   *
   * <p><strong>Returns the single-argument form when neither mode is enabled</strong>, so the
   * emitted document is byte-identical to what shipped before the {@code modes} field existed.
   * That is what keeps already-released clients — whose {@code ObjectMapper} rejects unknown
   * properties — working against an upgraded base-mode server. An empty list would not do; see
   * {@code OprfClientConfigResponse}.
   *
   * <p>What is advertised is public data only: the untweaked public key, the keying-context label
   * already present on every response, and the batch cap already discoverable by sending an
   * oversized batch. Nothing here is a secret, and nothing here is authenticated — see
   * {@code OprfModeInfo} for why a client must still pin the key out of band.
   *
   * @param cipherSuiteName the configured curve/hash suite name
   * @param voprf           the VOPRF manager, or null if the mode is disabled
   * @param poprf           the POPRF manager, or null if the mode is disabled
   * @return the config response
   */
  public static OprfClientConfigResponse clientConfigResponse(final String cipherSuiteName,
                                                              final VoprfServerManager voprf,
                                                              final PoprfServerManager poprf) {
    if (voprf == null && poprf == null) {
      return new OprfClientConfigResponse(cipherSuiteName);
    }
    final List<OprfModeInfo> modes = new ArrayList<>(2);
    if (voprf != null) {
      modes.add(new OprfModeInfo(OprfMode.VOPRF.name(), voprf.serverPublicKeyHex(),
          voprf.processorIdentifier(), voprf.maxBatchSize()));
    }
    if (poprf != null) {
      modes.add(new OprfModeInfo(OprfMode.POPRF.name(), poprf.serverPublicKeyHex(),
          poprf.processorIdentifier(), poprf.maxBatchSize()));
    }
    return new OprfClientConfigResponse(cipherSuiteName, modes);
  }
}
