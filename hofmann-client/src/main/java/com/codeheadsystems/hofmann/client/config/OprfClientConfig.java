package com.codeheadsystems.hofmann.client.config;

import com.codeheadsystems.hofmann.client.exceptions.OprfModeNotEnabledException;
import com.codeheadsystems.hofmann.client.exceptions.OprfPublicKeyMismatchException;
import com.codeheadsystems.hofmann.model.oprf.OprfClientConfigResponse;
import com.codeheadsystems.hofmann.model.oprf.OprfModeInfo;
import com.codeheadsystems.rfc.oprf.rfc9497.CurveHashSuite;
import com.codeheadsystems.rfc.oprf.rfc9497.OprfCipherSuite;
import com.codeheadsystems.rfc.oprf.rfc9497.OprfMode;
import java.security.MessageDigest;
import org.bouncycastle.util.encoders.DecoderException;
import org.bouncycastle.util.encoders.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Client-side OPRF configuration: the cipher suite the client will use when blinding requests and
 * unblinding responses, and — for the verifiable modes — the server public keys it has pinned.
 *
 * <p>The suite must agree with the server's, which is why {@link #fromServerConfig} exists.
 *
 * <p><strong>The pinned keys deliberately have no equivalent.</strong> {@code fromServerConfig}
 * pins nothing, and there is no code path anywhere in this class from an HTTP response into a
 * pinned key. That is the whole security property of the verifiable modes: a proof graded against
 * a key taken from the same channel that carried the proof proves nothing, because a server able
 * to choose both can produce a verifying pair for any key it likes — and RFC 9497 §7.3 notes it
 * can do that per-client, partitioning users into individually identifiable buckets. The key must
 * arrive out of band, authenticated by something other than this connection, and a reviewer should
 * be able to confirm that by reading one method.
 *
 * @param suite                   the OPRF cipher suite to use
 * @param voprfServerPublicKeyHex the pinned VOPRF server public key, hex-encoded, or null
 * @param poprfServerPublicKeyHex the pinned POPRF server public key, hex-encoded, or null. This is
 *                                the server's untweaked {@code pkS}; the tweak is derived per
 *                                request from the public input the client chooses
 */
public record OprfClientConfig(OprfCipherSuite suite,
                               String voprfServerPublicKeyHex,
                               String poprfServerPublicKeyHex) {

  private static final Logger log = LoggerFactory.getLogger(OprfClientConfig.class);

  /**
   * Instantiates a new Oprf client config.
   */
  public OprfClientConfig() {
    this(OprfCipherSuite.builder().withSuite(CurveHashSuite.P256_SHA256).build());
  }

  /**
   * Base-mode form, pinning no verifiable-mode keys.
   *
   * @param suite the OPRF cipher suite to use
   */
  public OprfClientConfig(final OprfCipherSuite suite) {
    this(suite, null, null);
  }

  /**
   * Creates an {@link OprfClientConfig} from a server-supplied config response.
   *
   * <p>Carries the cipher suite across and <strong>nothing else</strong>. In particular it does
   * not pin the public keys the response may advertise; see the class javadoc for why. A caller
   * that wants the verifiable modes follows this with {@link #withVoprfServerPublicKey} or
   * {@link #withPoprfServerPublicKey}, supplying a key it obtained some other way.
   *
   * @param cfg the server config response from GET /oprf/config
   * @return the oprf client config
   */
  public static OprfClientConfig fromServerConfig(OprfClientConfigResponse cfg) {
    return new OprfClientConfig(OprfCipherSuite.builder().withSuite(cfg.cipherSuite()).build());
  }

  /**
   * Returns a copy pinning the given VOPRF server public key.
   *
   * @param hex the server's public key, hex-encoded, obtained and authenticated out of band
   * @return a new config
   */
  public OprfClientConfig withVoprfServerPublicKey(final String hex) {
    return new OprfClientConfig(suite, hex, poprfServerPublicKeyHex);
  }

  /**
   * Returns a copy pinning the given POPRF server public key.
   *
   * @param hex the server's untweaked public key, hex-encoded, obtained out of band
   * @return a new config
   */
  public OprfClientConfig withPoprfServerPublicKey(final String hex) {
    return new OprfClientConfig(suite, voprfServerPublicKeyHex, hex);
  }

  /**
   * The configured curve and hash under RFC 9497 VOPRF mode.
   *
   * @return a VOPRF-mode suite
   */
  public OprfCipherSuite voprfSuite() {
    return suiteForMode(OprfMode.VOPRF);
  }

  /**
   * The configured curve and hash under RFC 9497 POPRF mode.
   *
   * @return a POPRF-mode suite
   */
  public OprfCipherSuite poprfSuite() {
    return suiteForMode(OprfMode.POPRF);
  }

  private OprfCipherSuite suiteForMode(final OprfMode mode) {
    return OprfCipherSuite.builder()
        .withSuite(suite.curveHashSuite())
        .withMode(mode)
        .build();
  }

  /**
   * The pinned public key for a mode, decoded.
   *
   * @param mode the mode
   * @return the decoded key, or null if none is pinned for that mode
   * @throws IllegalArgumentException if a key is pinned but is not valid hex, or if {@code mode}
   *                                  is base mode, which has no key to pin
   */
  public byte[] pinnedPublicKey(final OprfMode mode) {
    final String hex = switch (mode) {
      case VOPRF -> voprfServerPublicKeyHex;
      case POPRF -> poprfServerPublicKeyHex;
      case OPRF -> throw new IllegalArgumentException(
          "Base mode has no server public key; only VOPRF and POPRF are verifiable");
    };
    if (hex == null || hex.isBlank()) {
      return null;
    }
    try {
      return Hex.decode(hex.trim());
    } catch (DecoderException e) {
      throw new IllegalArgumentException(
          "Pinned " + mode + " server public key is not valid hex", e);
    }
  }

  /**
   * Cross-checks this config against what a server advertises, failing loudly on a disagreement.
   *
   * <p><strong>This is a diagnostic, not a security control, and must not be turned into one.</strong>
   * The config response is unauthenticated, so a hostile server can put anything in it. What it
   * cannot do is cause an <em>acceptance</em> — the only two outcomes here are "proceed with the
   * key already pinned" and "throw". Proof verification against the pinned key remains the sole
   * mechanism that makes a verifiable mode verifiable. What this buys is that a rotated key or a
   * mistyped pin surfaces once, at startup, saying what disagreed, instead of as an unexplained
   * run of {@code SecurityException: proof did not verify}.
   *
   * <p>The mode list is read as three states. Absent means the server predates the field or has no
   * verifiable mode configured — no cross-check is possible, so this logs and proceeds, leaving
   * the endpoint's 404 as the capability probe. Present and naming the mode is authoritative: a
   * key mismatch is fatal. Present and not naming the mode means the server publishes a complete
   * list and this mode is off, which fails here rather than after a wasted round trip.
   *
   * @param serverConfig the response from GET /oprf/config
   * @param mode         the mode about to be used
   * @throws OprfPublicKeyMismatchException if the suites disagree, or the advertised key differs
   *                                        from the pinned one
   * @throws OprfModeNotEnabledException    if the server publishes a mode list without this mode
   */
  public void assertMatches(final OprfClientConfigResponse serverConfig, final OprfMode mode) {
    if (serverConfig == null) {
      return;
    }
    if (serverConfig.cipherSuite() != null
        && !serverConfig.cipherSuite().equalsIgnoreCase(suite.curveHashSuite().name())) {
      throw new OprfPublicKeyMismatchException(
          "Cipher suite mismatch: this client is configured for " + suite.curveHashSuite().name()
              + " but the server reports " + serverConfig.cipherSuite()
              + ". Every domain-separation tag differs between suites, so nothing would verify.");
    }
    if (serverConfig.modes() == null) {
      log.info("Server does not advertise verifiable modes, so the pinned {} key cannot be "
          + "cross-checked. The pin is still enforced by proof verification.", mode);
      return;
    }
    final OprfModeInfo advertised = serverConfig.modes().stream()
        .filter(m -> mode.name().equalsIgnoreCase(m.mode()))
        .findFirst()
        .orElse(null);
    if (advertised == null) {
      throw new OprfModeNotEnabledException(
          "Server advertises its enabled modes and " + mode + " is not among them");
    }
    final byte[] pinned = pinnedPublicKey(mode);
    if (pinned == null) {
      return;
    }
    final byte[] served;
    try {
      served = Hex.decode(advertised.publicKeyHex() == null ? "" : advertised.publicKeyHex().trim());
    } catch (DecoderException e) {
      throw new OprfPublicKeyMismatchException(
          "Server advertised a " + mode + " public key that is not valid hex");
    }
    // Compared as bytes, not as strings: hex case and any leading-zero spelling difference would
    // otherwise read as a mismatch and refuse a perfectly good server.
    if (!MessageDigest.isEqual(pinned, served)) {
      throw new OprfPublicKeyMismatchException(
          "Server advertises a different " + mode + " public key than the one pinned for this "
              + "client. Either the server rotated its key and the pinned copies were not "
              + "updated, or this is not the server that was pinned. Refusing to proceed.");
    }
  }

}
