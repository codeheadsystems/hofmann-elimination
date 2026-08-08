package com.codeheadsystems.rfc.opaque.internal;

import com.codeheadsystems.rfc.common.ByteUtils;
import com.codeheadsystems.rfc.opaque.config.OpaqueCipherSuite;
import com.codeheadsystems.rfc.opaque.config.OpaqueConfig;
import com.codeheadsystems.rfc.opaque.model.CleartextCredentials;
import com.codeheadsystems.rfc.opaque.model.Envelope;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;

/**
 * OPAQUE credential envelope operations: Store and Recover.
 * The envelope protects the client's long-term private key using a randomized password.
 */
public class OpaqueEnvelope {

  private OpaqueEnvelope() {
  }

  /**
   * Stores credentials into an envelope.
   * Per RFC 9807 §3.3.1.1.
   *
   * @param config          OPAQUE configuration (provides cipher suite and size constants)
   * @param randomizedPwd   randomized password from OPRF
   * @param serverPublicKey server's public key bytes
   * @param serverIdentity  server identity bytes (may be null)
   * @param clientIdentity  client identity bytes (may be null)
   * @param envelopeNonce   Nn-byte nonce
   * @return the store result
   */
  public static StoreResult store(OpaqueConfig config, byte[] randomizedPwd, byte[] serverPublicKey,
                                  byte[] serverIdentity, byte[] clientIdentity,
                                  byte[] envelopeNonce) {
    OpaqueCipherSuite suite = config.cipherSuite();
    byte[] maskingKey = null;
    byte[] authKey = null;
    byte[] exportKey = null;
    byte[] seed = null;
    // Distinguishes "returned to the caller, who now owns it" from "abandoned on an exception".
    // Deriving these before the try left them uncleared on any throw, and one of the throws is
    // reachable: CleartextCredentials.serialize() calls I2OSP(len, 2), which rejects an identity
    // of 65536 bytes or more.
    boolean handedOff = false;
    try {
      maskingKey = expand(suite, randomizedPwd,
          "MaskingKey".getBytes(StandardCharsets.US_ASCII), config.Nh());
      authKey = expand(suite, randomizedPwd,
          ByteUtils.concat(envelopeNonce, "AuthKey".getBytes(StandardCharsets.US_ASCII)), config.Nh());
      exportKey = expand(suite, randomizedPwd,
          ByteUtils.concat(envelopeNonce, "ExportKey".getBytes(StandardCharsets.US_ASCII)), config.Nh());
      // RFC 9807 §4.1.2: Nseed = 32 (= Nn), suite-independent constant
      seed = expand(suite, randomizedPwd,
          ByteUtils.concat(envelopeNonce, "PrivateKey".getBytes(StandardCharsets.US_ASCII)), OpaqueConfig.Nn);

      OpaqueCipherSuite.AkeKeyPair keyPair = suite.deriveAkeKeyPair(seed);
      byte[] clientPublicKey = keyPair.publicKeyBytes();

      CleartextCredentials cleartext = CleartextCredentials.create(
          serverPublicKey, clientPublicKey, serverIdentity, clientIdentity);

      byte[] authInput = ByteUtils.concat(envelopeNonce, cleartext.serialize());
      byte[] authTag = suite.hmac(authKey, authInput);

      Envelope envelope = new Envelope(envelopeNonce, authTag);
      StoreResult result = new StoreResult(envelope, clientPublicKey, maskingKey, exportKey);
      handedOff = true;
      return result;
    } finally {
      // seed is the client's long-term AKE private key in pre-image form, and authKey forges
      // envelope tags; neither ever leaves this method, so both go unconditionally.
      // keyPair.privateKey() is a BigInteger and cannot be zeroed at the Java level.
      clear(authKey);
      clear(seed);
      if (!handedOff) {
        clear(maskingKey);
        clear(exportKey);
      }
    }
  }

  /**
   * Recovers credentials from an envelope given the randomized password.
   *
   * @param config          the config
   * @param randomizedPwd   the randomized pwd
   * @param serverPublicKey the server public key
   * @param envelope        the envelope
   * @param serverIdentity  the server identity
   * @param clientIdentity  the client identity
   * @return the recover result
   * @throws SecurityException if the auth_tag does not match
   */
  public static RecoverResult recover(OpaqueConfig config, byte[] randomizedPwd, byte[] serverPublicKey,
                                      Envelope envelope, byte[] serverIdentity,
                                      byte[] clientIdentity) {
    OpaqueCipherSuite suite = config.cipherSuite();
    byte[] nonce = envelope.envelopeNonce();
    byte[] authKey = null;
    byte[] exportKey = null;
    byte[] seed = null;
    boolean handedOff = false;
    try {
      authKey = expand(suite, randomizedPwd,
          ByteUtils.concat(nonce, "AuthKey".getBytes(StandardCharsets.US_ASCII)), config.Nh());
      exportKey = expand(suite, randomizedPwd,
          ByteUtils.concat(nonce, "ExportKey".getBytes(StandardCharsets.US_ASCII)), config.Nh());
      // RFC 9807 §4.1.2: Nseed = 32 (= Nn), suite-independent constant
      seed = expand(suite, randomizedPwd,
          ByteUtils.concat(nonce, "PrivateKey".getBytes(StandardCharsets.US_ASCII)), OpaqueConfig.Nn);

      OpaqueCipherSuite.AkeKeyPair keyPair = suite.deriveAkeKeyPair(seed);
      BigInteger clientSk = keyPair.privateKey();
      byte[] clientPublicKey = keyPair.publicKeyBytes();

      CleartextCredentials cleartext = CleartextCredentials.create(
          serverPublicKey, clientPublicKey, serverIdentity, clientIdentity);

      byte[] authInput = ByteUtils.concat(nonce, cleartext.serialize());
      byte[] expectedTag = suite.hmac(authKey, authInput);

      // Security: constant-time comparison prevents timing side-channel attacks on MAC verification
      boolean matches = MessageDigest.isEqual(expectedTag, envelope.authTag());
      Arrays.fill(expectedTag, (byte) 0);
      if (!matches) {
        // The wrong-password path. handedOff stays false, so the finally below clears the export
        // key — this is the branch a password-guessing client takes repeatedly, and nothing on it
        // reaches a caller who could clear it.
        throw new SecurityException("Authentication failed");
      }

      RecoverResult result = new RecoverResult(clientSk, clientPublicKey, cleartext, exportKey);
      handedOff = true;
      return result;
    } finally {
      clear(authKey);
      clear(seed);
      // Covers the wrong-password throw and every other exit that does not reach the caller —
      // CleartextCredentials.serialize() rejects an identity of 65536 bytes or more, so this is
      // not only the MAC branch.
      if (!handedOff) {
        clear(exportKey);
      }
    }
  }

  private static byte[] expand(OpaqueCipherSuite suite, byte[] prk, byte[] info, int len) {
    return suite.hkdfExpand(prk, info, len);
  }

  /** Null-tolerant, so a {@code finally} can run before every derivation has happened. */
  private static void clear(byte[] secret) {
    if (secret != null) {
      Arrays.fill(secret, (byte) 0);
    }
  }

  /**
   * Result of the Store operation.
   */
  public record StoreResult(Envelope envelope, byte[] clientPublicKey, byte[] maskingKey, byte[] exportKey) {
  }

  /**
   * Result of the Recover operation.
   */
  public record RecoverResult(BigInteger clientPrivateKey, byte[] clientPublicKey,
                              CleartextCredentials cleartextCredentials, byte[] exportKey) {
  }
}
