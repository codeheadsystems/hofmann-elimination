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
    byte[] maskingKey = expand(suite, randomizedPwd,
        "MaskingKey".getBytes(StandardCharsets.US_ASCII), config.Nh());
    byte[] authKey = expand(suite, randomizedPwd,
        ByteUtils.concat(envelopeNonce, "AuthKey".getBytes(StandardCharsets.US_ASCII)), config.Nh());
    byte[] exportKey = expand(suite, randomizedPwd,
        ByteUtils.concat(envelopeNonce, "ExportKey".getBytes(StandardCharsets.US_ASCII)), config.Nh());
    // RFC 9807 §4.1.2: Nseed = 32 (= Nn), suite-independent constant
    byte[] seed = expand(suite, randomizedPwd,
        ByteUtils.concat(envelopeNonce, "PrivateKey".getBytes(StandardCharsets.US_ASCII)), OpaqueConfig.Nn);
    try {
      OpaqueCipherSuite.AkeKeyPair keyPair = suite.deriveAkeKeyPair(seed);
      byte[] clientPublicKey = keyPair.publicKeyBytes();

      CleartextCredentials cleartext = CleartextCredentials.create(
          serverPublicKey, clientPublicKey, serverIdentity, clientIdentity);

      byte[] authInput = ByteUtils.concat(envelopeNonce, cleartext.serialize());
      byte[] authTag = suite.hmac(authKey, authInput);

      Envelope envelope = new Envelope(envelopeNonce, authTag);
      return new StoreResult(envelope, clientPublicKey, maskingKey, exportKey);
    } finally {
      // seed is the client's long-term AKE private key in pre-image form, and authKey forges
      // envelope tags. maskingKey and exportKey are returned, so they belong to the caller.
      // keyPair.privateKey() is a BigInteger and cannot be zeroed at the Java level.
      Arrays.fill(authKey, (byte) 0);
      Arrays.fill(seed, (byte) 0);
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
    byte[] authKey = expand(suite, randomizedPwd,
        ByteUtils.concat(nonce, "AuthKey".getBytes(StandardCharsets.US_ASCII)), config.Nh());
    byte[] exportKey = expand(suite, randomizedPwd,
        ByteUtils.concat(nonce, "ExportKey".getBytes(StandardCharsets.US_ASCII)), config.Nh());
    // RFC 9807 §4.1.2: Nseed = 32 (= Nn), suite-independent constant
    byte[] seed = expand(suite, randomizedPwd,
        ByteUtils.concat(nonce, "PrivateKey".getBytes(StandardCharsets.US_ASCII)), OpaqueConfig.Nn);
    try {
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
        // The wrong-password path: nothing here reaches a caller who could zero it, so the
        // export key has to be zeroed before the throw. This is the branch a password-guessing
        // client takes repeatedly, so it is the one most likely to leave residue on the heap.
        Arrays.fill(exportKey, (byte) 0);
        throw new SecurityException("Authentication failed");
      }

      return new RecoverResult(clientSk, clientPublicKey, cleartext, exportKey);
    } finally {
      Arrays.fill(authKey, (byte) 0);
      Arrays.fill(seed, (byte) 0);
    }
  }

  private static byte[] expand(OpaqueCipherSuite suite, byte[] prk, byte[] info, int len) {
    return suite.hkdfExpand(prk, info, len);
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
