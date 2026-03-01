package com.codeheadsystems.rfc.opaque.internal;

import com.codeheadsystems.rfc.common.ByteUtils;
import com.codeheadsystems.rfc.opaque.config.OpaqueCipherSuite;
import com.codeheadsystems.rfc.opaque.config.OpaqueConfig;
import com.codeheadsystems.rfc.opaque.model.CleartextCredentials;
import com.codeheadsystems.rfc.opaque.model.Envelope;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

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

    OpaqueCipherSuite.AkeKeyPair keyPair = suite.deriveAkeKeyPair(seed);
    byte[] clientPublicKey = keyPair.publicKeyBytes();

    CleartextCredentials cleartext = CleartextCredentials.create(
        serverPublicKey, clientPublicKey, serverIdentity, clientIdentity);

    byte[] authInput = ByteUtils.concat(envelopeNonce, cleartext.serialize());
    byte[] authTag = suite.hmac(authKey, authInput);

    Envelope envelope = new Envelope(envelopeNonce, authTag);
    return new StoreResult(envelope, clientPublicKey, maskingKey, exportKey);
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

    OpaqueCipherSuite.AkeKeyPair keyPair = suite.deriveAkeKeyPair(seed);
    BigInteger clientSk = keyPair.privateKey();
    byte[] clientPublicKey = keyPair.publicKeyBytes();

    CleartextCredentials cleartext = CleartextCredentials.create(
        serverPublicKey, clientPublicKey, serverIdentity, clientIdentity);

    byte[] authInput = ByteUtils.concat(nonce, cleartext.serialize());
    byte[] expectedTag = suite.hmac(authKey, authInput);

    // Security: constant-time comparison prevents timing side-channel attacks on MAC verification
    if (!MessageDigest.isEqual(expectedTag, envelope.authTag())) {
      throw new SecurityException("Authentication failed");
    }

    // Return client private key as Nsk-byte big-endian
    int nsk = config.Nsk();
    byte[] clientSkBytes = clientSk.toByteArray();
    byte[] clientSkFixed = new byte[nsk];
    if (clientSkBytes.length > nsk) {
      System.arraycopy(clientSkBytes, clientSkBytes.length - nsk, clientSkFixed, 0, nsk);
    } else {
      System.arraycopy(clientSkBytes, 0, clientSkFixed, nsk - clientSkBytes.length, clientSkBytes.length);
    }
    return new RecoverResult(clientSkFixed, clientPublicKey, cleartext, exportKey);
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
  public record RecoverResult(byte[] clientPrivateKeyBytes, byte[] clientPublicKey,
                              CleartextCredentials cleartextCredentials, byte[] exportKey) {
  }
}
