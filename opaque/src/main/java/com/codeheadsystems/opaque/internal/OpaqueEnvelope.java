package com.codeheadsystems.opaque.internal;

import com.codeheadsystems.oprf.curve.OctetStringUtils;
import com.codeheadsystems.opaque.config.OpaqueConfig;
import com.codeheadsystems.opaque.config.OpaqueCipherSuite;
import com.codeheadsystems.opaque.model.CleartextCredentials;
import com.codeheadsystems.opaque.model.Envelope;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
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
   * @param config        OPAQUE configuration (provides cipher suite and size constants)
   * @param randomizedPwd randomized password from OPRF
   * @param serverPublicKey server's public key bytes
   * @param serverIdentity  server identity bytes (may be null)
   * @param clientIdentity  client identity bytes (may be null)
   * @param envelopeNonce   Nn-byte nonce
   */
  public static StoreResult store(OpaqueConfig config, byte[] randomizedPwd, byte[] serverPublicKey,
                                  byte[] serverIdentity, byte[] clientIdentity,
                                  byte[] envelopeNonce) {
    OpaqueCipherSuite suite = config.cipherSuite();
    byte[] maskingKey = expand(suite, randomizedPwd,
        "MaskingKey".getBytes(StandardCharsets.US_ASCII), config.Nh());
    byte[] authKey = expand(suite, randomizedPwd,
        OctetStringUtils.concat(envelopeNonce, "AuthKey".getBytes(StandardCharsets.US_ASCII)), config.Nh());
    byte[] exportKey = expand(suite, randomizedPwd,
        OctetStringUtils.concat(envelopeNonce, "ExportKey".getBytes(StandardCharsets.US_ASCII)), config.Nh());
    byte[] seed = expand(suite, randomizedPwd,
        OctetStringUtils.concat(envelopeNonce, "PrivateKey".getBytes(StandardCharsets.US_ASCII)), config.Nsk());

    OpaqueCrypto.AkeKeyPair keyPair = OpaqueCrypto.deriveAkeKeyPair(suite, seed);
    byte[] clientPublicKey = keyPair.publicKeyBytes();

    CleartextCredentials cleartext = CleartextCredentials.create(
        serverPublicKey, clientPublicKey, serverIdentity, clientIdentity);

    byte[] authInput = OctetStringUtils.concat(envelopeNonce, cleartext.serialize());
    byte[] authTag = OpaqueCrypto.hmac(suite, authKey, authInput);

    Envelope envelope = new Envelope(envelopeNonce, authTag);
    return new StoreResult(envelope, clientPublicKey, maskingKey, exportKey);
  }

  /**
   * Recovers credentials from an envelope given the randomized password.
   *
   * @throws SecurityException if the auth_tag does not match
   */
  public static RecoverResult recover(OpaqueConfig config, byte[] randomizedPwd, byte[] serverPublicKey,
                                      Envelope envelope, byte[] serverIdentity,
                                      byte[] clientIdentity) {
    OpaqueCipherSuite suite = config.cipherSuite();
    byte[] nonce = envelope.envelopeNonce();
    byte[] authKey = expand(suite, randomizedPwd,
        OctetStringUtils.concat(nonce, "AuthKey".getBytes(StandardCharsets.US_ASCII)), config.Nh());
    byte[] exportKey = expand(suite, randomizedPwd,
        OctetStringUtils.concat(nonce, "ExportKey".getBytes(StandardCharsets.US_ASCII)), config.Nh());
    byte[] seed = expand(suite, randomizedPwd,
        OctetStringUtils.concat(nonce, "PrivateKey".getBytes(StandardCharsets.US_ASCII)), config.Nsk());

    OpaqueCrypto.AkeKeyPair keyPair = OpaqueCrypto.deriveAkeKeyPair(suite, seed);
    BigInteger clientSk = keyPair.privateKey();
    byte[] clientPublicKey = keyPair.publicKeyBytes();

    CleartextCredentials cleartext = CleartextCredentials.create(
        serverPublicKey, clientPublicKey, serverIdentity, clientIdentity);

    byte[] authInput = OctetStringUtils.concat(nonce, cleartext.serialize());
    byte[] expectedTag = OpaqueCrypto.hmac(suite, authKey, authInput);

    if (!Arrays.equals(expectedTag, envelope.authTag())) {
      throw new SecurityException("Envelope auth_tag mismatch: authentication failed");
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
    return OpaqueCrypto.hkdfExpand(suite, prk, info, len);
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
