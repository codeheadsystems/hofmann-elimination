package com.codeheadsystems.opaque.internal;

import com.codeheadsystems.hofmann.curve.OctetStringUtils;
import com.codeheadsystems.opaque.config.OpaqueConfig;
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
   * Per RFC 9807 §3.3.1.1:
   * <p>
   * masking_key = Expand(randomizedPwd, "MaskingKey", Nh)
   * auth_key    = Expand(randomizedPwd, envelope_nonce || "AuthKey", Nh)
   * export_key  = Expand(randomizedPwd, envelope_nonce || "ExportKey", Nh)
   * seed        = Expand(randomizedPwd, envelope_nonce || "PrivateKey", Nsk)
   * (clientSk, clientPk) = DeriveKeyPair(seed, "OPAQUE-DeriveAuthKeyPair")
   * cleartext = CreateCleartextCredentials(serverPublicKey, clientPk, serverIdentity, clientIdentity)
   * auth_tag = HMAC(auth_key, envelope_nonce || serialize(cleartext))
   */
  public static StoreResult store(byte[] randomizedPwd, byte[] serverPublicKey,
                                  byte[] serverIdentity, byte[] clientIdentity,
                                  byte[] envelopeNonce) {
    byte[] maskingKey = expand(randomizedPwd, "MaskingKey".getBytes(StandardCharsets.US_ASCII), OpaqueConfig.Nh);
    byte[] authKey = expand(randomizedPwd, OctetStringUtils.concat(envelopeNonce, "AuthKey".getBytes(StandardCharsets.US_ASCII)), OpaqueConfig.Nh);
    byte[] exportKey = expand(randomizedPwd, OctetStringUtils.concat(envelopeNonce, "ExportKey".getBytes(StandardCharsets.US_ASCII)), OpaqueConfig.Nh);
    byte[] seed = expand(randomizedPwd, OctetStringUtils.concat(envelopeNonce, "PrivateKey".getBytes(StandardCharsets.US_ASCII)), OpaqueConfig.Nsk);

    OpaqueCrypto.AkeKeyPair keyPair = OpaqueCrypto.deriveAkeKeyPair(seed);
    byte[] clientPublicKey = keyPair.publicKeyBytes();

    CleartextCredentials cleartext = CleartextCredentials.create(
        serverPublicKey, clientPublicKey, serverIdentity, clientIdentity);

    byte[] authInput = OctetStringUtils.concat(envelopeNonce, cleartext.serialize());
    byte[] authTag = OpaqueCrypto.hmacSha256(authKey, authInput);

    Envelope envelope = new Envelope(envelopeNonce, authTag);
    return new StoreResult(envelope, clientPublicKey, maskingKey, exportKey);
  }

  /**
   * Recovers credentials from an envelope given the randomized password.
   *
   * @throws SecurityException if the auth_tag does not match
   */
  public static RecoverResult recover(byte[] randomizedPwd, byte[] serverPublicKey,
                                      Envelope envelope, byte[] serverIdentity,
                                      byte[] clientIdentity) {
    byte[] nonce = envelope.envelopeNonce();
    byte[] authKey = expand(randomizedPwd, OctetStringUtils.concat(nonce, "AuthKey".getBytes(StandardCharsets.US_ASCII)), OpaqueConfig.Nh);
    byte[] exportKey = expand(randomizedPwd, OctetStringUtils.concat(nonce, "ExportKey".getBytes(StandardCharsets.US_ASCII)), OpaqueConfig.Nh);
    byte[] seed = expand(randomizedPwd, OctetStringUtils.concat(nonce, "PrivateKey".getBytes(StandardCharsets.US_ASCII)), OpaqueConfig.Nsk);

    OpaqueCrypto.AkeKeyPair keyPair = OpaqueCrypto.deriveAkeKeyPair(seed);
    BigInteger clientSk = keyPair.privateKey();
    byte[] clientPublicKey = keyPair.publicKeyBytes();

    CleartextCredentials cleartext = CleartextCredentials.create(
        serverPublicKey, clientPublicKey, serverIdentity, clientIdentity);

    byte[] authInput = OctetStringUtils.concat(nonce, cleartext.serialize());
    byte[] expectedTag = OpaqueCrypto.hmacSha256(authKey, authInput);

    if (!Arrays.equals(expectedTag, envelope.authTag())) {
      throw new SecurityException("Envelope auth_tag mismatch: authentication failed");
    }

    // Return client private key as 32-byte big-endian
    byte[] clientSkBytes = clientSk.toByteArray();
    byte[] clientSkFixed = new byte[32];
    if (clientSkBytes.length > 32) {
      System.arraycopy(clientSkBytes, clientSkBytes.length - 32, clientSkFixed, 0, 32);
    } else {
      System.arraycopy(clientSkBytes, 0, clientSkFixed, 32 - clientSkBytes.length, clientSkBytes.length);
    }
    return new RecoverResult(clientSkFixed, clientPublicKey, cleartext, exportKey);
  }

  private static byte[] expand(byte[] prk, byte[] info, int len) {
    return OpaqueCrypto.hkdfExpand(prk, info, len);
  }

  /**
   * Result of the Store operation.
   *
   * @param envelope        the created envelope (nonce + auth_tag)
   * @param clientPublicKey 33-byte compressed client public key
   * @param maskingKey      32-byte masking key for credential response
   * @param exportKey       32-byte export key for application use
   */
  public record StoreResult(Envelope envelope, byte[] clientPublicKey, byte[] maskingKey, byte[] exportKey) {
  }

  /**
   * Result of the Recover operation.
   *
   * @param clientPrivateKeyBytes recovered client private key scalar bytes (32)
   * @param clientPublicKey       recovered client public key (33)
   * @param cleartextCredentials  recovered cleartext credentials
   * @param exportKey             32-byte export key
   */
  public record RecoverResult(byte[] clientPrivateKeyBytes, byte[] clientPublicKey,
                              CleartextCredentials cleartextCredentials, byte[] exportKey) {
  }
}
