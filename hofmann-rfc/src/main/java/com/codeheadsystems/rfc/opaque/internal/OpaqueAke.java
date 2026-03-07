package com.codeheadsystems.rfc.opaque.internal;

import com.codeheadsystems.rfc.common.ByteUtils;
import com.codeheadsystems.rfc.ellipticcurve.rfc9380.GroupSpec;
import com.codeheadsystems.rfc.opaque.config.OpaqueCipherSuite;
import com.codeheadsystems.rfc.opaque.config.OpaqueConfig;
import com.codeheadsystems.rfc.opaque.internal.OpaqueEnvelope.RecoverResult;
import com.codeheadsystems.rfc.opaque.model.AuthResult;
import com.codeheadsystems.rfc.opaque.model.ClientAuthState;
import com.codeheadsystems.rfc.opaque.model.CredentialRequest;
import com.codeheadsystems.rfc.opaque.model.CredentialResponse;
import com.codeheadsystems.rfc.opaque.model.KE1;
import com.codeheadsystems.rfc.opaque.model.KE2;
import com.codeheadsystems.rfc.opaque.model.KE3;
import com.codeheadsystems.rfc.opaque.model.RegistrationRecord;
import com.codeheadsystems.rfc.opaque.model.ServerAuthState;
import com.codeheadsystems.rfc.opaque.model.ServerKE2Result;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;

/**
 * OPAQUE-3DH Authenticated Key Exchange implementation.
 */
public class OpaqueAke {

  private OpaqueAke() {
  }

  /**
   * Constructs the preamble for key derivation.
   * preamble = "OPAQUEv1-" || encode_vector(context) || encode_vector(clientIdentity)
   * || serialize(ke1) || encode_vector(serverIdentity)
   * || serialize(credentialResponse) || serverNonce || serverAkePublicKey
   *
   * @param context            the context
   * @param clientIdentity     the client identity
   * @param ke1                the ke 1
   * @param serverIdentity     the server identity
   * @param credentialResponse the credential response
   * @param serverNonce        the server nonce
   * @param serverAkePublicKey the server ake public key
   * @return the byte [ ]
   */
  public static byte[] buildPreamble(byte[] context, byte[] clientIdentity, KE1 ke1,
                                     byte[] serverIdentity, CredentialResponse credentialResponse,
                                     byte[] serverNonce, byte[] serverAkePublicKey) {
    byte[] prefix = "OPAQUEv1-".getBytes(StandardCharsets.US_ASCII);
    return ByteUtils.concat(
        prefix,
        encodeVector(context),
        encodeVector(clientIdentity),
        ke1.serialize(),
        encodeVector(serverIdentity),
        serializeCredentialResponse(credentialResponse),
        serverNonce,
        serverAkePublicKey
    );
  }

  /**
   * Derives session keys from ikm and preamble using HKDF-Expand-Label.
   */
  private static DerivedKeys deriveKeys(OpaqueConfig config, byte[] ikm, byte[] preamble) {
    OpaqueCipherSuite suite = config.cipherSuite();
    byte[] prk = suite.hkdfExtract(new byte[0], ikm);
    byte[] preambleHash = suite.hash(preamble);

    byte[] handshakeSecret = suite.hkdfExpandLabel(prk,
        "HandshakeSecret".getBytes(StandardCharsets.US_ASCII), preambleHash, config.Nx());
    byte[] sessionKey = suite.hkdfExpandLabel(prk,
        "SessionKey".getBytes(StandardCharsets.US_ASCII), preambleHash, config.Nx());
    Arrays.fill(prk, (byte) 0);

    byte[] km2 = suite.hkdfExpandLabel(handshakeSecret,
        "ServerMAC".getBytes(StandardCharsets.US_ASCII), new byte[0], config.Nm());
    byte[] km3 = suite.hkdfExpandLabel(handshakeSecret,
        "ClientMAC".getBytes(StandardCharsets.US_ASCII), new byte[0], config.Nm());
    Arrays.fill(handshakeSecret, (byte) 0);

    return new DerivedKeys(km2, km3, sessionKey);
  }

  /**
   * Server GenerateKE2.
   *
   * @param config               OPAQUE configuration (provides context and cipher suite)
   * @param serverIdentity       server identity bytes (or serverPublicKey if null)
   * @param serverPrivateKey     server long-term private key
   * @param serverPublicKey      server long-term public key bytes
   * @param record               stored registration record
   * @param credentialIdentifier credential identifier
   * @param oprfSeed             server OPRF seed
   * @param ke1                  client's KE1 message
   * @param clientIdentity       client identity bytes (or clientPublicKey if null)
   * @param maskingNonce         provided masking nonce (null = random)
   * @param serverAkeKeySeed     provided server ephemeral AKE seed (null = random)
   * @return ServerKE2Result containing serverAuthState and ke2
   */
  public static ServerKE2Result generateKE2(OpaqueConfig config, byte[] serverIdentity,
                                            BigInteger serverPrivateKey, byte[] serverPublicKey,
                                            RegistrationRecord record, byte[] credentialIdentifier,
                                            byte[] oprfSeed, KE1 ke1, byte[] clientIdentity,
                                            byte[] maskingNonce, byte[] serverAkeKeySeed) {
    byte[] resolvedSeed = (serverAkeKeySeed != null) ? serverAkeKeySeed
        : config.randomProvider().randomBytes(OpaqueConfig.Nn);
    byte[] serverNonce = config.randomProvider().randomBytes(OpaqueConfig.Nn);
    return generateKE2Deterministic(config, serverIdentity, serverPrivateKey, serverPublicKey,
        record, credentialIdentifier, oprfSeed, ke1, clientIdentity, maskingNonce, resolvedSeed, serverNonce);
  }

  /**
   * Server GenerateKE2 with deterministic server nonce (for testing).
   *
   * @param config               the config
   * @param serverIdentity       the server identity
   * @param serverPrivateKey     the server private key
   * @param serverPublicKey      the server public key
   * @param record               the record
   * @param credentialIdentifier the credential identifier
   * @param oprfSeed             the oprf seed
   * @param ke1                  the ke 1
   * @param clientIdentity       the client identity
   * @param maskingNonce         the masking nonce
   * @param serverAkeKeySeed     the server ake key seed
   * @param serverNonce          the server nonce
   * @return the server ke 2 result
   */
  public static ServerKE2Result generateKE2Deterministic(OpaqueConfig config, byte[] serverIdentity,
                                                         BigInteger serverPrivateKey, byte[] serverPublicKey,
                                                         RegistrationRecord record, byte[] credentialIdentifier,
                                                         byte[] oprfSeed, KE1 ke1, byte[] clientIdentity,
                                                         byte[] maskingNonce, byte[] serverAkeKeySeed,
                                                         byte[] serverNonce) {
    OpaqueCipherSuite suite = config.cipherSuite();

    byte[] sId = (serverIdentity != null) ? serverIdentity : serverPublicKey;
    byte[] cId = (clientIdentity != null) ? clientIdentity : record.clientPublicKey();

    byte[] mn = (maskingNonce != null) ? maskingNonce : config.randomProvider().randomBytes(OpaqueConfig.Nn);
    CredentialRequest credReq = new CredentialRequest(ke1.credentialRequest().blindedElement());
    CredentialResponse credResponse = OpaqueCredentials.createCredentialResponseWithNonce(
        config, credReq, serverPublicKey, record, credentialIdentifier, oprfSeed, mn);

    OpaqueCipherSuite.AkeKeyPair serverAkeKp = suite.deriveAkeKeyPair(serverAkeKeySeed);
    BigInteger serverAkeSk = serverAkeKp.privateKey();
    byte[] serverAkePk = serverAkeKp.publicKeyBytes();

    byte[] preamble = buildPreamble(config.context(), cId, ke1, sId, credResponse, serverNonce, serverAkePk);
    byte[] preambleHash = suite.hash(preamble);

    GroupSpec gs = suite.oprfSuite().groupSpec();
    byte[] dh1 = gs.scalarMultiply(serverAkeSk, ke1.clientAkePublicKey());
    byte[] dh2 = gs.scalarMultiply(serverPrivateKey, ke1.clientAkePublicKey());
    byte[] dh3 = gs.scalarMultiply(serverAkeSk, record.clientPublicKey());
    byte[] ikm = ByteUtils.concat(dh1, dh2, dh3);
    Arrays.fill(dh1, (byte) 0);
    Arrays.fill(dh2, (byte) 0);
    Arrays.fill(dh3, (byte) 0);

    DerivedKeys keys = deriveKeys(config, ikm, preamble);
    Arrays.fill(ikm, (byte) 0);
    byte[] serverMac = suite.hmac(keys.km2(), preambleHash);
    byte[] expectedClientMac = suite.hmac(keys.km3(),
        suite.hash(ByteUtils.concat(preamble, serverMac)));
    Arrays.fill(keys.km2(), (byte) 0);
    Arrays.fill(keys.km3(), (byte) 0);

    ServerAuthState authState = new ServerAuthState(expectedClientMac, keys.sessionKey());
    KE2 ke2 = new KE2(credResponse, serverNonce, serverAkePk, serverMac);
    return new ServerKE2Result(authState, ke2);
  }

  /**
   * Client GenerateKE3.
   *
   * @param state          client auth state from GenerateKE1
   * @param clientIdentity client identity (null = use clientPublicKey from record)
   * @param serverIdentity server identity (null = use serverPublicKey from credential response)
   * @param ke2            server's KE2
   * @param context        application context
   * @param config         OPAQUE configuration
   * @return AuthResult
   */
  public static AuthResult generateKE3(ClientAuthState state, byte[] clientIdentity,
                                       byte[] serverIdentity, KE2 ke2, byte[] context,
                                       OpaqueConfig config) {
    OpaqueCipherSuite suite = config.cipherSuite();

    RecoverResult recovered = OpaqueCredentials.recoverCredentials(
        state.password(), state.blind(), ke2.credentialResponse(),
        serverIdentity, clientIdentity, config);

    byte[] cId = (clientIdentity != null) ? clientIdentity : recovered.clientPublicKey();
    byte[] sId = (serverIdentity != null) ? serverIdentity
        : recovered.cleartextCredentials().serverPublicKey();

    byte[] preamble = buildPreamble(context, cId, state.ke1(), sId,
        ke2.credentialResponse(), ke2.serverNonce(), ke2.serverAkePublicKey());
    byte[] preambleHash = suite.hash(preamble);

    GroupSpec gs = suite.oprfSuite().groupSpec();
    BigInteger clientSk = recovered.clientPrivateKey();

    byte[] dh1 = gs.scalarMultiply(state.clientAkePrivateKey(), ke2.serverAkePublicKey());
    byte[] dh2 = gs.scalarMultiply(state.clientAkePrivateKey(), recovered.cleartextCredentials().serverPublicKey());
    byte[] dh3 = gs.scalarMultiply(clientSk, ke2.serverAkePublicKey());
    byte[] ikm = ByteUtils.concat(dh1, dh2, dh3);
    Arrays.fill(dh1, (byte) 0);
    Arrays.fill(dh2, (byte) 0);
    Arrays.fill(dh3, (byte) 0);

    DerivedKeys keys = deriveKeys(config, ikm, preamble);
    Arrays.fill(ikm, (byte) 0);

    byte[] expectedServerMac = suite.hmac(keys.km2(), preambleHash);
    Arrays.fill(keys.km2(), (byte) 0);
    // Security: constant-time comparison prevents timing side-channel attacks on MAC verification
    if (!MessageDigest.isEqual(expectedServerMac, ke2.serverMac())) {
      Arrays.fill(expectedServerMac, (byte) 0);
      Arrays.fill(keys.km3(), (byte) 0);
      Arrays.fill(keys.sessionKey(), (byte) 0);
      throw new SecurityException("Authentication failed");
    }
    Arrays.fill(expectedServerMac, (byte) 0);

    byte[] clientMac = suite.hmac(keys.km3(),
        suite.hash(ByteUtils.concat(preamble, ke2.serverMac())));
    Arrays.fill(keys.km3(), (byte) 0);

    return new AuthResult(new KE3(clientMac), keys.sessionKey(), recovered.exportKey());
  }

  private static byte[] encodeVector(byte[] data) {
    return ByteUtils.concat(ByteUtils.I2OSP(data.length, 2), data);
  }

  private static byte[] serializeCredentialResponse(CredentialResponse cr) {
    return ByteUtils.concat(cr.evaluatedElement(), cr.maskingNonce(), cr.maskedResponse());
  }

  private record DerivedKeys(byte[] km2, byte[] km3, byte[] sessionKey) {
  }
}
