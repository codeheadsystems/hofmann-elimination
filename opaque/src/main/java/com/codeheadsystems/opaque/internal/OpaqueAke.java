package com.codeheadsystems.opaque.internal;

import com.codeheadsystems.hofmann.curve.OctetStringUtils;
import com.codeheadsystems.opaque.config.OpaqueConfig;
import com.codeheadsystems.opaque.internal.OpaqueEnvelope.RecoverResult;
import com.codeheadsystems.opaque.model.AuthResult;
import com.codeheadsystems.opaque.model.ClientAuthState;
import com.codeheadsystems.opaque.model.CredentialRequest;
import com.codeheadsystems.opaque.model.CredentialResponse;
import com.codeheadsystems.opaque.model.KE1;
import com.codeheadsystems.opaque.model.KE2;
import com.codeheadsystems.opaque.model.KE3;
import com.codeheadsystems.opaque.model.RegistrationRecord;
import com.codeheadsystems.opaque.model.ServerAuthState;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import org.bouncycastle.math.ec.ECPoint;

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
   * <p>
   * encode_vector(x) = I2OSP(len(x), 2) || x
   */
  public static byte[] buildPreamble(byte[] context, byte[] clientIdentity, KE1 ke1,
                                     byte[] serverIdentity, CredentialResponse credentialResponse,
                                     byte[] serverNonce, byte[] serverAkePublicKey) {
    byte[] prefix = "OPAQUEv1-".getBytes(StandardCharsets.US_ASCII);
    return OpaqueCrypto.concat(
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
   * <p>
   * prk = HKDF-Extract("", ikm)
   * preamble_hash = SHA-256(preamble)
   * handshake_secret = HKDF-Expand-Label(prk, "HandshakeSecret", preamble_hash, Nx)
   * session_key = HKDF-Expand-Label(prk, "SessionKey", preamble_hash, Nx)
   * Km2 = HKDF-Expand-Label(handshake_secret, "ServerMAC", "", Nm)
   * Km3 = HKDF-Expand-Label(handshake_secret, "ClientMAC", "", Nm)
   */
  private static DerivedKeys deriveKeys(byte[] ikm, byte[] preamble) {
    byte[] prk = OpaqueCrypto.hkdfExtract(new byte[0], ikm);
    byte[] preambleHash = OpaqueCrypto.sha256(preamble);

    byte[] handshakeSecret = OpaqueCrypto.hkdfExpandLabel(prk,
        "HandshakeSecret".getBytes(StandardCharsets.US_ASCII), preambleHash, OpaqueConfig.Nx);
    byte[] sessionKey = OpaqueCrypto.hkdfExpandLabel(prk,
        "SessionKey".getBytes(StandardCharsets.US_ASCII), preambleHash, OpaqueConfig.Nx);

    byte[] km2 = OpaqueCrypto.hkdfExpandLabel(handshakeSecret,
        "ServerMAC".getBytes(StandardCharsets.US_ASCII), new byte[0], OpaqueConfig.Nm);
    byte[] km3 = OpaqueCrypto.hkdfExpandLabel(handshakeSecret,
        "ClientMAC".getBytes(StandardCharsets.US_ASCII), new byte[0], OpaqueConfig.Nm);

    return new DerivedKeys(km2, km3, sessionKey);
  }

  /**
   * Server GenerateKE2.
   *
   * @param context              application context from config
   * @param serverIdentity       server identity bytes (or serverPublicKey if null)
   * @param serverPrivateKey     server long-term private key
   * @param serverPublicKey      server long-term public key bytes (33)
   * @param record               stored registration record
   * @param credentialIdentifier credential identifier
   * @param oprfSeed             server OPRF seed
   * @param ke1                  client's KE1 message
   * @param clientIdentity       client identity bytes (or clientPublicKey if null)
   * @param maskingNonce         provided masking nonce (null = random)
   * @param serverAkeKeySeed     provided server ephemeral AKE seed (null = random)
   * @return [ServerAuthState, KE2]
   */
  public static Object[] generateKE2(byte[] context, byte[] serverIdentity, BigInteger serverPrivateKey,
                                     byte[] serverPublicKey, RegistrationRecord record,
                                     byte[] credentialIdentifier, byte[] oprfSeed,
                                     KE1 ke1, byte[] clientIdentity,
                                     byte[] maskingNonce, byte[] serverAkeKeySeed) {
    // Effective identities
    byte[] sId = (serverIdentity != null) ? serverIdentity : serverPublicKey;
    byte[] cId = (clientIdentity != null) ? clientIdentity : record.clientPublicKey();

    // Credential response
    byte[] mn = (maskingNonce != null) ? maskingNonce : OpaqueCrypto.randomBytes(OpaqueConfig.Nn);
    CredentialRequest credReq = new CredentialRequest(ke1.credentialRequest().blindedElement());
    CredentialResponse credResponse = OpaqueCredentials.createCredentialResponseWithNonce(
        credReq, serverPublicKey, record, credentialIdentifier, oprfSeed, mn);

    // Server ephemeral AKE key pair
    byte[] seed = (serverAkeKeySeed != null) ? serverAkeKeySeed : OpaqueCrypto.randomBytes(OpaqueConfig.Nsk);
    Object[] serverAkeKp = OpaqueCrypto.deriveAkeKeyPairFull(seed);
    BigInteger serverAkeSk = (BigInteger) serverAkeKp[0];
    byte[] serverAkePk = (byte[]) serverAkeKp[1];

    byte[] serverNonce = OpaqueCrypto.randomBytes(OpaqueConfig.Nn);

    // Preamble
    byte[] preamble = buildPreamble(context, cId, ke1, sId, credResponse, serverNonce, serverAkePk);
    byte[] preambleHash = OpaqueCrypto.sha256(preamble);

    // 3DH: dh1 = serverAkeSk * clientAkePk, dh2 = serverSk * clientAkePk, dh3 = serverAkeSk * clientPk
    ECPoint clientAkePk = OpaqueCrypto.deserializePoint(ke1.clientAkePublicKey());
    ECPoint clientLongTermPk = OpaqueCrypto.deserializePoint(record.clientPublicKey());
    byte[] dh1 = OpaqueCrypto.dhP256(serverAkeSk, clientAkePk);
    byte[] dh2 = OpaqueCrypto.dhP256(serverPrivateKey, clientAkePk);
    byte[] dh3 = OpaqueCrypto.dhP256(serverAkeSk, clientLongTermPk);
    byte[] ikm = OpaqueCrypto.concat(dh1, dh2, dh3);

    DerivedKeys keys = deriveKeys(ikm, preamble);
    byte[] serverMac = OpaqueCrypto.hmacSha256(keys.km2(), preambleHash);
    byte[] expectedClientMac = OpaqueCrypto.hmacSha256(keys.km3(),
        OpaqueCrypto.sha256(OpaqueCrypto.concat(preamble, serverMac)));

    ServerAuthState authState = new ServerAuthState(expectedClientMac, keys.sessionKey());
    KE2 ke2 = new KE2(credResponse, serverNonce, serverAkePk, serverMac);
    return new Object[]{authState, ke2};
  }

  /**
   * Server GenerateKE2 with deterministic server nonce (for testing).
   */
  public static Object[] generateKE2Deterministic(byte[] context, byte[] serverIdentity,
                                                  BigInteger serverPrivateKey, byte[] serverPublicKey,
                                                  RegistrationRecord record, byte[] credentialIdentifier,
                                                  byte[] oprfSeed, KE1 ke1, byte[] clientIdentity,
                                                  byte[] maskingNonce, byte[] serverAkeKeySeed,
                                                  byte[] serverNonce) {
    byte[] sId = (serverIdentity != null) ? serverIdentity : serverPublicKey;
    byte[] cId = (clientIdentity != null) ? clientIdentity : record.clientPublicKey();

    byte[] mn = (maskingNonce != null) ? maskingNonce : OpaqueCrypto.randomBytes(OpaqueConfig.Nn);
    CredentialRequest credReq = new CredentialRequest(ke1.credentialRequest().blindedElement());
    CredentialResponse credResponse = OpaqueCredentials.createCredentialResponseWithNonce(
        credReq, serverPublicKey, record, credentialIdentifier, oprfSeed, mn);

    Object[] serverAkeKp = OpaqueCrypto.deriveAkeKeyPairFull(serverAkeKeySeed);
    BigInteger serverAkeSk = (BigInteger) serverAkeKp[0];
    byte[] serverAkePk = (byte[]) serverAkeKp[1];

    byte[] preamble = buildPreamble(context, cId, ke1, sId, credResponse, serverNonce, serverAkePk);
    byte[] preambleHash = OpaqueCrypto.sha256(preamble);

    ECPoint clientAkePk = OpaqueCrypto.deserializePoint(ke1.clientAkePublicKey());
    ECPoint clientLongTermPk = OpaqueCrypto.deserializePoint(record.clientPublicKey());
    byte[] dh1 = OpaqueCrypto.dhP256(serverAkeSk, clientAkePk);
    byte[] dh2 = OpaqueCrypto.dhP256(serverPrivateKey, clientAkePk);
    byte[] dh3 = OpaqueCrypto.dhP256(serverAkeSk, clientLongTermPk);
    byte[] ikm = OpaqueCrypto.concat(dh1, dh2, dh3);

    DerivedKeys keys = deriveKeys(ikm, preamble);
    byte[] serverMac = OpaqueCrypto.hmacSha256(keys.km2(), preambleHash);
    byte[] expectedClientMac = OpaqueCrypto.hmacSha256(keys.km3(),
        OpaqueCrypto.sha256(OpaqueCrypto.concat(preamble, serverMac)));

    ServerAuthState authState = new ServerAuthState(expectedClientMac, keys.sessionKey());
    KE2 ke2 = new KE2(credResponse, serverNonce, serverAkePk, serverMac);
    return new Object[]{authState, ke2};
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
    // Recover credentials
    RecoverResult recovered = OpaqueCredentials.recoverCredentials(
        state.password(), state.blind(), ke2.credentialResponse(),
        serverIdentity, clientIdentity, config);

    // Effective identities (same as server used)
    byte[] cId = (clientIdentity != null) ? clientIdentity : recovered.clientPublicKey();
    // Server identity: if null, defaults to the serverPublicKey from the recovered credentials
    byte[] sId = (serverIdentity != null) ? serverIdentity
        : recovered.cleartextCredentials().serverPublicKey();

    // Rebuild preamble exactly as server did
    byte[] preamble = buildPreamble(context, cId, state.ke1(), sId,
        ke2.credentialResponse(), ke2.serverNonce(), ke2.serverAkePublicKey());
    byte[] preambleHash = OpaqueCrypto.sha256(preamble);

    // Deserialize server long-term public key
    ECPoint serverLongTermPk = OpaqueCrypto.deserializePoint(
        recovered.cleartextCredentials().serverPublicKey());
    ECPoint serverAkePk = OpaqueCrypto.deserializePoint(ke2.serverAkePublicKey());

    // Client long-term private key
    BigInteger clientSk = new BigInteger(1, recovered.clientPrivateKeyBytes());

    // 3DH: dh1 = clientAkeSk * serverAkePk, dh2 = clientAkeSk * serverPk, dh3 = clientSk * serverAkePk
    byte[] dh1 = OpaqueCrypto.dhP256(state.clientAkePrivateKey(), serverAkePk);
    byte[] dh2 = OpaqueCrypto.dhP256(state.clientAkePrivateKey(), serverLongTermPk);
    byte[] dh3 = OpaqueCrypto.dhP256(clientSk, serverAkePk);
    byte[] ikm = OpaqueCrypto.concat(dh1, dh2, dh3);

    DerivedKeys keys = deriveKeys(ikm, preamble);

    // Verify server MAC
    byte[] expectedServerMac = OpaqueCrypto.hmacSha256(keys.km2(), preambleHash);
    if (!Arrays.equals(expectedServerMac, ke2.serverMac())) {
      throw new SecurityException("Server MAC verification failed");
    }

    // Compute client MAC: MAC(Km3, Hash(preamble || server_mac))
    byte[] clientMac = OpaqueCrypto.hmacSha256(keys.km3(),
        OpaqueCrypto.sha256(OpaqueCrypto.concat(preamble, ke2.serverMac())));

    return new AuthResult(new KE3(clientMac), keys.sessionKey(), recovered.exportKey());
  }

  private static byte[] encodeVector(byte[] data) {
    return OpaqueCrypto.concat(OctetStringUtils.I2OSP(data.length, 2), data);
  }

  private static byte[] serializeCredentialResponse(CredentialResponse cr) {
    return OpaqueCrypto.concat(cr.evaluatedElement(), cr.maskingNonce(), cr.maskedResponse());
  }

  /**
   * Keys derived by DeriveKeys.
   */
  private record DerivedKeys(byte[] km2, byte[] km3, byte[] sessionKey) {
  }
}
