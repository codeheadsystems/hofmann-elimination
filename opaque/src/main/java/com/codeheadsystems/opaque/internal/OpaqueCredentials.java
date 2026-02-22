package com.codeheadsystems.opaque.internal;

import com.codeheadsystems.ellipticcurve.curve.OctetStringUtils;
import com.codeheadsystems.opaque.config.OpaqueCipherSuite;
import com.codeheadsystems.opaque.config.OpaqueConfig;
import com.codeheadsystems.opaque.internal.OpaqueEnvelope.RecoverResult;
import com.codeheadsystems.opaque.internal.OpaqueEnvelope.StoreResult;
import com.codeheadsystems.opaque.model.ClientRegistrationState;
import com.codeheadsystems.opaque.model.CredentialRequest;
import com.codeheadsystems.opaque.model.CredentialResponse;
import com.codeheadsystems.opaque.model.Envelope;
import com.codeheadsystems.opaque.model.RegistrationRecord;
import com.codeheadsystems.opaque.model.RegistrationRequest;
import com.codeheadsystems.opaque.model.RegistrationResponse;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;

/**
 * Handles the credential request/response lifecycle for OPAQUE registration and authentication.
 */
public class OpaqueCredentials {

  private OpaqueCredentials() {
  }

  /**
   * Client creates a registration request by blinding the password.
   */
  public static ClientRegistrationState createRegistrationRequest(byte[] password, OpaqueConfig config) {
    BigInteger blind = config.cipherSuite().oprfSuite().randomScalar();
    return createRegistrationRequestWithBlind(password, blind, config);
  }

  /**
   * Client creates a registration request with a given blinding factor (for deterministic testing).
   */
  public static ClientRegistrationState createRegistrationRequestWithBlind(byte[] password,
                                                                           BigInteger blind,
                                                                           OpaqueConfig config) {
    byte[] blindedElement = OpaqueOprf.blind(config.cipherSuite(), password, blind);
    RegistrationRequest request = new RegistrationRequest(blindedElement);
    return new ClientRegistrationState(blind, password, request);
  }

  /**
   * Server creates a registration response: evaluates OPRF and includes server public key.
   */
  public static RegistrationResponse createRegistrationResponse(OpaqueConfig config,
                                                                RegistrationRequest request,
                                                                byte[] serverPublicKey,
                                                                byte[] credentialIdentifier,
                                                                byte[] oprfSeed) {
    BigInteger oprfKey = OpaqueOprf.deriveOprfKey(config.cipherSuite(), oprfSeed, credentialIdentifier);
    byte[] evaluatedElement = OpaqueOprf.blindEvaluate(config.cipherSuite(), oprfKey, request.blindedElement());
    return new RegistrationResponse(evaluatedElement, serverPublicKey);
  }

  /**
   * Client finalizes registration: derives randomized_pwd, stores envelope.
   */
  public static RegistrationRecord finalizeRegistration(ClientRegistrationState state,
                                                        RegistrationResponse response,
                                                        byte[] serverIdentity,
                                                        byte[] clientIdentity,
                                                        OpaqueConfig config) {
    return finalizeRegistrationWithNonce(state, response, serverIdentity, clientIdentity,
        config, config.randomConfig().randomBytes(OpaqueConfig.Nn));
  }

  /**
   * Client finalizes registration with a provided nonce (for deterministic testing).
   */
  public static RegistrationRecord finalizeRegistrationWithNonce(ClientRegistrationState state,
                                                                 RegistrationResponse response,
                                                                 byte[] serverIdentity,
                                                                 byte[] clientIdentity,
                                                                 OpaqueConfig config,
                                                                 byte[] envelopeNonce) {
    byte[] randomizedPwd = deriveRandomizedPwd(state.password(), state.blind(),
        response.evaluatedElement(), config);

    StoreResult stored = OpaqueEnvelope.store(config,
        randomizedPwd, response.serverPublicKey(), serverIdentity, clientIdentity, envelopeNonce);
    return new RegistrationRecord(stored.clientPublicKey(), stored.maskingKey(), stored.envelope());
  }

  /**
   * Server creates a credential response for authentication.
   */
  public static CredentialResponse createCredentialResponse(OpaqueConfig config,
                                                            CredentialRequest request,
                                                            byte[] serverPublicKey,
                                                            RegistrationRecord record,
                                                            byte[] credentialIdentifier,
                                                            byte[] oprfSeed) {
    return createCredentialResponseWithNonce(config, request, serverPublicKey, record,
        credentialIdentifier, oprfSeed, config.randomConfig().randomBytes(OpaqueConfig.Nn));
  }

  /**
   * Server creates a credential response with a provided masking nonce (for deterministic testing).
   */
  public static CredentialResponse createCredentialResponseWithNonce(OpaqueConfig config,
                                                                     CredentialRequest request,
                                                                     byte[] serverPublicKey,
                                                                     RegistrationRecord record,
                                                                     byte[] credentialIdentifier,
                                                                     byte[] oprfSeed,
                                                                     byte[] maskingNonce) {
    OpaqueCipherSuite suite = config.cipherSuite();
    BigInteger oprfKey = OpaqueOprf.deriveOprfKey(suite, oprfSeed, credentialIdentifier);
    byte[] evaluatedElement = OpaqueOprf.blindEvaluate(suite, oprfKey, request.blindedElement());

    // pad = HKDF-Expand(masking_key, masking_nonce || "CredentialResponsePad", Npk + Nn + Nm)
    byte[] padInfo = OctetStringUtils.concat(
        maskingNonce,
        "CredentialResponsePad".getBytes(StandardCharsets.US_ASCII)
    );
    byte[] pad = OpaqueCrypto.hkdfExpand(suite, record.maskingKey(), padInfo, config.maskedResponseSize());

    // plaintext = server_public_key || envelope_nonce || auth_tag
    byte[] plaintext = OctetStringUtils.concat(serverPublicKey, record.envelope().serialize());
    byte[] maskedResponse = OpaqueCrypto.xor(pad, plaintext);

    return new CredentialResponse(evaluatedElement, maskingNonce, maskedResponse);
  }

  /**
   * Client recovers credentials from the credential response during authentication.
   */
  public static RecoverResult recoverCredentials(byte[] password, BigInteger blind,
                                                 CredentialResponse response,
                                                 byte[] serverIdentity,
                                                 byte[] clientIdentity,
                                                 OpaqueConfig config) {
    OpaqueCipherSuite suite = config.cipherSuite();
    byte[] randomizedPwd = deriveRandomizedPwd(password, blind, response.evaluatedElement(), config);

    // Recover masking_key = Expand(randomized_pwd, "MaskingKey", Nh)
    byte[] maskingKey = OpaqueCrypto.hkdfExpand(suite, randomizedPwd,
        "MaskingKey".getBytes(StandardCharsets.US_ASCII), config.Nh());

    // Unmask: pad = HKDF-Expand(masking_key, masking_nonce || "CredentialResponsePad", ...)
    byte[] padInfo = OctetStringUtils.concat(
        response.maskingNonce(),
        "CredentialResponsePad".getBytes(StandardCharsets.US_ASCII)
    );
    byte[] pad = OpaqueCrypto.hkdfExpand(suite, maskingKey, padInfo, config.maskedResponseSize());
    byte[] plaintext = OpaqueCrypto.xor(pad, response.maskedResponse());

    // Extract server_public_key || envelope
    byte[] serverPublicKey = new byte[config.Npk()];
    System.arraycopy(plaintext, 0, serverPublicKey, 0, config.Npk());
    Envelope envelope = Envelope.deserialize(plaintext, config.Npk(), OpaqueConfig.Nn, config.Nm());

    return OpaqueEnvelope.recover(config, randomizedPwd, serverPublicKey, envelope, serverIdentity, clientIdentity);
  }

  /**
   * Derives randomized password from OPRF output.
   */
  public static byte[] deriveRandomizedPwd(byte[] password, BigInteger blind,
                                           byte[] evaluatedElement, OpaqueConfig config) {
    byte[] oprfOutput = OpaqueOprf.finalize(config.cipherSuite(), password, blind, evaluatedElement);
    byte[] stretchedOutput = config.ksf().stretch(oprfOutput, config);
    return OpaqueCrypto.hkdfExtract(config.cipherSuite(), new byte[0],
        OctetStringUtils.concat(oprfOutput, stretchedOutput));
  }
}
