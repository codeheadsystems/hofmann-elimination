package com.codeheadsystems.opaque.internal;

import com.codeheadsystems.hofmann.curve.Curve;
import com.codeheadsystems.hofmann.curve.OctetStringUtils;
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
    BigInteger blind = Curve.P256_CURVE.randomScalar();
    byte[] blindedElement = OpaqueOprf.blind(password, blind);
    RegistrationRequest request = new RegistrationRequest(blindedElement);
    return new ClientRegistrationState(blind, password, request);
  }

  /**
   * Client creates a registration request with a given blinding factor (for deterministic testing).
   */
  public static ClientRegistrationState createRegistrationRequestWithBlind(byte[] password,
                                                                           BigInteger blind,
                                                                           OpaqueConfig config) {
    byte[] blindedElement = OpaqueOprf.blind(password, blind);
    RegistrationRequest request = new RegistrationRequest(blindedElement);
    return new ClientRegistrationState(blind, password, request);
  }

  /**
   * Server creates a registration response: evaluates OPRF and includes server public key.
   */
  public static RegistrationResponse createRegistrationResponse(RegistrationRequest request,
                                                                byte[] serverPublicKey,
                                                                byte[] credentialIdentifier,
                                                                byte[] oprfSeed) {
    BigInteger oprfKey = OpaqueOprf.deriveOprfKey(oprfSeed, credentialIdentifier);
    byte[] evaluatedElement = OpaqueOprf.blindEvaluate(oprfKey, request.blindedElement());
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
        config, OpaqueCrypto.randomBytes(OpaqueConfig.Nn));
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

    StoreResult stored = OpaqueEnvelope.store(
        randomizedPwd, response.serverPublicKey(), serverIdentity, clientIdentity, envelopeNonce);
    return new RegistrationRecord(stored.clientPublicKey(), stored.maskingKey(), stored.envelope());
  }

  /**
   * Server creates a credential response for authentication.
   * Evaluates OPRF and masks the server public key + envelope.
   */
  public static CredentialResponse createCredentialResponse(CredentialRequest request,
                                                            byte[] serverPublicKey,
                                                            RegistrationRecord record,
                                                            byte[] credentialIdentifier,
                                                            byte[] oprfSeed) {
    return createCredentialResponseWithNonce(request, serverPublicKey, record,
        credentialIdentifier, oprfSeed, OpaqueCrypto.randomBytes(OpaqueConfig.Nn));
  }

  /**
   * Server creates a credential response with a provided masking nonce (for deterministic testing).
   */
  public static CredentialResponse createCredentialResponseWithNonce(CredentialRequest request,
                                                                     byte[] serverPublicKey,
                                                                     RegistrationRecord record,
                                                                     byte[] credentialIdentifier,
                                                                     byte[] oprfSeed,
                                                                     byte[] maskingNonce) {
    BigInteger oprfKey = OpaqueOprf.deriveOprfKey(oprfSeed, credentialIdentifier);
    byte[] evaluatedElement = OpaqueOprf.blindEvaluate(oprfKey, request.blindedElement());

    // pad = HKDF-Expand(masking_key, masking_nonce || "CredentialResponsePad", Npk + Nn + Nm)
    byte[] padInfo = OctetStringUtils.concat(
        maskingNonce,
        "CredentialResponsePad".getBytes(StandardCharsets.US_ASCII)
    );
    byte[] pad = OpaqueCrypto.hkdfExpand(record.maskingKey(), padInfo, OpaqueConfig.MASKED_RESPONSE_SIZE);

    // plaintext = server_public_key || envelope_nonce || auth_tag
    byte[] plaintext = OctetStringUtils.concat(serverPublicKey, record.envelope().serialize());
    byte[] maskedResponse = OpaqueCrypto.xor(pad, plaintext);

    return new CredentialResponse(evaluatedElement, maskingNonce, maskedResponse);
  }

  /**
   * Client recovers credentials from the credential response during authentication.
   *
   * @return RecoverResult with clientPrivateKeyBytes, clientPublicKey, cleartextCredentials, exportKey
   */
  public static RecoverResult recoverCredentials(byte[] password, BigInteger blind,
                                                 CredentialResponse response,
                                                 byte[] serverIdentity,
                                                 byte[] clientIdentity,
                                                 OpaqueConfig config) {
    byte[] randomizedPwd = deriveRandomizedPwd(password, blind, response.evaluatedElement(), config);

    // Recover masking_key = Expand(randomized_pwd, "MaskingKey", Nh)
    byte[] maskingKey = OpaqueCrypto.hkdfExpand(randomizedPwd,
        "MaskingKey".getBytes(StandardCharsets.US_ASCII), OpaqueConfig.Nh);

    // Unmask: pad = HKDF-Expand(masking_key, masking_nonce || "CredentialResponsePad", ...)
    byte[] padInfo = OctetStringUtils.concat(
        response.maskingNonce(),
        "CredentialResponsePad".getBytes(StandardCharsets.US_ASCII)
    );
    byte[] pad = OpaqueCrypto.hkdfExpand(maskingKey, padInfo, OpaqueConfig.MASKED_RESPONSE_SIZE);
    byte[] plaintext = OpaqueCrypto.xor(pad, response.maskedResponse());

    // Extract server_public_key || envelope
    byte[] serverPublicKey = new byte[OpaqueConfig.Npk];
    System.arraycopy(plaintext, 0, serverPublicKey, 0, OpaqueConfig.Npk);
    Envelope envelope = Envelope.deserialize(plaintext, OpaqueConfig.Npk, OpaqueConfig.Nn, OpaqueConfig.Nm);

    return OpaqueEnvelope.recover(randomizedPwd, serverPublicKey, envelope, serverIdentity, clientIdentity);
  }

  /**
   * Derives randomized password from OPRF output.
   * oprfOutput = OPRF.finalize(password, blind, evaluatedElement)
   * stretchedOutput = config.ksf.stretch(oprfOutput)
   * randomizedPwd = HKDF-Extract("", oprfOutput || stretchedOutput)
   */
  public static byte[] deriveRandomizedPwd(byte[] password, BigInteger blind,
                                           byte[] evaluatedElement, OpaqueConfig config) {
    byte[] oprfOutput = OpaqueOprf.finalize(password, blind, evaluatedElement);
    byte[] stretchedOutput = config.ksf().stretch(oprfOutput, config);
    return OpaqueCrypto.hkdfExtract(new byte[0], OctetStringUtils.concat(oprfOutput, stretchedOutput));
  }
}
