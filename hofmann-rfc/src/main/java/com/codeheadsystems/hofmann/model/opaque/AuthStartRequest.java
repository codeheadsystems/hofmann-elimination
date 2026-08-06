package com.codeheadsystems.hofmann.model.opaque;

import com.codeheadsystems.rfc.opaque.model.CredentialRequest;
import com.codeheadsystems.rfc.opaque.model.KE1;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.Base64;

/**
 * Wire model for KE1 — the first message the client sends during OPAQUE authentication
 * (RFC 9807 §5.2 — AKE message 1).
 * <p>
 * Authentication in OPAQUE-3DH is a three-message authenticated key exchange (AKE).
 * This message (KE1) carries both the credential request and the client's AKE contribution:
 * <ul>
 *   <li>The <em>blinded element</em> is the client's OPRF input (password blinded with a
 *       random scalar), exactly as in registration.  The server evaluates the OPRF so the
 *       client can re-derive {@code randomized_pwd} and recover the envelope.</li>
 *   <li>The <em>client nonce</em> is a fresh random value that binds this AKE session;
 *       it is included in the key-derivation transcript to prevent replay attacks.</li>
 *   <li>The <em>client AKE public key</em> is the ephemeral Diffie-Hellman public key the
 *       client generates for this session.  Together with the server's ephemeral key (in KE2),
 *       it forms the 3DH handshake that produces the shared session key.</li>
 * </ul>
 * All byte array fields are base64-encoded for JSON transport.
 * <p>
 * Used by: {@code POST /opaque/auth/start}
 *
 * @param credentialIdentifierBase64 base64-encoded credential identifier used by the server                                   to look up the stored registration record
 * @param blindedElementBase64       base64-encoded blinded OPRF input element (compressed SEC1 EC point)
 * @param clientNonceBase64          base64-encoded 32-byte random client nonce for this AKE session
 * @param clientAkePublicKeyBase64   base64-encoded ephemeral client AKE public key (compressed SEC1 EC point)
 */
public record AuthStartRequest(
    @JsonProperty("credentialIdentifier") String credentialIdentifierBase64,
    @JsonProperty("blindedElement") String blindedElementBase64,
    @JsonProperty("clientNonce") String clientNonceBase64,
    @JsonProperty("clientAkePublicKey") String clientAkePublicKeyBase64) {

  private static final Base64.Encoder B64 = Base64.getEncoder();
  private static final Base64.Decoder B64D = Base64.getDecoder();

  /**
   * Upper bound on the encoded length of any single field. The largest legitimate value is a
   * base64-encoded P-521 point (~180 chars); credential identifiers are application-defined.
   * This cap blocks unbounded allocation from attacker-supplied fields (e.g. a megabyte-long
   * credentialIdentifier that would be retained as a rate-limiter / store map key).
   */
  private static final int MAX_ENCODED_FIELD_LENGTH = 4096;

  /**
   * Instantiates a new Auth start request.
   *
   * @param credentialIdentifier the credential identifier
   * @param ke1                  the ke 1
   */
  public AuthStartRequest(byte[] credentialIdentifier, KE1 ke1) {
    this(B64.encodeToString(credentialIdentifier),
        B64.encodeToString(ke1.credentialRequest().blindedElement()),
        B64.encodeToString(ke1.clientNonce()),
        B64.encodeToString(ke1.clientAkePublicKey()));
  }

  private static byte[] decode(String value, String fieldName) {
    if (value == null || value.isBlank()) {
      throw new IllegalArgumentException("Missing required field: " + fieldName);
    }
    if (value.length() > MAX_ENCODED_FIELD_LENGTH) {
      throw new IllegalArgumentException("Field too large: " + fieldName);
    }
    try {
      return B64D.decode(value);
    } catch (IllegalArgumentException e) {
      throw new IllegalArgumentException("Invalid base64 in field: " + fieldName, e);
    }
  }

  /**
   * Returns the credential identifier in its canonical base64 spelling.
   *
   * <p>Overrides the generated accessor so that downstream consumers — the session index,
   * the JWT subject, and every rate-limiter bucket key — see one spelling per identifier.
   * See {@link CredentialIdentifiers} for why the raw client string cannot be used directly.
   *
   * @return the canonical base64 credential identifier
   */
  public String credentialIdentifierBase64() {
    return CredentialIdentifiers.canonicalize(credentialIdentifierBase64);
  }

  /**
   * Credential identifier byte [ ].
   *
   * @return the byte [ ]
   */
  public byte[] credentialIdentifier() {
    return decode(credentialIdentifierBase64, "credentialIdentifier");
  }

  /**
   * Ke 1 ke 1.
   *
   * @return the ke 1
   */
  public KE1 ke1() {
    return new KE1(
        new CredentialRequest(decode(blindedElementBase64, "blindedElement")),
        decode(clientNonceBase64, "clientNonce"),
        decode(clientAkePublicKeyBase64, "clientAkePublicKey"));
  }
}
