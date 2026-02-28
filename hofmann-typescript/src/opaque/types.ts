/**
 * TypeScript interfaces for OPAQUE-3DH protocol state and wire types (RFC 9807).
 */

/** The stored envelope: nonce + auth tag (no plaintext). */
export interface Envelope {
  nonce: Uint8Array;    // 32 bytes
  authTag: Uint8Array;  // 32 bytes (HMAC-SHA256)
}

/** Client-side registration state (held between request and finalize). */
export interface ClientRegistrationState {
  password: Uint8Array;
  blind: bigint;
  blindedElement: Uint8Array;  // 33-byte compressed point
}

/** Registration response from server. */
export interface RegistrationResponse {
  evaluatedElement: Uint8Array;  // 33-byte compressed point
  serverPublicKey: Uint8Array;   // 33-byte compressed point
}

/** The registration record uploaded to the server. */
export interface RegistrationRecord {
  clientPublicKey: Uint8Array;  // 33-byte compressed point
  maskingKey: Uint8Array;       // 32 bytes
  envelope: Envelope;
}

/** KE1: blindedElement (33) || clientNonce (32) || clientAkePk (33) */
export interface KE1 {
  blindedElement: Uint8Array;
  clientNonce: Uint8Array;
  clientAkePublicKey: Uint8Array;
}

/** KE2 wire fields (deserialized). */
export interface KE2 {
  /** evaluatedElement (33) || maskingNonce (32) || maskedResponse (Npk + 2*32 = 97) */
  evaluatedElement: Uint8Array;
  maskingNonce: Uint8Array;
  maskedResponse: Uint8Array;     // 97 bytes: Npk(33) + nonce(32) + authTag(32)
  serverNonce: Uint8Array;        // 32 bytes
  serverAkePublicKey: Uint8Array; // 33 bytes
  serverMac: Uint8Array;          // 32 bytes
}

/** Client authentication state (between KE1 and KE3). */
export interface ClientAuthState {
  password: Uint8Array;
  blind: bigint;
  blindedElement: Uint8Array;
  clientAkeSecretKey: bigint;
  clientAkePublicKey: Uint8Array;
  clientNonce: Uint8Array;
  ke1Bytes: Uint8Array;  // serialized KE1 for preamble
}

/** Final authentication result returned to the caller. */
export interface AuthResult {
  clientMac: Uint8Array;   // 32-byte KE3 message (sent to server)
  sessionKey: Uint8Array;  // 32-byte shared session key
  exportKey: Uint8Array;   // 32-byte export key (for application use)
}

/** Recovered credential after successful authentication. */
export interface RecoveredCredentials {
  clientSecretKey: bigint;
  clientPublicKey: Uint8Array;
  serverPublicKey: Uint8Array;
  exportKey: Uint8Array;
  envelope: Envelope;
}
