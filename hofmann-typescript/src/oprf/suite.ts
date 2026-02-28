/**
 * P-256/SHA-256 OPRF cipher suite constants (RFC 9497 §4.1).
 *
 * contextString = "OPRFV1-" || I2OSP(0, 1) || "-P256-SHA256"
 *
 * The null byte at index 7 is critical — built via byte arrays, never string literals.
 */
import { concat } from '../crypto/primitives.js';
import { strToBytes } from '../crypto/encoding.js';

function buildContextString(): Uint8Array {
  return concat(
    strToBytes('OPRFV1-'),
    new Uint8Array([0x00]),   // mode = 0 (OPRF, not VOPRF or POPRF)
    strToBytes('-P256-SHA256')
  );
}

export const CONTEXT_STRING: Uint8Array = buildContextString();

// HashToGroup-<contextString>
export const HASH_TO_GROUP_DST: Uint8Array = concat(
  strToBytes('HashToGroup-'),
  CONTEXT_STRING
);

// HashToScalar-<contextString>
export const HASH_TO_SCALAR_DST: Uint8Array = concat(
  strToBytes('HashToScalar-'),
  CONTEXT_STRING
);

// DeriveKeyPair<contextString>  — no dash separator between "DeriveKeyPair" and contextString
export const DERIVE_KEY_PAIR_DST: Uint8Array = concat(
  strToBytes('DeriveKeyPair'),
  CONTEXT_STRING
);

// Size constants for P-256/SHA-256
export const Nh = 32;   // hash output length (SHA-256)
export const Npk = 33;  // compressed EC public key size
export const Nsk = 32;  // scalar (private key) size
export const Nn = 32;   // nonce size
export const Nm = 32;   // MAC size
