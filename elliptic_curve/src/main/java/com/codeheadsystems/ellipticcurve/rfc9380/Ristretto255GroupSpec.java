package com.codeheadsystems.ellipticcurve.rfc9380;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * {@link GroupSpec} implementation for ristretto255 (RFC 9496 / RFC 9380 Appendix B).
 * <p>
 * Implements all required group operations using pure Edwards25519 arithmetic
 * (extended coordinates) with ristretto255 encode/decode as defined in RFC 9496.
 * <p>
 * hash_to_group uses expand_message_xmd (SHA-512) → 128 bytes → two 64-byte
 * big-endian field elements → Elligator MAP × 2 → add → encode, per RFC 9380 Appendix B.
 * <p>
 * hashToScalar uses expand_message_xmd (SHA-512) → 64 bytes → little-endian mod L.
 */
public class Ristretto255GroupSpec implements GroupSpec {

  /** Singleton instance. */
  public static final Ristretto255GroupSpec INSTANCE = new Ristretto255GroupSpec();

  // ─── Field modulus and group order ──────────────────────────────────────────

  /** p = 2^255 - 19 */
  static final BigInteger P = BigInteger.TWO.pow(255).subtract(BigInteger.valueOf(19));

  /** L = 2^252 + 27742317777372353535851937790883648493 */
  private static final BigInteger L = BigInteger.TWO.pow(252).add(
      new BigInteger("27742317777372353535851937790883648493"));

  // ─── RFC 9496 §4.1 constants ─────────────────────────────────────────────

  /** d = -121665/121666 mod p */
  static final BigInteger D = new BigInteger(
      "37095705934669439343138083508754565189542113879843219016388785533085940283555");

  /** sqrt(-1) = 2^((p-1)/4) mod p */
  static final BigInteger SQRT_M1 = new BigInteger(
      "19681161376707505956807079304988542015446066515923890162744021073123829784752");

  /** sqrt(a*d - 1) = sqrt(-d - 1) — the "negative" (odd) square root */
  static final BigInteger SQRT_AD_MINUS_ONE = new BigInteger(
      "25063068953384623474111414158702152701244531502492656460079210482610430750235");

  /** 1/sqrt(a - d) = 1/sqrt(-(1+d)) — even ("positive") square root */
  static final BigInteger INVSQRT_A_MINUS_D = new BigInteger(
      "54469307008909316920995813868745141605393597292927456921205312896311721017578");

  /** (1 - d)^2 mod p */
  static final BigInteger ONE_MINUS_D_SQ = new BigInteger(
      "1159843021668779879193775521855586647937357759715417654439879720876111806838");

  /** (d - 1)^2 mod p */
  static final BigInteger D_MINUS_ONE_SQ = new BigInteger(
      "40440834346308536858101042469323190826248399146238708352240133220865137265952");

  // ─── Edwards25519 base point ─────────────────────────────────────────────

  // Bx: positive root satisfying Edwards curve equation with By = 4/5 mod p.
  private static final BigInteger BX = new BigInteger(
      "15112221349535807912866137220509078750507884956996801574307167488439920701478");

  // By = 4/5 mod p
  private static final BigInteger BY = BigInteger.valueOf(4)
      .multiply(BigInteger.valueOf(5).modInverse(P)).mod(P);

  // Base point in extended twisted Edwards coordinates (X, Y, Z, T), T = X*Y when Z=1.
  private static final BigInteger[] BASE_POINT =
      new BigInteger[]{BX, BY, BigInteger.ONE, fmul(BX, BY)};

  private static final SecureRandom RANDOM = new SecureRandom();
  private static final ExpandMessageXmd XMD_SHA512 = ExpandMessageXmd.forSha512();

  private Ristretto255GroupSpec() {}

  // ─── GroupSpec interface ──────────────────────────────────────────────────

  @Override
  public BigInteger groupOrder() {
    return L;
  }

  @Override
  public int elementSize() {
    return 32;
  }

  /**
   * hash_to_ristretto255 per RFC 9496 §4.3.4 / CFRG PoC reference.
   * <p>
   * Expands message to 64 bytes via expand_message_xmd (SHA-512), splits into
   * two 32-byte halves, decodes each as a little-endian field element (masking
   * bit 255), maps each via the Elligator MAP, and returns the encoded sum.
   */
  @Override
  public byte[] hashToGroup(byte[] msg, byte[] dst) {
    byte[] uniform = XMD_SHA512.expand(msg, dst, 64);
    // Each 32-byte half → mask bit 255 → decode as little-endian field element mod p
    byte[] b0 = Arrays.copyOfRange(uniform, 0, 32);
    byte[] b1 = Arrays.copyOfRange(uniform, 32, 64);
    b0[31] &= 0x7F;   // mask bit 255 (MSB of little-endian 32-byte representation)
    b1[31] &= 0x7F;
    BigInteger u0 = decodeLittleEndian(b0).mod(P);
    BigInteger u1 = decodeLittleEndian(b1).mod(P);
    BigInteger[] Q0 = mapToRistretto255(u0);
    BigInteger[] Q1 = mapToRistretto255(u1);
    return encodeRistretto255(addPoints(Q0, Q1));
  }

  /**
   * HashToScalar per RFC 9497 §4.4: expand to 64 bytes, decode as little-endian mod L.
   */
  @Override
  public BigInteger hashToScalar(byte[] msg, byte[] dst) {
    byte[] uniform = XMD_SHA512.expand(msg, dst, 64);
    return decodeLittleEndian(uniform).mod(L);
  }

  @Override
  public byte[] scalarMultiply(BigInteger scalar, byte[] element) {
    BigInteger[] pt = decodeRistretto255(element);
    return encodeRistretto255(scalarMul(pt, scalar));
  }

  @Override
  public byte[] scalarMultiplyGenerator(BigInteger scalar) {
    return encodeRistretto255(scalarMul(BASE_POINT, scalar));
  }

  @Override
  public BigInteger randomScalar() {
    BigInteger k;
    do {
      k = new BigInteger(L.bitLength(), RANDOM);
    } while (k.compareTo(BigInteger.ONE) < 0 || k.compareTo(L) >= 0);
    return k;
  }

  /** Serializes scalar as 32-byte little-endian (ristretto255 convention). */
  @Override
  public byte[] serializeScalar(BigInteger k) {
    return encodeLittleEndian(k, 32);
  }

  // ─── Field arithmetic (GF(p)) ────────────────────────────────────────────

  static BigInteger fmul(BigInteger a, BigInteger b) {
    return a.multiply(b).mod(P);
  }

  static BigInteger fadd(BigInteger a, BigInteger b) {
    return a.add(b).mod(P);
  }

  static BigInteger fsub(BigInteger a, BigInteger b) {
    return a.subtract(b).mod(P);
  }

  static BigInteger fneg(BigInteger a) {
    BigInteger r = a.mod(P);
    return r.signum() == 0 ? BigInteger.ZERO : P.subtract(r);
  }

  static BigInteger fsq(BigInteger a) {
    return a.multiply(a).mod(P);
  }

  /** IS_NEGATIVE: true if the canonical representative has LSB = 1. */
  static boolean isNegative(BigInteger u) {
    return u.mod(P).testBit(0);
  }

  /** CT_ABS: negate u if IS_NEGATIVE(u). */
  static BigInteger ctabs(BigInteger u) {
    BigInteger r = u.mod(P);
    return isNegative(r) ? P.subtract(r) : r;
  }

  // ─── SQRT_RATIO_M1 (RFC 9496 §4.2) ──────────────────────────────────────

  /**
   * Computes (was_square, root) where root = CT_ABS(sqrt(u/v)) when u/v is a
   * quadratic residue, or CT_ABS(sqrt(SQRT_M1 * u/v)) otherwise.
   *
   * <p>Used internally by encode, decode, and the Elligator MAP.
   *
   * @return BigInteger[2]: [1 if u/v was square else 0, the root]
   */
  static BigInteger[] sqrtRatioM1(BigInteger u, BigInteger v) {
    // r = (u*v^3) * (u*v^7)^((p-5)/8)
    BigInteger v3 = fmul(fsq(v), v);
    BigInteger v7 = fmul(fsq(v3), v);
    BigInteger exp = P.subtract(BigInteger.valueOf(5)).divide(BigInteger.valueOf(8));
    BigInteger r = fmul(fmul(u, v3), fmul(u, v7).modPow(exp, P));

    BigInteger check = fmul(v, fsq(r));
    BigInteger uMod = u.mod(P);

    boolean correctSign  = check.equals(uMod);
    boolean flippedSign  = check.equals(fneg(u));
    boolean flippedSignI = check.equals(fneg(fmul(u, SQRT_M1)));

    BigInteger rPrime = fmul(SQRT_M1, r);
    r = (flippedSign || flippedSignI) ? rPrime : r;
    r = ctabs(r);

    boolean wasSquare = correctSign || flippedSign;
    return new BigInteger[]{wasSquare ? BigInteger.ONE : BigInteger.ZERO, r};
  }

  // ─── Ristretto255 Decode (RFC 9496 §4.3.1) ───────────────────────────────

  /**
   * Decodes a 32-byte ristretto255 encoding to extended Edwards coordinates (X, Y, Z, T).
   *
   * @throws SecurityException if the encoding is invalid
   */
  static BigInteger[] decodeRistretto255(byte[] s) {
    if (s.length != 32) {
      throw new IllegalArgumentException("Ristretto255 encoding must be 32 bytes");
    }
    // Interpret as little-endian unsigned integer
    BigInteger sInt = decodeLittleEndian(s);
    if (sInt.compareTo(P) >= 0) {
      throw new SecurityException("Invalid ristretto255 encoding: s >= p");
    }
    if (isNegative(sInt)) {
      throw new SecurityException("Invalid ristretto255 encoding: s is negative");
    }

    BigInteger ss = fsq(sInt);
    BigInteger u1   = fsub(BigInteger.ONE, ss);                    // 1 - s^2
    BigInteger u2   = fadd(BigInteger.ONE, ss);                    // 1 + s^2
    BigInteger u2Sq = fsq(u2);
    // v = -(D * u1^2) - u2^2  (note the negation — the a=-1 correction)
    BigInteger v = fsub(fneg(fmul(D, fsq(u1))), u2Sq);

    BigInteger[] sr = sqrtRatioM1(BigInteger.ONE, fmul(v, u2Sq));
    if (sr[0].equals(BigInteger.ZERO)) {
      throw new SecurityException("Invalid ristretto255 encoding: not a quadratic residue");
    }
    BigInteger invsqrt = sr[1];

    BigInteger denX = fmul(invsqrt, u2);
    BigInteger denY = fmul(fmul(invsqrt, denX), v);
    BigInteger x    = ctabs(fmul(fmul(BigInteger.TWO, sInt).mod(P), denX));
    BigInteger y    = fmul(u1, denY);
    BigInteger t    = fmul(x, y);

    if (isNegative(t) || y.equals(BigInteger.ZERO)) {
      throw new SecurityException("Invalid ristretto255 encoding: rejected by final checks");
    }
    return new BigInteger[]{x, y, BigInteger.ONE, t};
  }

  // ─── Ristretto255 Encode (RFC 9496 §4.3.2) ───────────────────────────────

  /**
   * Encodes an Edwards25519 point (in extended coordinates) to a canonical
   * 32-byte ristretto255 encoding.
   */
  static byte[] encodeRistretto255(BigInteger[] point) {
    BigInteger x0 = point[0].mod(P);
    BigInteger y0 = point[1].mod(P);
    BigInteger z0 = point[2].mod(P);
    BigInteger t0 = point[3].mod(P);

    BigInteger u1 = fmul(fadd(z0, y0), fsub(z0, y0));   // (Z+Y)*(Z-Y)
    BigInteger u2 = fmul(x0, y0);                         // X*Y

    BigInteger[] sr    = sqrtRatioM1(BigInteger.ONE, fmul(u1, fsq(u2)));
    BigInteger invsqrt = sr[1];

    BigInteger den1 = fmul(invsqrt, u1);
    BigInteger den2 = fmul(invsqrt, u2);
    BigInteger zInv = fmul(fmul(den1, den2), t0);  // den1 * den2 * T

    BigInteger ix0          = fmul(x0, SQRT_M1);       // x0 * sqrt(-1)
    BigInteger iy0          = fmul(y0, SQRT_M1);       // y0 * sqrt(-1)
    BigInteger enchantedDen = fmul(den1, INVSQRT_A_MINUS_D);

    boolean rotate  = isNegative(fmul(t0, zInv));
    BigInteger x    = rotate ? iy0 : x0;
    BigInteger y    = rotate ? ix0 : y0;   // uses original ix0 (= x0 * sqrt(-1))
    BigInteger denInv = rotate ? enchantedDen : den2;

    if (isNegative(fmul(x, zInv))) {
      y = fneg(y);
    }

    BigInteger s = ctabs(fmul(denInv, fsub(z0, y)));
    return encodeLittleEndian(s, 32);
  }

  // ─── Elligator MAP (RFC 9496 §4.3.4 / RFC 9380 Appendix B) ──────────────

  /**
   * Maps a field element to an Edwards25519 point using the ristretto255 Elligator map.
   * Returns extended coordinates (X, Y, Z, T).
   */
  static BigInteger[] mapToRistretto255(BigInteger u) {
    BigInteger r   = fmul(SQRT_M1, fsq(u));
    BigInteger ns  = fmul(fadd(r, BigInteger.ONE), ONE_MINUS_D_SQ);   // (r+1) * ONE_MINUS_D_SQ
    // v = (-1 - r*D) * (r + D)
    BigInteger v   = fmul(fsub(fneg(BigInteger.ONE), fmul(r, D)), fadd(r, D));

    BigInteger[] sr      = sqrtRatioM1(ns, v);
    boolean wasSquare    = sr[0].equals(BigInteger.ONE);
    BigInteger s         = sr[1];

    // s_prime = -CT_ABS(s * u)
    BigInteger sPrime = fneg(ctabs(fmul(s, u)));
    s = wasSquare ? s : sPrime;
    BigInteger c = wasSquare ? fneg(BigInteger.ONE) : r;

    BigInteger N  = fsub(fmul(fmul(c, fsub(r, BigInteger.ONE)), D_MINUS_ONE_SQ), v);

    BigInteger w0 = fmul(fmul(BigInteger.TWO, s).mod(P), v);
    BigInteger w1 = fmul(N, SQRT_AD_MINUS_ONE);
    BigInteger w2 = fsub(BigInteger.ONE, fsq(s));
    BigInteger w3 = fadd(BigInteger.ONE, fsq(s));

    // Returns (X, Y, Z, T) = (w0*w3, w2*w1, w1*w3, w0*w2)
    return new BigInteger[]{fmul(w0, w3), fmul(w2, w1), fmul(w1, w3), fmul(w0, w2)};
  }

  // ─── Edwards25519 extended-coordinate arithmetic ─────────────────────────

  /**
   * Unified addition for twisted Edwards curve with a=-1.
   * Uses RFC 8032 §5.1.4 extended-coordinate formula with k = 2*d.
   *
   * <p>Input/output: (X, Y, Z, T) where T = X*Y/Z (projective).
   */
  static BigInteger[] addPoints(BigInteger[] p1, BigInteger[] p2) {
    BigInteger X1 = p1[0], Y1 = p1[1], Z1 = p1[2], T1 = p1[3];
    BigInteger X2 = p2[0], Y2 = p2[1], Z2 = p2[2], T2 = p2[3];

    // k = 2*d
    BigInteger A  = fmul(fsub(Y1, X1), fsub(Y2, X2));
    BigInteger B  = fmul(fadd(Y1, X1), fadd(Y2, X2));
    BigInteger C  = fmul(T1, fmul(fmul(BigInteger.TWO, D).mod(P), T2));
    BigInteger DD = fmul(fmul(BigInteger.TWO, Z1).mod(P), Z2);
    BigInteger E  = fsub(B, A);
    BigInteger F  = fsub(DD, C);
    BigInteger G  = fadd(DD, C);
    BigInteger H  = fadd(B, A);

    return new BigInteger[]{fmul(E, F), fmul(G, H), fmul(F, G), fmul(E, H)};
  }

  /**
   * Point doubling for twisted Edwards curve with a=-1.
   * From https://hyperelliptic.org/EFD/g1p/auto-twisted-extended.html#doubling-dbl-2008-hwcd
   */
  static BigInteger[] doublePoint(BigInteger[] pt) {
    BigInteger X = pt[0], Y = pt[1], Z = pt[2];

    BigInteger A = fsq(X);
    BigInteger B = fsq(Y);
    BigInteger C = fmul(BigInteger.TWO, fsq(Z)).mod(P);
    BigInteger Dv = fneg(A);                                    // a*A where a = -1
    BigInteger E  = fsub(fsub(fsq(fadd(X, Y)), A), B);
    BigInteger G  = fadd(Dv, B);
    BigInteger F  = fsub(G, C);
    BigInteger H  = fsub(Dv, B);

    return new BigInteger[]{fmul(E, F), fmul(G, H), fmul(F, G), fmul(E, H)};
  }

  /** The neutral element (identity) in extended coordinates: (0, 1, 1, 0). */
  static BigInteger[] neutralElement() {
    return new BigInteger[]{BigInteger.ZERO, BigInteger.ONE, BigInteger.ONE, BigInteger.ZERO};
  }

  /**
   * Scalar multiplication k*P using right-to-left double-and-add.
   * Scalar is reduced mod L before use.
   */
  static BigInteger[] scalarMul(BigInteger[] pt, BigInteger k) {
    k = k.mod(L);
    if (k.signum() == 0) {
      return neutralElement();
    }
    BigInteger[] result = neutralElement();
    BigInteger[] addend = pt;
    for (int i = 0; i < k.bitLength(); i++) {
      if (k.testBit(i)) {
        result = addPoints(result, addend);
      }
      addend = doublePoint(addend);
    }
    return result;
  }

  // ─── Endianness utilities ─────────────────────────────────────────────────

  /** Decodes a little-endian byte array to a non-negative BigInteger. */
  static BigInteger decodeLittleEndian(byte[] b) {
    byte[] rev = new byte[b.length];
    for (int i = 0; i < b.length; i++) {
      rev[i] = b[b.length - 1 - i];
    }
    return new BigInteger(1, rev);
  }

  /** Encodes a BigInteger as a {@code length}-byte little-endian array. */
  static byte[] encodeLittleEndian(BigInteger k, int length) {
    byte[] be = k.toByteArray();
    // Skip leading sign byte if present
    int start  = (be.length > length && be[0] == 0) ? 1 : 0;
    int srcLen = be.length - start;
    byte[] result = new byte[length];
    int copyLen = Math.min(srcLen, length);
    for (int i = 0; i < copyLen; i++) {
      result[i] = be[be.length - 1 - i];
    }
    return result;
  }
}
