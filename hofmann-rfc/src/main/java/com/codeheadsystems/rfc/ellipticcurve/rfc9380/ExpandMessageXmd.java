package com.codeheadsystems.rfc.ellipticcurve.rfc9380;

import com.codeheadsystems.rfc.common.ByteUtils;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

/**
 * Implementation of expand_message_xmd from RFC 9380 Section 5.3.1.
 * <p>
 * Expands a message using a hash function to produce uniform bytes.
 * This is used as part of the hash_to_field operation.
 * Supports SHA-256, SHA-384, and SHA-512.
 */
public class ExpandMessageXmd {

  private static final int MAX_DST_LENGTH = 255;

  private final String hashAlgorithm;
  private final int bInBytes; // hash output size
  private final int rInBytes; // hash block size

  private ExpandMessageXmd(String hashAlgorithm, int bInBytes, int rInBytes) {
    this.hashAlgorithm = hashAlgorithm;
    this.bInBytes = bInBytes;
    this.rInBytes = rInBytes;
  }

  /**
   * SHA-256: bInBytes=32, rInBytes=64.
   */
  public static ExpandMessageXmd forSha256() {
    return new ExpandMessageXmd("SHA-256", 32, 64);
  }

  /**
   * SHA-384: bInBytes=48, rInBytes=128 (SHA-384 uses the same 1024-bit block as SHA-512).
   */
  public static ExpandMessageXmd forSha384() {
    return new ExpandMessageXmd("SHA-384", 48, 128);
  }

  /**
   * SHA-512: bInBytes=64, rInBytes=128.
   */
  public static ExpandMessageXmd forSha512() {
    return new ExpandMessageXmd("SHA-512", 64, 128);
  }

  /**
   * Expands a message into a uniformly random byte string.
   *
   * @param msg        The message to expand
   * @param dst        Domain Separation Tag (DST)
   * @param lenInBytes The desired output length in bytes
   * @return A byte array of length lenInBytes containing uniformly distributed bytes
   * @throws IllegalArgumentException if parameters are invalid
   */
  public byte[] expand(byte[] msg, byte[] dst, int lenInBytes) {
    if (lenInBytes <= 0 || lenInBytes > 65535) {
      throw new IllegalArgumentException("lenInBytes must be between 1 and 65535");
    }

    // Calculate ell = ceil(len_in_bytes / b_in_bytes)
    int ell = (lenInBytes + bInBytes - 1) / bInBytes;
    if (ell > 255) {
      throw new IllegalArgumentException("lenInBytes too large for " + hashAlgorithm);
    }

    try {
      MessageDigest digest = MessageDigest.getInstance(hashAlgorithm);

      // Prepare DST_prime = DST || I2OSP(len(DST), 1)
      byte[] dstPrime = prepareDstPrime(dst);

      // Z_pad = I2OSP(0, r_in_bytes)
      byte[] zPad = new byte[rInBytes];

      // l_i_b_str = I2OSP(len_in_bytes, 2)
      byte[] libStr = ByteUtils.I2OSP(lenInBytes, 2);

      // msg_prime = Z_pad || msg || l_i_b_str || I2OSP(0, 1) || DST_prime
      byte[] msgPrime = ByteBuffer.allocate(rInBytes + msg.length + 2 + 1 + dstPrime.length)
          .put(zPad)
          .put(msg)
          .put(libStr)
          .put((byte) 0)
          .put(dstPrime)
          .array();

      // b_0 = H(msg_prime)
      byte[] b0 = digest.digest(msgPrime);

      // b_1 = H(b_0 || I2OSP(1, 1) || DST_prime)
      digest.reset();
      digest.update(b0);
      digest.update((byte) 1);
      digest.update(dstPrime);
      byte[] b1 = digest.digest();

      // Build uniform_bytes
      byte[] uniformBytes = new byte[ell * bInBytes];
      System.arraycopy(b1, 0, uniformBytes, 0, bInBytes);

      byte[] bPrev = b1;
      for (int i = 2; i <= ell; i++) {
        // b_i = H(strxor(b_0, b_(i-1)) || I2OSP(i, 1) || DST_prime)
        digest.reset();
        byte[] xored = strxor(b0, bPrev);
        digest.update(xored);
        digest.update((byte) i);
        digest.update(dstPrime);
        byte[] bi = digest.digest();

        System.arraycopy(bi, 0, uniformBytes, (i - 1) * bInBytes, bInBytes);
        bPrev = bi;
      }

      // Return only the requested number of bytes
      return Arrays.copyOf(uniformBytes, lenInBytes);

    } catch (NoSuchAlgorithmException e) {
      throw new RuntimeException(hashAlgorithm + " not available", e);
    }
  }

  /**
   * Prepares DST_prime according to RFC 9380 Section 5.3.3.
   * If DST is longer than 255 bytes, it's hashed first.
   */
  private byte[] prepareDstPrime(byte[] dst) throws NoSuchAlgorithmException {
    if (dst.length > MAX_DST_LENGTH) {
      // DST_prime = H("H2C-OVERSIZE-DST-" || DST) || I2OSP(len(H), 1)
      MessageDigest digest = MessageDigest.getInstance(hashAlgorithm);
      digest.update("H2C-OVERSIZE-DST-".getBytes(StandardCharsets.UTF_8));
      digest.update(dst);
      byte[] hashedDst = digest.digest();

      byte[] dstPrime = new byte[hashedDst.length + 1];
      System.arraycopy(hashedDst, 0, dstPrime, 0, hashedDst.length);
      dstPrime[hashedDst.length] = (byte) bInBytes;
      return dstPrime;
    } else {
      // DST_prime = DST || I2OSP(len(DST), 1)
      byte[] dstPrime = new byte[dst.length + 1];
      System.arraycopy(dst, 0, dstPrime, 0, dst.length);
      dstPrime[dst.length] = (byte) dst.length;
      return dstPrime;
    }
  }

  /**
   * XOR two byte arrays of the same length.
   */
  private byte[] strxor(byte[] a, byte[] b) {
    if (a.length != b.length) {
      throw new IllegalArgumentException("Arrays must have the same length");
    }
    byte[] result = new byte[a.length];
    for (int i = 0; i < a.length; i++) {
      result[i] = (byte) (a[i] ^ b[i]);
    }
    return result;
  }
}
