package com.codeheadsystems.hofmann.rfc9380;

import com.codeheadsystems.hofmann.Curve;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

/**
 * Implementation of expand_message_xmd from RFC 9380 Section 5.3.1.
 * <p>
 * Expands a message using a hash function (SHA-256) to produce uniform bytes.
 * This is used as part of the hash_to_field operation.
 */
public class ExpandMessageXmd {

  private static final String HASH_ALGORITHM = "SHA-256";
  private static final int B_IN_BYTES = 32; // SHA-256 output size
  private static final int R_IN_BYTES = 64; // SHA-256 block size
  private static final int MAX_DST_LENGTH = 255;

  /**
   * Expands a message into a uniformly random byte string.
   *
   * @param msg        The message to expand
   * @param dst        Domain Separation Tag (DST)
   * @param lenInBytes The desired output length in bytes
   * @return A byte array of length lenInBytes containing uniformly distributed bytes
   * @throws IllegalArgumentException if parameters are invalid
   */
  public static byte[] expand(byte[] msg, byte[] dst, int lenInBytes) {
    if (lenInBytes <= 0 || lenInBytes > 65535) {
      throw new IllegalArgumentException("lenInBytes must be between 1 and 65535");
    }

    // Calculate ell = ceil(len_in_bytes / b_in_bytes)
    int ell = (lenInBytes + B_IN_BYTES - 1) / B_IN_BYTES;
    if (ell > 255) {
      throw new IllegalArgumentException("lenInBytes too large for SHA-256");
    }

    try {
      MessageDigest digest = MessageDigest.getInstance(HASH_ALGORITHM);

      // Prepare DST_prime = DST || I2OSP(len(DST), 1)
      byte[] dstPrime = prepareDstPrime(dst);

      // Z_pad = I2OSP(0, r_in_bytes)
      byte[] zPad = new byte[R_IN_BYTES];

      // l_i_b_str = I2OSP(len_in_bytes, 2)
      byte[] libStr = Curve.I2OSP(lenInBytes, 2);

      // msg_prime = Z_pad || msg || l_i_b_str || I2OSP(0, 1) || DST_prime
      byte[] msgPrime = ByteBuffer.allocate(R_IN_BYTES + msg.length + 2 + 1 + dstPrime.length)
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
      byte[] uniformBytes = new byte[ell * B_IN_BYTES];
      System.arraycopy(b1, 0, uniformBytes, 0, B_IN_BYTES);

      byte[] bPrev = b1;
      for (int i = 2; i <= ell; i++) {
        // b_i = H(strxor(b_0, b_(i-1)) || I2OSP(i, 1) || DST_prime)
        digest.reset();
        byte[] xored = strxor(b0, bPrev);
        digest.update(xored);
        digest.update((byte) i);
        digest.update(dstPrime);
        byte[] bi = digest.digest();

        System.arraycopy(bi, 0, uniformBytes, (i - 1) * B_IN_BYTES, B_IN_BYTES);
        bPrev = bi;
      }

      // Return only the requested number of bytes
      return Arrays.copyOf(uniformBytes, lenInBytes);

    } catch (NoSuchAlgorithmException e) {
      throw new RuntimeException("SHA-256 not available", e);
    }
  }

  /**
   * Prepares DST_prime according to RFC 9380 Section 5.3.3.
   * If DST is longer than 255 bytes, it's hashed first.
   */
  private static byte[] prepareDstPrime(byte[] dst) throws NoSuchAlgorithmException {
    if (dst.length > MAX_DST_LENGTH) {
      // DST_prime = H("H2C-OVERSIZE-DST-" || DST) || I2OSP(len(H), 1)
      MessageDigest digest = MessageDigest.getInstance(HASH_ALGORITHM);
      digest.update("H2C-OVERSIZE-DST-".getBytes(StandardCharsets.UTF_8));
      digest.update(dst);
      byte[] hashedDst = digest.digest();

      byte[] dstPrime = new byte[hashedDst.length + 1];
      System.arraycopy(hashedDst, 0, dstPrime, 0, hashedDst.length);
      dstPrime[hashedDst.length] = (byte) B_IN_BYTES;
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
  private static byte[] strxor(byte[] a, byte[] b) {
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
