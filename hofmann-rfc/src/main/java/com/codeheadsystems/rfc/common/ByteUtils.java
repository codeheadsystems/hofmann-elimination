package com.codeheadsystems.rfc.common;

import java.math.BigInteger;
import org.bouncycastle.math.ec.ECPoint;

/**
 * Utility methods for octet string encoding and EC point serialization.
 */
public class ByteUtils {

  private ByteUtils() {
  }

  /**
   * Integer to Octet String Primitive (I2OSP) from RFC 8017.
   * Converts a non-negative integer to an octet string of specified length.
   *
   * @param value  the value
   * @param length the length
   * @return the byte [ ]
   */
  public static byte[] I2OSP(int value, int length) {
    if (value < 0 || (length < 4 && value >= (1 << (8 * length)))) {
      throw new IllegalArgumentException("Value too large for specified length");
    }
    byte[] result = new byte[length];
    for (int i = length - 1; i >= 0; i--) {
      result[i] = (byte) (value & 0xFF);
      value >>= 8;
    }
    return result;
  }

  /**
   * Concatenates multiple byte arrays into a single array.
   *
   * @param arrays the arrays
   * @return the byte [ ]
   */
  public static byte[] concat(byte[]... arrays) {
    int totalLength = 0;
    for (byte[] arr : arrays) {
      totalLength += arr.length;
    }
    byte[] result = new byte[totalLength];
    int offset = 0;
    for (byte[] arr : arrays) {
      System.arraycopy(arr, 0, result, offset, arr.length);
      offset += arr.length;
    }
    return result;
  }

  /**
   * Computes DH: serializes (privateKey * publicKey) as compressed SEC1.
   *
   * @param privateKey the private key
   * @param publicKey  the public key
   * @return the byte [ ]
   */
  public static byte[] dhECDH(BigInteger privateKey, ECPoint publicKey) {
    ECPoint result = publicKey.multiply(privateKey).normalize();
    return result.getEncoded(true);
  }

  /**
   * XOR two byte arrays of equal length.
   *
   * @param a the a
   * @param b the b
   * @return the byte [ ]
   */
  public static byte[] xor(byte[] a, byte[] b) {
    if (a.length != b.length) {
      throw new IllegalArgumentException("XOR arrays must have equal length: " + a.length + " vs " + b.length);
    }
    byte[] out = new byte[a.length];
    for (int i = 0; i < a.length; i++) {
      out[i] = (byte) (a[i] ^ b[i]);
    }
    return out;
  }
}
