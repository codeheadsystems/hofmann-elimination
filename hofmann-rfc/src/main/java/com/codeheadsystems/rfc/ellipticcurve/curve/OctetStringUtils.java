package com.codeheadsystems.rfc.ellipticcurve.curve;

/**
 * Utility methods for octet string encoding and EC point serialization.
 */
public class OctetStringUtils {

  private OctetStringUtils() {
  }

  /**
   * Integer to Octet String Primitive (I2OSP) from RFC 8017.
   * Converts a non-negative integer to an octet string of specified length.
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

}
