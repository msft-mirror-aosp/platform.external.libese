package com.android.javacard.seprovider;

import javacard.framework.JCSystem;
import javacard.framework.Util;

/**
 * Manages a shared, transient buffer for temporary data storage within the seprovider package.
 */
public class KMSharedBuffer {

  /**
   * The size of the shared transient buffer in bytes. This should be large enough to accommodate
   * the biggest temporary data structure needed by any operation.
   */
  public static final short TRANSIENT_BUFFER_SIZE = 300;

  // The underlying transient byte array for temporary storage.
  private byte[] mTransientBuffer;

  // TODO Introduce an `IN_USE` flag to prevent double using it in the same call stack
  // The single, shared instance of this class.
  private static KMSharedBuffer sSharedBuffer;

  /**
   * Returns the single instance of the {@code KMSharedBuffer}.
   *
   * @return The singleton {@code KMSharedBuffer} instance.
   */
  public static KMSharedBuffer getInstance() {
    if (sSharedBuffer == null) {
      sSharedBuffer = new KMSharedBuffer();
    }
    return sSharedBuffer;
  }

  /** Private constructor to initialize transient resources and enforce the Singleton pattern. */
  private KMSharedBuffer() {
    // Allocate the main transient buffer. It will be cleared automatically by the
    // Java Card RE on card reset or applet deselect.
    mTransientBuffer =
        JCSystem.makeTransientByteArray(TRANSIENT_BUFFER_SIZE, JCSystem.CLEAR_ON_DESELECT);
  }

  /**
   * Returns the shared transient buffer.
   *
   * @return The shared {@code byte[]} buffer.
   */
  public byte[] getTransientBuffer() {
    return mTransientBuffer;
  }

  /**
   * Cleans the buffer's contents.
   *
   * <p>This method MUST be called in a {@code finally} block after an operation using the buffer is
   * complete. It securely zeroes out the buffer to prevent data leakage between APDU commands
   */
  public void clean() {
    Util.arrayFillNonAtomic(mTransientBuffer, (short) 0, TRANSIENT_BUFFER_SIZE, (byte) 0);
  }
}
