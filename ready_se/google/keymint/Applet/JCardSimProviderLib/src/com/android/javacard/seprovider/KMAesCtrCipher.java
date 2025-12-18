/*
 * Copyright(C) 2025 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" (short)0IS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.android.javacard.seprovider;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.security.CryptoException;
import javacard.security.Key;
import javacardx.crypto.Cipher;

/**
 * This class extends the `Cipher` class to provide support for the AES_CTR cipher algorithm.
 * JCardSimulator, does not natively support AES_CTR. To circumvent this limitation, this class
 * overrides the default Cipher implementation and leverages the SunJCE cipher provider to handle
 * AES_CTR operations.
 */
public class KMAesCtrCipher extends Cipher {
  public static final byte AES_CTR_NONCE_LENGTH = 16;
  private final KMCipher mCipher;

  public KMAesCtrCipher() {
    mCipher = new KMCipher(Cipher.ALG_AES_CTR);
  }

  @Override
  public void init(Key key, byte b) throws CryptoException {
    ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
  }

  @Override
  public void init(Key key, byte mode, byte[] iv, short ivStart, short ivLen)
      throws CryptoException {
    if (ivLen != AES_CTR_NONCE_LENGTH) {
      CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
    }
    mCipher.init(key, mode, (short) 0, iv, ivStart, ivLen);
  }

  @Override
  public byte getAlgorithm() {
    return mCipher.getAlgorithm();
  }

  @Override
  public byte getCipherAlgorithm() {
    return mCipher.getAlgorithm();
  }

  @Override
  public byte getPaddingAlgorithm() {
    return 0;
  }

  @Override
  public short doFinal(
      byte[] input, short inputStart, short inputLen, byte[] output, short outputOff)
      throws CryptoException {
    return mCipher.doFinal(input, inputStart, inputLen, output, outputOff);
  }

  @Override
  public short update(
      byte[] input, short inputStart, short inputLen, byte[] output, short outputOff)
      throws CryptoException {
    return mCipher.update(input, inputStart, inputLen, output, outputOff);
  }
}
