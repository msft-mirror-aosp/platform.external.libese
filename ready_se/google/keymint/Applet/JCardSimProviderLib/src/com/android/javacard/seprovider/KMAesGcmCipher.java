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
import javacardx.crypto.AEADCipher;

/**
 * This class extends the `Cipher` class to provide support for the AES_GCM cipher algorithm.
 * JCardSimulator, does not natively support AES_GCM. To circumvent this limitation, this class
 * overrides the default Cipher implementation and leverages the SunJCE cipher provider to handle
 * AES_GCM operations.
 */
public class KMAesGcmCipher extends AEADCipher {
  private final KMCipher mCipher;
  private short mTagLengthBits;

  public KMAesGcmCipher() {
    mCipher = new KMCipher(AEADCipher.ALG_AES_GCM);
  }

  void setAesGcmMacLengthBits(short macLengthBits) {
    mTagLengthBits = macLengthBits;
  }

  @Override
  public void init(Key key, byte b) throws CryptoException {
    ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
  }

  @Override
  public void init(Key key, byte mode, byte[] iv, short ivStart, short ivLen)
      throws CryptoException {
    if (ivLen != KMBaseSEProvider.AES_GCM_NONCE_LENGTH) {
      CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
    }
    mCipher.init(key, mode, mTagLengthBits, iv, ivStart, ivLen);
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
  public void init(Key key, byte b, byte[] bytes, short i, short i1, short i2, short i3, short i4)
      throws CryptoException {
    ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
  }

  @Override
  public void updateAAD(byte[] aad, short start, short length) throws CryptoException {
    mCipher.updateAAD(aad, start, length);
  }

  @Override
  public short doFinal(
      byte[] input, short inputStart, short inputLen, byte[] output, short outputOff)
      throws CryptoException {
    // reset the tagLengthBits
    mTagLengthBits = 0;
    return mCipher.doFinal(input, inputStart, inputLen, output, outputOff);
  }

  @Override
  public short update(
      byte[] input, short inputStart, short inputLen, byte[] output, short outputOff)
      throws CryptoException {
    return mCipher.update(input, inputStart, inputLen, output, outputOff);
  }

  @Override
  public short retrieveTag(byte[] authTag, short authTagStart, short authTagLen)
      throws CryptoException {
    // Ignore. For JCard Simulator this function is never called.
    return (short) 0;
  }

  @Override
  public boolean verifyTag(byte[] bytes, short i, short i1, short i2) throws CryptoException {
    // Ignore. For JCard Simulator this function is never called.
    return false;
  }

  public short getAesGcmOutputSize(short inputLen) {
    return mCipher.getOutputSize(inputLen);
  }
}
