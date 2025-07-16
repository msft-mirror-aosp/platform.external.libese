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

import javacard.framework.Util;
import javacard.security.Key;
import javacardx.crypto.AEADCipher;
import javacardx.crypto.Cipher;

public class KMJCardSimOperationImpl extends KMOperationImpl {
  @Override
  public short getAESGCMOutputSize(short dataSize, short macLength) {
    if (getResource(KMPoolManager.RESOURCE_TYPE_CRYPTO) instanceof KMAesGcmCipher) {
      return ((KMAesGcmCipher) getResource(KMPoolManager.RESOURCE_TYPE_CRYPTO))
          .getAesGcmOutputSize(dataSize);
    }
    return super.getAESGCMOutputSize(dataSize, macLength);
  }

  /**
   * Overrides the base implementation to handle special initialization requirements for AES/GCM in
   * the JCardSimulator environment.
   */
  @Override
  protected void initSymmetricCipher(Key key, byte[] ivBuffer, short ivStart, short ivLength) {
    Cipher symmCipher = (Cipher) getResource(KMPoolManager.RESOURCE_TYPE_CRYPTO);
    byte cipherAlg = symmCipher.getAlgorithm();
    // JCardSimulator uses a JCE provider (like SunJCE) which requires the AES/GCM tag length
    // to be specified during cipher initialization. The standard Java Card API handles this
    // differently, so we must intercept the init call for this specific algorithm.
    if (cipherAlg == AEADCipher.ALG_AES_GCM) {
      // Retrieve the MAC/tag length from the operation parameters and convert it to bits.
      short macLenBits = (short) (getMacLengthBits() * 8);
      // Cast to our custom AES/GCM cipher wrapper and set the expected tag length.
      ((KMAesGcmCipher) symmCipher).setAesGcmMacLengthBits(macLenBits);
    }
    // Proceed with the standard initialization now that the special handling is complete.
    super.initSymmetricCipher(key, ivBuffer, ivStart, ivLength);
  }

  @Override
  public void updateAAD(byte[] dataBuf, short dataStart, short dataLength) {
    ((KMAesGcmCipher) getResource(KMPoolManager.RESOURCE_TYPE_CRYPTO))
        .updateAAD(dataBuf, dataStart, dataLength);
  }

  @Override
  protected short finishCipher(
      byte[] inputDataBuf,
      short inputDataStart,
      short inputDataLen,
      byte[] outputDataBuf,
      short outputDataStart) {
    short cipherAlg = getAlgorithmType();
    short padding = getPaddingAlgorithm();
    short mode = getPurpose();
    KMSharedBuffer sharedBuffer = KMSharedBuffer.getInstance();
    try {
      byte[] tmpArray = sharedBuffer.getTransientBuffer();
      if ((cipherAlg == KMType.DES || cipherAlg == KMType.AES)
          && padding == KMType.PKCS7
          && mode == KMType.ENCRYPT) {
        short len =
            addPkcs7Padding(inputDataBuf, inputDataStart, inputDataLen, tmpArray, (short) 0);
        inputDataBuf = tmpArray;
        inputDataStart = (short) 0;
        inputDataLen = len;
      }
      short len =
          ((Cipher) getResource(KMPoolManager.RESOURCE_TYPE_CRYPTO))
              .doFinal(inputDataBuf, inputDataStart, inputDataLen, outputDataBuf, outputDataStart);
      // JCardSim removes leading zeros during decryption in case of no padding - so add that
      // back.
      if (cipherAlg == KMType.RSA
          && padding == KMType.PADDING_NONE
          && mode == KMType.DECRYPT
          && len < 256) {
        Util.arrayFillNonAtomic(tmpArray, (short) 0, (short) 256, (byte) 0);
        Util.arrayCopyNonAtomic(
            outputDataBuf, outputDataStart, tmpArray, (short) (outputDataStart + 256 - len), len);
        Util.arrayCopyNonAtomic(tmpArray, (short) 0, outputDataBuf, outputDataStart, (short) 256);
        len = 256;
      } else if ((cipherAlg == KMType.AES || cipherAlg == KMType.DES) // PKCS7
          && padding == KMType.PKCS7
          && mode == KMType.DECRYPT) {
        len = removePkcs7Padding(outputDataBuf, outputDataStart, len);
      }
      return len;
    } finally {
      sharedBuffer.clean();
    }
  }
}
