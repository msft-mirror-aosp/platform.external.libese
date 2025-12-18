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

import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.CryptoException;
import javacard.security.Key;
import javacard.security.RSAPrivateKey;

public class KMJCardSimRsa2048NoDigestSignature extends KMRsa2048NoDigestSignature {
  private final byte[] mRsaModulus; // to compare with the data value

  public KMJCardSimRsa2048NoDigestSignature(byte alg) {
    super(alg);
    mRsaModulus = JCSystem.makeTransientByteArray((short) 256, JCSystem.CLEAR_ON_RESET);
  }

  @Override
  public void init(Key key, byte mode) throws CryptoException {
    RSAPrivateKey rsaPrivateKey = (RSAPrivateKey) key;
    Util.arrayFillNonAtomic(mRsaModulus, (short) 0, (short) 256, (byte) 0);
    rsaPrivateKey.getModulus(mRsaModulus, (short) 0);
    super.init(key, mode);
  }

  @Override
  protected boolean isValidData(byte[] buf, short start, short len) {
    if (getAlgorithm() == ALG_RSA_SIGN_NOPAD) {
      if (len > 256) {
        return false;
      } else if (len == 256) {
        // JCardSimulator's raw RSA cipher operation (i.e., with no padding) does not
        // inherently validate that the numerical value of the input message is strictly
        // less than the RSA modulus. To address this, a check has been added here: if the
        // input message's byte representation, when interpreted as a positive integer, is
        // found to be greater than the RSA modulus, its magnitude is now compared against
        // the modulus before proceeding.
        short v = unsignedByteArrayCompare(buf, start, mRsaModulus, (short) 0, len);
        if (v > 0) {
          return false;
        }
      }
    } else { // pkcs1 no digest
      if (len > 245) {
        KMException.throwIt(KMError.INVALID_INPUT_LENGTH);
        return false;
      }
    }
    return true;
  }

  private byte unsignedByteArrayCompare(
      byte[] a1, short offset1, byte[] a2, short offset2, short length) {
    byte count = (byte) 0;
    short val1 = (short) 0;
    short val2 = (short) 0;

    for (; count < length; count++) {
      val1 = (short) (a1[(short) (count + offset1)] & 0x00FF);
      val2 = (short) (a2[(short) (count + offset2)] & 0x00FF);

      if (val1 < val2) {
        return -1;
      }
      if (val1 > val2) {
        return 1;
      }
    }
    return 0;
  }
}
