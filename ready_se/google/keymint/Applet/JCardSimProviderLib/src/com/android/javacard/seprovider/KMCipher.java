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

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.AlgorithmParameterSpec;
import javacard.security.AESKey;
import javacard.security.CryptoException;
import javacard.security.Key;
import javacardx.crypto.AEADCipher;
import javacardx.crypto.Cipher;
import javax.crypto.AEADBadTagException;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * This base class provides an implementation of cryptographic operations, specifically AES_CTR and
 * AES_GCM, which are not natively supported by the standard JCardSimulator environment. It achieves
 * this by leveraging the Java Cryptography Architecture (JCA) and specifically the "SunJCE"
 * security provider to perform the actual cipher operations. This allows for simulating advanced
 * AES modes within a JCardSimulator context, bridging the gap between typical Java Card
 * capabilities and required functionalities.
 */
public class KMCipher {
  private final String mTransformation;
  private javax.crypto.Cipher mAesCipher;
  private final byte mAlgorithm;

  /**
   * Constructs a KMCipher instance for a given algorithm.
   *
   * @param algorithm The cipher algorithm to be used (e.g., AEADCipher.ALG_AES_GCM or other for AES/CTR).
   */
  public KMCipher(byte algorithm) {
    mAlgorithm = algorithm;
    if (algorithm == AEADCipher.ALG_AES_GCM) {
      mTransformation = "AES/GCM/NoPadding";
    } else {
      mTransformation = "AES/CTR/NoPadding";
    }
  }

  /**
   * Initializes the cipher for encryption or decryption. This method translates Javacard API calls
   * to the corresponding SunJCE cipher initialization.
   *
   * @param key The Javacard `Key` object containing the AES secret key.
   * @param mode The cipher mode (Cipher.MODE_ENCRYPT or Cipher.MODE_DECRYPT).
   * @param macLenBits For AES/GCM, the length of the authentication tag in bits.
   * @param ivBuffer The buffer containing the initialization vector (IV).
   * @param ivStart The offset in `ivBuffer` where the IV starts.
   * @param ivLength The length of the IV.
   * @throws CryptoException If an error occurs during cipher initialization, such as invalid key,
   *     unsupported algorithm/padding, or incorrect parameters.
   */
  public void init(
      Key key, byte mode, short macLenBits, byte[] ivBuffer, short ivStart, short ivLength)
      throws CryptoException {
    KMSharedBuffer sharedBuffer = KMSharedBuffer.getInstance();
    try {
      byte[] secret = sharedBuffer.getTransientBuffer();
      AESKey jcAesKey = (AESKey) key;
      short secretLength = jcAesKey.getKey(secret, (short) 0);
      if (secretLength != 16 && secretLength != 32) {
        CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
      }
      if (mode != Cipher.MODE_ENCRYPT && mode != Cipher.MODE_DECRYPT) {
        CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
      }
      // Convert Javacard AESKey to standard Java SecretKeySpec for SunJCE.
      java.security.Key aesKey = new SecretKeySpec(secret, (short) 0, secretLength, "AES");
      try {
        // Instantiate the SunJCE cipher with the specified transformation.
        mAesCipher = javax.crypto.Cipher.getInstance(mTransformation, "SunJCE");
      } catch (NoSuchAlgorithmException e) {
        e.printStackTrace();
        CryptoException.throwIt(CryptoException.NO_SUCH_ALGORITHM);
      } catch (NoSuchProviderException e) {
        e.printStackTrace();
        CryptoException.throwIt(CryptoException.INVALID_INIT);
      } catch (NoSuchPaddingException e) {
        e.printStackTrace();
        CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
      }
      // Generate the appropriate algorithm parameter specification (GCM or IV).
      AlgorithmParameterSpec spec = generateAlgParamSpec(macLenBits, ivBuffer, ivStart, ivLength);
      try {
        // Map Javacard mode to SunJCE cipher mode.
        if (mode == Cipher.MODE_ENCRYPT) {
          mode = javax.crypto.Cipher.ENCRYPT_MODE;
        } else {
          mode = javax.crypto.Cipher.DECRYPT_MODE;
        }
        mAesCipher.init(mode, aesKey, spec);
      } catch (InvalidKeyException e) {
        e.printStackTrace();
        CryptoException.throwIt(CryptoException.INVALID_INIT);
      } catch (InvalidAlgorithmParameterException e) {
        e.printStackTrace();
        CryptoException.throwIt(CryptoException.NO_SUCH_ALGORITHM);
      }
    } finally {
      sharedBuffer.clean();
    }
  }

  /**
   * Generates the appropriate `AlgorithmParameterSpec` based on the cipher algorithm. For AES_GCM,
   * it returns a `GCMParameterSpec`; otherwise, an `IvParameterSpec` for AES_CTR.
   *
   * @param tagLen The tag length for GCM.
   * @param iv The IV buffer.
   * @param ivOff The offset of the IV in the buffer.
   * @param ivLen The length of the IV.
   * @return The appropriate `AlgorithmParameterSpec` instance.
   */
  private AlgorithmParameterSpec generateAlgParamSpec(
      short tagLen, byte[] iv, short ivOff, short ivLen) {
    if (mAlgorithm == AEADCipher.ALG_AES_GCM) {
      return new GCMParameterSpec(tagLen, iv, ivOff, ivLen);
    } else {
      return new IvParameterSpec(iv, ivOff, ivLen);
    }
  }

  /**
   * Returns the algorithm used by this cipher instance.
   *
   * @return The algorithm byte.
   */
  public byte getAlgorithm() {
    return mAlgorithm;
  }

  /**
   * Completes a multiple-part encryption or decryption operation.
   *
   * @param buffer The input buffer containing the data to be processed.
   * @param startOff The offset in the input buffer.
   * @param length The number of bytes to process.
   * @param out The output buffer to store the processed data.
   * @param outOff The offset in the output buffer.
   * @return The number of bytes processed and stored in the output buffer.
   * @throws CryptoException If an error occurs during the final operation, such as a bad
   *     authentication tag (for GCM) or illegal block size/padding.
   */
  public short doFinal(byte[] buffer, short startOff, short length, byte[] out, short outOff)
      throws CryptoException {
    try {
      return (short) mAesCipher.doFinal(buffer, startOff, length, out, outOff);
    } catch (AEADBadTagException e) {
      e.printStackTrace();
      // Translate AEADBadTagException to a Javacard-specific error.
      KMException.throwIt(KMError.VERIFICATION_FAILED);
    } catch (ShortBufferException e) {
      e.printStackTrace();
      CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
    } catch (IllegalBlockSizeException e) {
      CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
    } catch (BadPaddingException e) {
      CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
    }
    return (short) 0; // Should not be reached
  }

  /**
   * Continues a multiple-part encryption or decryption operation.
   *
   * @param buffer The input buffer containing the data to be processed.
   * @param startOff The offset in the input buffer.
   * @param length The number of bytes to process.
   * @param out The output buffer to store the processed data.
   * @param outOff The offset in the output buffer.
   * @return The number of bytes processed and stored in the output buffer.
   * @throws CryptoException If an error occurs during the update operation.
   */
  public short update(byte[] buffer, short startOff, short length, byte[] out, short outOff)
      throws CryptoException {
    try {
      return (short) mAesCipher.update(buffer, startOff, length, out, outOff);
    } catch (ShortBufferException e) {
      e.printStackTrace();
      CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
    } catch (IllegalStateException e) {
      e.printStackTrace();
      CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
    }
    return (short) 0; // Should not be reached
  }

  /**
   * Processes additional authenticated data (AAD) for AEAD ciphers (like AES/GCM). This data is
   * authenticated but not encrypted.
   *
   * @param buffer The buffer containing the AAD.
   * @param startOff The offset in the AAD buffer.
   * @param length The length of the AAD.
   * @throws CryptoException If an error occurs during AAD processing, such as an illegal argument
   *     or unsupported operation.
   */
  public void updateAAD(byte[] buffer, short startOff, short length) {
    try {
      mAesCipher.updateAAD(buffer, startOff, length);
    } catch (IllegalArgumentException e) {
      e.printStackTrace();
      CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
    } catch (IllegalStateException e) {
      CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
    } catch (UnsupportedOperationException e) {
      // This might happen if updateAAD is called on a non-AEAD cipher,
      // though controlled by `transformation`.
      CryptoException.throwIt(CryptoException.ILLEGAL_USE);
    }
  }

  /**
   * Returns the output size of the cipher operation for a given input length.
   *
   * @param inputLen The length of the input data.
   * @return The expected output size.
   */
  public short getOutputSize(int inputLen) {
    return (short) mAesCipher.getOutputSize(inputLen);
  }
}
