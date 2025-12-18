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

import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import javacard.framework.Util;
import javacard.security.CryptoException;
import javacard.security.Key;
import javacard.security.MessageDigest;
import javacard.security.RSAPrivateKey;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;

public class KMJCardSimRsaOAEPEncoding extends KMRsaOAEPEncoding {
  private javax.crypto.Cipher mRsaCipher;

  public KMJCardSimRsaOAEPEncoding(byte alg) {
    super(alg);
  }

  @Override
  public void init(Key key, byte mode) throws CryptoException {
    KMSharedBuffer sharedBuffer = KMSharedBuffer.getInstance();
    try {
      byte[] scratchPad = sharedBuffer.getTransientBuffer();
      RSAPrivateKey rsaPrivateKey = (RSAPrivateKey) key;
      // Convert byte arrays into keys
      byte[] exp = null;
      if (mode == KMType.ENCRYPT) {
        exp = new byte[] {0x01, 0x00, 0x01};
      } else {
        short exponentLen = rsaPrivateKey.getExponent(scratchPad, (short) 0);
        exp = new byte[exponentLen];
        Util.arrayCopyNonAtomic(scratchPad, (short) 0, exp, (short) 0, exponentLen);
        Util.arrayFillNonAtomic(scratchPad, (short) 0, exponentLen, (byte) 0);
      }
      short modulusLen = rsaPrivateKey.getModulus(scratchPad, (short) 0);
      byte[] mod = new byte[modulusLen];
      Util.arrayCopyNonAtomic(scratchPad, (short) 0, mod, (short) 0, modulusLen);
      String modString = toHexString(mod);
      String expString = toHexString(exp);
      BigInteger modInt = new BigInteger(modString, 16);
      BigInteger expInt = new BigInteger(expString, 16);
      try {
        KeyFactory kf = KeyFactory.getInstance("RSA");
        // Create cipher with oaep padding
        OAEPParameterSpec oaepSpec =
            new OAEPParameterSpec(
                "SHA-256", "MGF1", getMGF1ParamSpec(), PSource.PSpecified.DEFAULT);
        mRsaCipher = javax.crypto.Cipher.getInstance("RSA/ECB/OAEPPadding", "SunJCE");
        if (mode == KMType.ENCRYPT) {
          RSAPublicKeySpec pubSpec = new RSAPublicKeySpec(modInt, expInt);
          java.security.interfaces.RSAPublicKey pubKey =
              (java.security.interfaces.RSAPublicKey) kf.generatePublic(pubSpec);
          mRsaCipher.init(javax.crypto.Cipher.ENCRYPT_MODE, pubKey, oaepSpec);
        } else {
          RSAPrivateKeySpec privSpec = new RSAPrivateKeySpec(modInt, expInt);
          java.security.interfaces.RSAPrivateKey privKey =
              (java.security.interfaces.RSAPrivateKey) kf.generatePrivate(privSpec);
          mRsaCipher.init(javax.crypto.Cipher.DECRYPT_MODE, privKey, oaepSpec);
        }
      } catch (NoSuchAlgorithmException e) {
        e.printStackTrace();
        CryptoException.throwIt(CryptoException.NO_SUCH_ALGORITHM);
      } catch (InvalidKeySpecException e) {
        e.printStackTrace();
        CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
      } catch (InvalidKeyException e) {
        e.printStackTrace();
        CryptoException.throwIt(CryptoException.INVALID_INIT);
      } catch (InvalidAlgorithmParameterException e) {
        e.printStackTrace();
        CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
      } catch (NoSuchPaddingException e) {
        e.printStackTrace();
        CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
      } catch (NoSuchProviderException e) {
        e.printStackTrace();
        CryptoException.throwIt(CryptoException.INVALID_INIT);
      }
    } finally {
      sharedBuffer.clean();
    }
  }

  @Override
  public short doFinal(
      byte[] inBuff, short inOffset, short inLength, byte[] outBuff, short outOffset)
      throws CryptoException {
    try {
      return (short) mRsaCipher.doFinal(inBuff, inOffset, inLength, outBuff, outOffset);
    } catch (ShortBufferException e) {
      e.printStackTrace();
      CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
    } catch (IllegalBlockSizeException e) {
      e.printStackTrace();
      CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
    } catch (BadPaddingException e) {
      e.printStackTrace();
      CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
    }
    return (short) 0;
  }

  @Override
  public short update(
      byte[] inBuff, short inOffset, short inLength, byte[] outBuff, short outOffset)
      throws CryptoException {
    try {
      return (short) mRsaCipher.update(inBuff, inOffset, inLength, outBuff, outOffset);
    } catch (ShortBufferException e) {
      e.printStackTrace();
      CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
    }
    return (short) 0;
  }

  private MGF1ParameterSpec getMGF1ParamSpec() {
    switch (getMgf1Hash()) {
      case MessageDigest.ALG_SHA:
        return MGF1ParameterSpec.SHA1;
      case MessageDigest.ALG_SHA_256:
        return MGF1ParameterSpec.SHA256;
      case MessageDigest.ALG_SHA_224:
        return MGF1ParameterSpec.SHA224;
      case MessageDigest.ALG_SHA_384:
        return MGF1ParameterSpec.SHA384;
      case MessageDigest.ALG_SHA_512:
        return MGF1ParameterSpec.SHA512;
      default:
        KMException.throwIt(KMError.UNSUPPORTED_DIGEST);
    }
    return null;
  }

  private String toHexString(byte[] num) {
    StringBuilder sb = new StringBuilder();
    for (int i = 0; i < num.length; i++) {
      sb.append(String.format("%02X", num[i]));
    }
    return sb.toString();
  }
}
