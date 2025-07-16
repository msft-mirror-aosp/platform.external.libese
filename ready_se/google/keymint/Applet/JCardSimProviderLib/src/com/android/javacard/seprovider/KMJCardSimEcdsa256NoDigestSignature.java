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
import java.security.AlgorithmParameters;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import javacard.framework.Util;
import javacard.security.CryptoException;
import javacard.security.Key;
import javacard.security.Signature;

public class KMJCardSimEcdsa256NoDigestSignature extends KMEcdsa256NoDigestSignature {
  private java.security.Signature mJcaSigner;

  public KMJCardSimEcdsa256NoDigestSignature(byte alg) {
    super(alg);
  }

  @Override
  public void init(Key key, byte mode) throws CryptoException {
    KeyFactory kf;
    KMSharedBuffer sharedBuffer = KMSharedBuffer.getInstance();
    try {
      byte[] keyBuf = sharedBuffer.getTransientBuffer();
      javacard.security.ECPrivateKey ecPrivateKey = (javacard.security.ECPrivateKey) key;
      short keyStart = (short) 0;
      short keyLength = ecPrivateKey.getS(keyBuf, keyStart);

      mJcaSigner = java.security.Signature.getInstance("NONEwithECDSA", "SunEC");
      kf = KeyFactory.getInstance("EC");
      AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC", "SunEC");
      // Supported curve secp256r1
      parameters.init(new ECGenParameterSpec("secp256r1"));
      ECParameterSpec ecParameters = parameters.getParameterSpec(ECParameterSpec.class);
      if (mode == Signature.MODE_SIGN) {
        byte[] privKey = new byte[keyLength];
        for (short i = 0; i < keyLength; i++) {
          privKey[i] = keyBuf[keyStart + i];
        }
        BigInteger bI = new BigInteger(1, privKey);
        ECPrivateKeySpec ecPrivateKeySpec = new ECPrivateKeySpec(bI, ecParameters);
        ECPrivateKey ecPrivKey = (ECPrivateKey) kf.generatePrivate(ecPrivateKeySpec);
        mJcaSigner.initSign(ecPrivKey);
      } else {
        // Check if  the first byte is 04 and remove it.
        if (keyBuf[keyStart] == 0x04) {
          // uncompressed format.
          keyStart++;
          keyLength--;
        }
        short i = 0;
        byte[] pubx = new byte[keyLength / 2];
        for (; i < keyLength / 2; i++) {
          pubx[i] = keyBuf[keyStart + i];
        }
        byte[] puby = new byte[keyLength / 2];
        for (i = 0; i < keyLength / 2; i++) {
          puby[i] = keyBuf[keyStart + keyLength / 2 + i];
        }
        BigInteger bIX = new BigInteger(pubx);
        BigInteger bIY = new BigInteger(puby);
        ECPoint point = new ECPoint(bIX, bIY);
        ECPublicKeySpec ecPublicKeySpec = new ECPublicKeySpec(point, ecParameters);
        ECPublicKey ecPublicKey = (ECPublicKey) kf.generatePublic(ecPublicKeySpec);
        mJcaSigner.initVerify(ecPublicKey);
      }
    } catch (NoSuchAlgorithmException e) {
      CryptoException.throwIt(CryptoException.NO_SUCH_ALGORITHM);
    } catch (NoSuchProviderException e) {
      CryptoException.throwIt(CryptoException.NO_SUCH_ALGORITHM);
    } catch (InvalidParameterSpecException e) {
      CryptoException.throwIt(CryptoException.INVALID_INIT);
    } catch (InvalidKeySpecException e) {
      CryptoException.throwIt(CryptoException.INVALID_INIT);
    } catch (InvalidKeyException e) {
      CryptoException.throwIt(CryptoException.INVALID_INIT);
    } finally {
      sharedBuffer.clean();
    }
  }

  @Override
  public short getLength() throws CryptoException {
    // This method is not supported in sunJCE
    CryptoException.throwIt(CryptoException.ILLEGAL_USE);
    return (short) 0;
  }

  @Override
  public short sign(byte[] msg, short start, short len, byte[] sig, short sigStart)
      throws CryptoException {
    try {
      mJcaSigner.update(msg, start, len);
      byte[] signature = mJcaSigner.sign();
      Util.arrayCopyNonAtomic(signature, (short) 0, sig, sigStart, (short) signature.length);
      return (short) signature.length;
    } catch (SignatureException e) {
      CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
    }
    return 0;
  }

  @Override
  public short signPreComputedHash(byte[] bytes, short i, short i1, byte[] bytes1, short i2)
      throws CryptoException {
    // Ignore. For JCard Simulator this function is never called.
    return 0;
  }
}
