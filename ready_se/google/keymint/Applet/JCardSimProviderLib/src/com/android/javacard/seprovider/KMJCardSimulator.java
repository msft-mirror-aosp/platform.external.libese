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
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.android.javacard.seprovider;

import javacard.framework.APDU;
import javacard.framework.ISO7816;
import javacard.framework.Util;
import javacard.security.AESKey;
import javacard.security.ECPrivateKey;
import javacard.security.ECPublicKey;
import javacard.security.MessageDigest;
import javacard.security.RSAPrivateKey;
import javacard.security.Signature;
import javacardx.crypto.Cipher;
import org.globalplatform.upgrade.Element;

/**
 * This class implements KMSEProvider and provides all the necessary crypto operations required to
 * support the KeyMint specification. This class supports AES, 3DES, HMAC, RSA, ECDSA, ECDH
 * algorithms additionally it also supports ECDSA_NO_DIGEST, RSA_NO_DIGEST and RSA_OAEP_MGF1_SHA1
 * and RSA_OAEP_MGF1_SHA256 algorithms. This class follows the pattern of Init-Update-Final for the
 * crypto operations.
 */
public class KMJCardSimulator extends KMBaseSEProvider {
  private final Signature mEcSigner;
  private final Signature mRsaSigner;

  // Implements JCard Simulator based restricted crypto provider
  public KMJCardSimulator() {
    mEcSigner = Signature.getInstance(Signature.ALG_ECDSA_SHA_256, false);
    mRsaSigner = Signature.getInstance(Signature.ALG_RSA_SHA_256_PKCS1, false);

    // The `hmacKey` object is reused across different key sizes.
    // To ensure `JcardSimulator` allocates enough buffer for the largest possible key,
    // we preemptively set the `hmacKey` with an empty buffer of the maximum expected size (64
    // bytes).
    // This guarantees sufficient memory is reserved regardless of the actual key size used
    // later.
    try {
      byte[] tmpArray = sharedBuffer.getTransientBuffer();
      hmacKey.setKey(tmpArray, (short) 0, (short) 64);
    } finally {
      sharedBuffer.clean();
    }
  }

  @Override
  protected short aesGCMEncryptInternal(
      AESKey key,
      byte[] secret,
      short secretStart,
      short secretLen,
      byte[] encSecret,
      short encSecretStart,
      byte[] nonce,
      short nonceStart,
      short nonceLen,
      byte[] authData,
      short authDataStart,
      short authDataLen,
      byte[] authTag,
      short authTagStart,
      short authTagLen) {
    if (aesGcmCipher == null) {
      aesGcmCipher = new KMAesGcmCipher();
    }
    ((KMAesGcmCipher) aesGcmCipher).setAesGcmMacLengthBits((short) (authTagLen * 8));
    aesGcmCipher.init(key, Cipher.MODE_ENCRYPT, nonce, nonceStart, nonceLen);
    if (authDataLen != 0) {
      aesGcmCipher.updateAAD(authData, authDataStart, authDataLen);
    }
    short cipherLen =
        aesGcmCipher.doFinal(secret, secretStart, secretLen, encSecret, encSecretStart);
    Util.arrayCopyNonAtomic(
        encSecret,
        (short) (encSecretStart + cipherLen - authTagLen),
        authTag,
        authTagStart,
        authTagLen);
    return (short) (cipherLen - authTagLen);
  }

  @Override
  protected boolean aesGCMDecryptInternal(
      AESKey key,
      byte[] encSecret,
      short encSecretStart,
      short encSecretLen,
      byte[] secret,
      short secretStart,
      byte[] nonce,
      short nonceStart,
      short nonceLen,
      byte[] authData,
      short authDataStart,
      short authDataLen,
      byte[] authTag,
      short authTagStart,
      short authTagLen) {
    boolean verification = true;
    if (aesGcmCipher == null) {
      aesGcmCipher = new KMAesGcmCipher();
    }
    ((KMAesGcmCipher) aesGcmCipher).setAesGcmMacLengthBits((short) (authTagLen * 8));
    aesGcmCipher.init(key, Cipher.MODE_DECRYPT, nonce, nonceStart, nonceLen);
    if (authDataLen != 0) {
      aesGcmCipher.updateAAD(authData, authDataStart, authDataLen);
    }
    try {
      short totalInputLen = (short) (encSecretLen + authTagLen);
      byte[] totalInputBuf = new byte[totalInputLen];
      Util.arrayCopyNonAtomic(encSecret, encSecretStart, totalInputBuf, (short) 0, encSecretLen);
      Util.arrayCopyNonAtomic(authTag, authTagStart, totalInputBuf, encSecretLen, authTagLen);
      aesGcmCipher.doFinal(totalInputBuf, (short) 0, totalInputLen, secret, secretStart);
    } catch (KMException e) {
      if (KMException.reason() == KMError.VERIFICATION_FAILED) {
        verification = false;
      }
      KMException.throwIt(KMException.reason());
    }
    return verification;
  }

  @Override
  public boolean isValidCLA(APDU apdu) {
    byte[] apduBuffer = apdu.getBuffer();
    short apduClass = (short) (apduBuffer[ISO7816.OFFSET_CLA] & 0x00FF);

    // Validate CLA.
    if (((apduClass & 0x00E0) == 0x0020) || (apduClass == 0x00FF)) {
      return false;
    }
    return true;
  }

  @Override
  public short rsaSign256Pkcs1(
      byte[] secret,
      short secretStart,
      short secretLength,
      byte[] modBuf,
      short modStart,
      short modLength,
      byte[] inputDataBuf,
      short inputDataStart,
      short inputDataLength,
      byte[] outputDataBuf,
      short outputDataStart) {
    RSAPrivateKey key = (RSAPrivateKey) rsaKeyPair.getPrivate();
    key.setExponent(secret, secretStart, secretLength);
    key.setModulus(modBuf, modStart, modLength);
    mRsaSigner.init(key, Signature.MODE_SIGN);
    return mRsaSigner.sign(
        inputDataBuf, inputDataStart, inputDataLength, outputDataBuf, outputDataStart);
  }

  @Override
  public short ecSign256(
      byte[] secret,
      short secretStart,
      short secretLength,
      byte[] inputDataBuf,
      short inputDataStart,
      short inputDataLength,
      byte[] outputDataBuf,
      short outputDataStart) {
    ECPrivateKey key = (ECPrivateKey) ecKeyPair.getPrivate();
    key.setS(secret, secretStart, secretLength);
    mEcSigner.init(key, Signature.MODE_SIGN);
    return mEcSigner.sign(
        inputDataBuf, inputDataStart, inputDataLength, outputDataBuf, outputDataStart);
  }

  @Override
  public short signWithDeviceUniqueKey(
      KMKey deviceUniqueKey,
      byte[] inputDataBuf,
      short inputDataStart,
      short inputDataLength,
      byte[] outputDataBuf,
      short outputDataStart) {
    ECPrivateKey key =
        (ECPrivateKey) ((KMECDeviceUniqueKeyPair) deviceUniqueKey).ecKeyPair.getPrivate();
    mEcSigner.init(key, Signature.MODE_SIGN);
    return mEcSigner.sign(
        inputDataBuf, inputDataStart, inputDataLength, outputDataBuf, outputDataStart);
  }

  @Override
  public boolean ecVerify256(
      byte[] pubKey,
      short pubKeyOffset,
      short pubKeyLen,
      byte[] inputDataBuf,
      short inputDataStart,
      short inputDataLength,
      byte[] signatureDataBuf,
      short signatureDataStart,
      short signatureDataLen) {
    ECPublicKey key = (ECPublicKey) ecKeyPair.getPublic();
    key.setW(pubKey, pubKeyOffset, pubKeyLen);

    mEcSigner.init(key, Signature.MODE_VERIFY);
    return mEcSigner.verify(
        inputDataBuf,
        inputDataStart,
        inputDataLength,
        signatureDataBuf,
        signatureDataStart,
        signatureDataLen);
  }

  @Override
  public boolean isUpgrading() {
    return false;
  }

  @Override
  public short messageDigest256(
      byte[] inBuff, short inOffset, short inLength, byte[] outBuff, short outOffset) {
    MessageDigest digest =
        MessageDigest.getInitializedMessageDigestInstance(MessageDigest.ALG_SHA_256, false);
    return digest.doFinal(inBuff, inOffset, inLength, outBuff, outOffset);
  }

  @Override
  public void onSave(Element element, byte interfaceType, Object object) {}

  @Override
  public Object onRestore(Element element) {
    return null;
  }

  @Override
  public short getBackupPrimitiveByteCount(byte interfaceType) {
    return 0;
  }

  @Override
  public short getBackupObjectCount(byte interfaceType) {
    return 0;
  }

  @Override
  protected KMPoolManager createPoolManager() {
    return new KMJCardSimPoolManager();
  }

  @Override
  protected KMRsaOAEPEncoding createRsaOaepDecipher(byte alg) {
    return new KMJCardSimRsaOAEPEncoding(alg);
  }
}
