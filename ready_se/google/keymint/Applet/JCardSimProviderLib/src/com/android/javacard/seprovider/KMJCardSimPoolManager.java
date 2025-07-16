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

import javacard.security.AESKey;
import javacard.security.DESKey;
import javacard.security.HMACKey;
import javacard.security.KeyBuilder;
import javacard.security.KeyPair;
import javacard.security.Signature;
import javacardx.crypto.AEADCipher;
import javacardx.crypto.Cipher;

public class KMJCardSimPoolManager extends KMPoolManager {
  private static final short MAX_HMAC_KEY_SIZE_BITS = 512;

  @Override
  protected Signature getSignatureInstance(byte alg) {
    if (KMRsa2048NoDigestSignature.ALG_RSA_SIGN_NOPAD == alg
        || KMRsa2048NoDigestSignature.ALG_RSA_PKCS1_NODIGEST == alg) {
      return new KMJCardSimRsa2048NoDigestSignature(alg);
    } else if (KMEcdsa256NoDigestSignature.ALG_ECDSA_NODIGEST == alg) {
      return new KMJCardSimEcdsa256NoDigestSignature(alg);
    } else {
      return Signature.getInstance(alg, false);
    }
  }

  @Override
  protected Cipher getCipherInstance(byte alg) {
    if ((KMRsaOAEPEncoding.ALG_RSA_PKCS1_OAEP_SHA256_MGF1_SHA1 == alg)
        || (KMRsaOAEPEncoding.ALG_RSA_PKCS1_OAEP_SHA256_MGF1_SHA256 == alg)) {
      return new KMJCardSimRsaOAEPEncoding(alg);
    } else if (AEADCipher.ALG_AES_GCM == alg) {
      return new KMAesGcmCipher();
    } else if (AEADCipher.ALG_AES_CTR == alg) {
      return new KMAesCtrCipher();
    } else {
      return Cipher.getInstance(alg, false);
    }
  }

  @Override
  public void initECKey(KeyPair ecKeyPair) {
    // The EC P-256 Curve Parameters need not be initialized for JCardSimulator
  }

  @Override
  protected KMOperation createOperation() {
    return new KMJCardSimOperationImpl();
  }

  /**
   * Overrides the default behavior to correctly build a transient HMAC key for JCardSimulator.
   *
   * <p>The standard {@code KeyBuilder} for {@code TYPE_HMAC_TRANSIENT_RESET} creates a key in
   * memory that is cleared on deselect. This is unsuitable for our operations which require the key
   * to persist across multiple APDUs in the same session.
   *
   * <p>This method handles the key creation differently to ensure it is not cleared on deselect.
   * With TYPE_HMAC, although the memory persists longer than necessary in JCardSimulator,
   * it serves the purpose of the simulation.
   *
   * <p>TYPE_HMAC uses persistent memory in JCardSimulator
   */
  @Override
  protected HMACKey buildTransientResetHmacKey() {
    HMACKey hmacKey =
        (HMACKey)
            KeyBuilder.buildKey(
                KeyBuilder.TYPE_HMAC, MAX_HMAC_KEY_SIZE_BITS, /* keyEncryption= */ false);
    short maxSize = (short) (MAX_HMAC_KEY_SIZE_BITS / 8);
    KMSharedBuffer sharedBuffer = KMSharedBuffer.getInstance();
    try {
      byte[] tmpBuf = sharedBuffer.getTransientBuffer();
      hmacKey.setKey(tmpBuf, (short) 0, maxSize);
      return hmacKey;
    } finally {
      sharedBuffer.clean();
    }
  }

  /**
   * Overrides the default behavior to correctly build a transient AES key for JCardSimulator.
   *
   * <p>The standard {@code KeyBuilder} for {@code TYPE_AES_TRANSIENT_RESET} creates a key in memory
   * that is cleared on deselect. This is unsuitable for our operations which require the key to
   * persist across multiple APDUs in the same session.
   *
   * <p>This method handles the key creation differently to ensure it is not cleared on deselect.
   * With TYPE_AES, although the memory persists longer than necessary in JCardSimulator,
   * it serves the purpose of the simulation.
   *
   * <p>TYPE_AES uses persistent memory in JCardSimulator
   */
  @Override
  protected AESKey buildTransientResetAesKey(short len) {
    return (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, len, /* keyEncryption= */ false);
  }

  /**
   * Overrides the default behavior to correctly build a transient DES key for JCardSimulator.
   *
   * <p>The standard {@code KeyBuilder} for {@code TYPE_DES_TRANSIENT_RESET} creates a key in memory
   * that is cleared on deselect. This is unsuitable for our operations which require the key to
   * persist across multiple APDUs in the same session.
   *
   * <p>This method handles the key creation differently to ensure it is not cleared on deselect.
   * With TYPE_DES, although the memory persists longer than necessary in JCardSimulator,
   * it serves the purpose of the simulation.
   *
   * <p>TYPE_DES uses persistent memory in JCardSimulator
   */
  @Override
  protected DESKey buildTransientResetDesKey(short len) {
    return (DESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_DES, len, /* keyEncryption= */ false);
  }
}
