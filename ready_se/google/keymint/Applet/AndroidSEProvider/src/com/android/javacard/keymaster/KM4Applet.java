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
package com.android.javacard.keymaster;

import com.android.javacard.seprovider.KMAndroidSEProvider;
import com.android.javacard.seprovider.KMException;
import com.android.javacard.seprovider.KMSEProvider;
import javacard.framework.APDU;
import javacard.framework.ISO7816;
import javacard.framework.Util;

public class KM4Applet extends KMAndroidSEApplet {
  // MSB byte is for Major version and LSB byte is for Minor version.
  private static final short KM_APPLET_PACKAGE_VERSION = 0x0500;
  // This is the P1P2 constant of the APDU command header.
  private static final short P1P2 = (short) 0x7000;

  private static final short KM_VERSION = 400;
  private static final short ATTEST_VERSION = 400;

  protected KM4Applet(KMSEProvider seImpl) {
    super(seImpl);
  }

  public static void install(byte[] bArray, short bOffset, byte bLength) {
    KMAndroidSEProvider provider = new KMAndroidSEProvider();
    new KM4Applet(provider).register();
  }

  @Override
  protected void actionBeforeDeviceBooted() {
    kmDataStore.clearModuleHash();
  }

  @Override
  protected boolean handleAddtionalApdu(APDU apdu) {
    byte[] apduBuffer = apdu.getBuffer();
    switch (apduBuffer[ISO7816.OFFSET_INS]) {
      // Only KM4 commands are handled here
      // This command is allowed even if Keymint is not ready.
      // Refer to KMKeymasterApplet.isKeyMintReady()
      case INS_SET_ADDITIONAL_ATTESTATION_INFO:
        processSetAdditionalAttestationInfo(apdu);
        return true;
      default:
        return false;
    }
  }

  private short setAdditionalAttestationInfoCmd(APDU apdu) {
    short params = KMKeyParameters.expAny();
    // Array of expected arguments
    short cmd = KMArray.instance((short) 1);
    KMArray.cast(cmd).add((short) 0, params); // key params
    return receiveIncoming(apdu, cmd);
  }

  private void processSetAdditionalAttestationInfo(APDU apdu) {
    // Receive the incoming request fully from the host into buffer.
    short cmd = setAdditionalAttestationInfoCmd(apdu);
    // Re-purpose the apdu buffer as scratch pad.
    byte[] scratchPad = apdu.getBuffer();
    short keyParams = KMArray.cast(cmd).get((short) 0);
    short moduleHashPtr = KMKeyParameters.findTag(KMType.BYTES_TAG, KMType.MODULE_HASH, keyParams);
    short moduleHashLen;
    if (moduleHashPtr != KMType.INVALID_VALUE) {
      moduleHashPtr = KMByteTag.cast(moduleHashPtr).getValue();
      moduleHashLen = kmDataStore.getModuleHash(scratchPad, (short) 0);
      if (0 == moduleHashLen) {
        kmDataStore.setModuleHash(
            KMByteBlob.cast(moduleHashPtr).getBuffer(),
            KMByteBlob.cast(moduleHashPtr).getStartOff(),
            KMByteBlob.cast(moduleHashPtr).length());
      } else {
        // ModuleHash already has a different value set.
        if (0
            != Util.arrayCompare(
                scratchPad,
                (short) 0,
                KMByteBlob.cast(moduleHashPtr).getBuffer(),
                KMByteBlob.cast(moduleHashPtr).getStartOff(),
                moduleHashLen)) {
          KMException.throwIt(KMError.MODULE_HASH_ALREADY_SET);
        }
      }
    }
    sendResponse(apdu, KMError.OK);
  }

  @Override
  protected short getPackageVersion() {
    return KM_APPLET_PACKAGE_VERSION;
  }

  @Override
  protected short getP1P2() {
    return P1P2;
  }

  @Override
  protected short halVersion() {
    return KM_VERSION;
  }

  @Override
  protected short attestVersion() {
    return ATTEST_VERSION;
  }
}
