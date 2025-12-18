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

public class KM3Applet extends KMAndroidSEApplet {

  private static final short KM_VERSION = 300;
  private static final short ATTEST_VERSION = 300;
  // This is the P1P2 constant of the APDU command header.
  private static final short P1P2 = (short) 0x6000;

  protected KM3Applet() {
    super(KMSEProviderFactory.createInstance());
  }

  /**
   * Installs this applet.
   *
   * @param bArray the array containing installation parameters
   * @param bOffset the starting offset in bArray
   * @param bLength the length in bytes of the parameter data in bArray
   */
  public static void install(byte[] bArray, short bOffset, byte bLength) {
    if (bLength == 0) {
      // This change addresses a compatibility issue with JCardSim.
      // The `install()` method in Java Card's framework receives a buffer containing installation
      // parameters, including the applet's AID. However, JCardSim doesn't send the AID in this
      // buffer, causing the buffer length to be 0. Calling `register()` with installation
      // parameters in this scenario would throw an exception. This conditional check ensures that
      // the no-argument `register()` method is called when the buffer length is 0, allowing the
      // applet to be installed correctly in JCardSim.
      new KM3Applet().register();
    } else {
      new KM3Applet().register(bArray, (short) (bOffset + 1), bArray[bOffset]);
    }
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
