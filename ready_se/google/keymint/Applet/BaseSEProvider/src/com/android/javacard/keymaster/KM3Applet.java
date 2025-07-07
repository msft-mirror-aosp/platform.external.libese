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
import com.android.javacard.seprovider.KMSEProvider;

public class KM3Applet extends KMAndroidSEApplet {

  private static final short KM_VERSION = 300;
  private static final short ATTEST_VERSION = 300;
  // This is the P1P2 constant of the APDU command header.
  private static final short P1P2 = (short) 0x6000;

  protected KM3Applet(KMSEProvider seImpl) {
    super(seImpl);
  }

  public static void install(byte[] bArray, short bOffset, byte bLength) {
    KMAndroidSEProvider provider = new KMAndroidSEProvider();
    new KM3Applet(provider).register();
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
