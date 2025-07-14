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

/**
 * The KMSEProviderFactory class serves as a factory for creating instances of KMSEProvider. It
 * abstracts the creation process, allowing the system to obtain the correct SEProvider
 * instance based on the compilation target.
 */
public class KMSEProviderFactory {

  /**
   * Creates an instance of the AndroidSEProvider.
   */
  public static KMSEProvider createInstance() {
    return new KMAndroidSEProvider();
  }
}
