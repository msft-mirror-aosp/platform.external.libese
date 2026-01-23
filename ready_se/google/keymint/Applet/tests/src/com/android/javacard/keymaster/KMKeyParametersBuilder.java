/*
 * Copyright(C) 2026 The Android Open Source Project
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
package com.android.javacard.keymaster;

import java.util.HashMap;

/** This class utilizes the builder pattern to construct the {@code KMKeyParameters}. */
public class KMKeyParametersBuilder {
    private static final long MAX_EXPIRATION_TIME_MS = 253402300799000L; // Dec 31 9999 23:59:59

    private final HashMap<String, Short> mKeyParameters;

    public KMKeyParametersBuilder() {
        mKeyParameters = new HashMap<>();
    }

    private short enumArrayTag(short key, byte[] values) {
        short byteBlobPtr = KMByteBlob.instance(values, (short) 0, (short) values.length);
        return KMEnumArrayTag.instance(key, byteBlobPtr);
    }

    private short enumTag(short key, byte value) {
        return KMEnumTag.instance(key, value);
    }

    private short byteTag(short key, byte[] value) {
        short byteBlobPtr = KMByteBlob.instance(value, (short) 0, (short) value.length);
        return KMByteTag.instance(key, byteBlobPtr);
    }

    private short integerTag(short key, int value) {
        byte[] intVal =
                new byte[] {
                    (byte) (value >> 24), (byte) (value >> 16), (byte) (value >> 8), (byte) value
                };
        short intPtr = KMInteger.uint_32(intVal, (short) 0);
        return KMIntegerTag.instance(KMType.UINT_TAG, key, intPtr);
    }

    private short dateTag(short key, long value) {
        byte[] longVal =
                new byte[] {
                    (byte) (value >> 56),
                    (byte) (value >> 48),
                    (byte) (value >> 40),
                    (byte) (value >> 32),
                    (byte) (value >> 24),
                    (byte) (value >> 16),
                    (byte) (value >> 8),
                    (byte) value
                };
        short longPtr = KMInteger.uint_64(longVal, (short) 0);
        return KMIntegerTag.instance(KMType.DATE_TAG, key, longPtr);
    }

    private short boolTag(short key) {
        return KMBoolTag.instance(key);
    }

    public KMKeyParametersBuilder noAuthRequired() {
        mKeyParameters.put("no_auth_required", boolTag(KMType.NO_AUTH_REQUIRED));
        return this;
    }

    public KMKeyParametersBuilder callerNonce() {
        mKeyParameters.put("caller_nonce", boolTag(KMType.CALLER_NONCE));
        return this;
    }

    public KMKeyParametersBuilder unlockedDeviceRequired() {
        mKeyParameters.put("unlocked_device_req", boolTag(KMType.UNLOCKED_DEVICE_REQUIRED));
        return this;
    }

    public KMKeyParametersBuilder algorithm(byte value) {
        mKeyParameters.put("algorithm", enumTag(KMType.ALGORITHM, value));
        return this;
    }

    public KMKeyParametersBuilder applicationId(byte[] appId) {
        mKeyParameters.put("app_id", byteTag(KMType.APPLICATION_ID, appId));
        return this;
    }

    public KMKeyParametersBuilder applicationData(byte[] appData) {
        mKeyParameters.put("app_data", byteTag(KMType.APPLICATION_DATA, appData));
        return this;
    }

    public KMKeyParametersBuilder nonce(byte[] nonce) {
        mKeyParameters.put("nonce", byteTag(KMType.NONCE, nonce));
        return this;
    }

    public KMKeyParametersBuilder keySize(short keySize) {
        mKeyParameters.put("key_size", integerTag(KMType.KEYSIZE, keySize));
        return this;
    }

    public KMKeyParametersBuilder macLength(short macLength) {
        mKeyParameters.put("mac_length", integerTag(KMType.MAC_LENGTH, macLength));
        return this;
    }

    public KMKeyParametersBuilder minMacLength(short macLength) {
        mKeyParameters.put("min_mac_length", integerTag(KMType.MIN_MAC_LENGTH, macLength));
        return this;
    }

    public KMKeyParametersBuilder padding(byte[] values) {
        mKeyParameters.put("padding", enumArrayTag(KMType.PADDING, values));
        return this;
    }

    public KMKeyParametersBuilder purpose(byte[] values) {
        mKeyParameters.put("purpose", enumArrayTag(KMType.PURPOSE, values));
        return this;
    }

    public KMKeyParametersBuilder blockMode(byte[] values) {
        mKeyParameters.put("block_mode", enumArrayTag(KMType.BLOCK_MODE, values));
        return this;
    }

    public KMKeyParametersBuilder setDefaultValidity() {
        short notBeforeTag = dateTag(KMType.CERTIFICATE_NOT_BEFORE, 0L);
        short notAfterTag = dateTag(KMType.CERTIFICATE_NOT_AFTER, MAX_EXPIRATION_TIME_MS);
        mKeyParameters.put("not_before", notBeforeTag);
        mKeyParameters.put("not_after", notAfterTag);
        return this;
    }

    public short build() {
        int len = mKeyParameters.size();
        short arr = KMArray.instance((short) len);
        short idx = 0;
        for (Short value : mKeyParameters.values()) {
            KMArray.cast(arr).add(idx++, value);
        }
        return KMKeyParameters.instance(arr);
    }
}
