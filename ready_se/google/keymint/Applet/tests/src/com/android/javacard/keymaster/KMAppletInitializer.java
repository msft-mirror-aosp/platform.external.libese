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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import com.android.javacard.seprovider.KMSEProvider;

import com.licel.jcardsim.smartcardio.CardSimulator;

import javacard.framework.Util;
import javacard.security.ECPrivateKey;
import javacard.security.KeyBuilder;
import javacard.security.Signature;

import java.security.SecureRandom;

import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

/**
 * This class provisions the KeyMint Applet and also helps in transitioning the Applet to the Ready
 * State so that it starts accepting and executing the commands.
 *
 * <p>The provisioning phase initializes the following data:
 *
 * <ul>
 *   <li>UDS KeyPair
 *   <li>UDS Certificate Chain
 *   <li>Attestation IDs
 *   <li>Shared Secret
 *   <li>OEM Root Public Key
 *   <li>Secure Boot Mode (On/Off)
 * </ul>
 *
 * <p>Transitioning KeyMint to Ready state requires executing below commands
 *
 * <ul>
 *   <li>{@code INS_SEND_ROT_DATA_CMD}
 *   <li>{@code INS_COMPUTE_SHARED_HMAC_CMD}
 *   <li>{@code INS_INIT_STRONGBOX_CMD} (OS version, system patch level, and vendor patch level)
 * </ul>
 *
 * @param simulator The {@code CardSimulator} instance used to manage the applet lifecycle
 *     (installation and deletion) and to transmit APDU commands to the applet within the JCardSim
 *     environment.
 * @param encoder The {@code KMEncoder} instance used to Encode the data into CBOR format.
 * @param decoder The {@code KMDecoder} instance used to parse the CBOR data.
 * @param seProvider The {@code KMSEProvider} implementation, wrapping a {@code KMJCardSimulator}
 *     instance, It is used to perform the cryptographic operations required by the KeyMint
 *     specification.
 * @param p1 P1 field in the APDU.
 */
public record KMAppletInitializer(
        CardSimulator simulator,
        KMSEProvider seProvider,
        KMEncoder encoder,
        KMDecoder decoder,
        byte p1) {

    // Provision Commands
    private static final byte INS_KEYMINT_PROVIDER_APDU_START = 0x00;
    private static final byte INS_PROVISION_ATTEST_IDS_CMD = INS_KEYMINT_PROVIDER_APDU_START + 3;
    private static final byte INS_SE_FACTORY_PROVISIONING_LOCK_CMD =
            INS_KEYMINT_PROVIDER_APDU_START + 10;
    private static final byte INS_PROVISION_OEM_ROOT_PUBLIC_KEY_CMD =
            INS_KEYMINT_PROVIDER_APDU_START + 11;
    private static final byte INS_PROVISION_RKP_DEVICE_UNIQUE_KEYPAIR_CMD =
            INS_KEYMINT_PROVIDER_APDU_START + 13;
    private static final byte INS_PROVISION_RKP_UDS_CERT_CHAIN_CMD =
            INS_KEYMINT_PROVIDER_APDU_START + 14;
    private static final byte INS_PROVISION_PRESHARED_SECRET_CMD =
            INS_KEYMINT_PROVIDER_APDU_START + 15;
    private static final byte INS_OEM_LOCK_PROVISIONING_CMD = INS_KEYMINT_PROVIDER_APDU_START + 17;
    private static final byte INS_PROVISION_SECURE_BOOT_MODE_CMD =
            INS_KEYMINT_PROVIDER_APDU_START + 18;

    // KeyMint Functional APDU Commands
    private static final byte KEYMINT_CMD_APDU_START = 0x20;
    private static final byte INS_COMPUTE_SHARED_HMAC_CMD = KEYMINT_CMD_APDU_START + 10; // 0x2A
    private static final byte INS_GET_HMAC_SHARING_PARAM_CMD = KEYMINT_CMD_APDU_START + 13; // 0x2D
    private static final byte INS_EARLY_BOOT_ENDED_CMD = KEYMINT_CMD_APDU_START + 21; // 0x35
    private static final byte INS_INIT_STRONGBOX_CMD = KEYMINT_CMD_APDU_START + 26; // 0x3A
    private static final byte INS_GET_ROT_CHALLENGE_CMD = KEYMINT_CMD_APDU_START + 45; // 0x4D
    private static final byte INS_SEND_ROT_DATA_CMD = KEYMINT_CMD_APDU_START + 47; // 0x4F

    // Hard-coded Attestation IDS
    public static final byte[] BRAND = {0x67, 0x65, 0x6e, 0x65, 0x72, 0x69, 0x63}; // generic
    public static final byte[] DEVICE = {
        0x76, 0x73, 0x6f, 0x63, 0x5f, 0x78, 0x38, 0x36, 0x5f, 0x36, 0x34
    }; // vsoc_x86_64
    public static final byte[] PRODUCT = {
        0x61, 0x6f, 0x73, 0x70, 0x5f, 0x63, 0x66, 0x5f, 0x78, 0x38, 0x36, 0x5f, 0x36, 0x34, 0x5f,
        0x70, 0x68, 0x6f, 0x6e, 0x65
    }; // aosp_cf_x86_64_phone
    public static final byte[] SERIAL = {
        0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39
    }; // 123456789
    public static final byte[] IMEI = {
        0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30
    };
    public static final byte[] SECOND_IMEI = {
        0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x31
    };
    public static final byte[] MEID = {
        0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30
    };
    public static final byte[] MANUFACTURER = {0x47, 0x6f, 0x6f, 0x67, 0x6c, 0x65}; // Google

    public static final byte[] MODEL = {
        0x43, 0x75, 0x74, 0x74, 0x6c, 0x65, 0x66, 0x69, 0x73, 0x68, 0x20, 0x78, 0x38, 0x36, 0x5f,
        0x36, 0x34, 0x20, 0x70, 0x68, 0x6f, 0x6e, 0x65
    }; // Cuttlefish x86_64 phone

    // Hard-coded System Properties
    public static final int OS_VERSION = 1;
    public static final int OS_PATCH_LEVEL = 1;
    public static final int VENDOR_PATCH_LEVEL = 1;
    public static final int BOOT_PATCH_LEVEL = 1;

    private static final byte[] EC_PRIV_KEY = {
        (byte) 0x21, (byte) 0xe0, (byte) 0x86, (byte) 0x43, (byte) 0x2a,
        (byte) 0x15, (byte) 0x19, (byte) 0x84, (byte) 0x59, (byte) 0xcf,
        (byte) 0x36, (byte) 0x3a, (byte) 0x50, (byte) 0xfc, (byte) 0x14,
        (byte) 0xc9, (byte) 0xda, (byte) 0xad, (byte) 0xf9, (byte) 0x35,
        (byte) 0xf5, (byte) 0x27, (byte) 0xc2, (byte) 0xdf, (byte) 0xd7,
        (byte) 0x1e, (byte) 0x4d, (byte) 0x6d, (byte) 0xbc, (byte) 0x42,
        (byte) 0xe5, (byte) 0x44
    };
    private static final byte[] EC_PUB_KEY = {
        (byte) 0x04, (byte) 0xeb, (byte) 0x9e, (byte) 0x79, (byte) 0xf8,
        (byte) 0x42, (byte) 0x63, (byte) 0x59, (byte) 0xac, (byte) 0xcb,
        (byte) 0x2a, (byte) 0x91, (byte) 0x4c, (byte) 0x89, (byte) 0x86,
        (byte) 0xcc, (byte) 0x70, (byte) 0xad, (byte) 0x90, (byte) 0x66,
        (byte) 0x93, (byte) 0x82, (byte) 0xa9, (byte) 0x73, (byte) 0x26,
        (byte) 0x13, (byte) 0xfe, (byte) 0xac, (byte) 0xcb, (byte) 0xf8,
        (byte) 0x21, (byte) 0x27, (byte) 0x4c, (byte) 0x21, (byte) 0x74,
        (byte) 0x97, (byte) 0x4a, (byte) 0x2a, (byte) 0xfe, (byte) 0xa5,
        (byte) 0xb9, (byte) 0x4d, (byte) 0x7f, (byte) 0x66, (byte) 0xd4,
        (byte) 0xe0, (byte) 0x65, (byte) 0x10, (byte) 0x66, (byte) 0x35,
        (byte) 0xbc, (byte) 0x53, (byte) 0xb7, (byte) 0xa0, (byte) 0xa3,
        (byte) 0xa6, (byte) 0x71, (byte) 0x58, (byte) 0x3e, (byte) 0xdb,
        (byte) 0x3e, (byte) 0x11, (byte) 0xae, (byte) 0x10, (byte) 0x14
    };

    private static final byte[] EC_ATTEST_ROOT_CERT = {
        (byte) 0x30, (byte) 0x82, (byte) 0x02, (byte) 0xad, (byte) 0x30, (byte) 0x82, (byte) 0x02,
        (byte) 0x53, (byte) 0xa0, (byte) 0x03, (byte) 0x02, (byte) 0x01, (byte) 0x02, (byte) 0x02,
        (byte) 0x14, (byte) 0x77, (byte) 0x76, (byte) 0x38, (byte) 0x73, (byte) 0x7f, (byte) 0x38,
        (byte) 0xe6, (byte) 0x9e, (byte) 0xd9, (byte) 0x75, (byte) 0x5e, (byte) 0x67, (byte) 0xab,
        (byte) 0x0f, (byte) 0x0e, (byte) 0x3d, (byte) 0xe3, (byte) 0xb4, (byte) 0x94, (byte) 0xb3,
        (byte) 0x30, (byte) 0x0a, (byte) 0x06, (byte) 0x08, (byte) 0x2a, (byte) 0x86, (byte) 0x48,
        (byte) 0xce, (byte) 0x3d, (byte) 0x04, (byte) 0x03, (byte) 0x02, (byte) 0x30, (byte) 0x81,
        (byte) 0xa3, (byte) 0x31, (byte) 0x0b, (byte) 0x30, (byte) 0x09, (byte) 0x06, (byte) 0x03,
        (byte) 0x55, (byte) 0x04, (byte) 0x06, (byte) 0x13, (byte) 0x02, (byte) 0x55, (byte) 0x53,
        (byte) 0x31, (byte) 0x13, (byte) 0x30, (byte) 0x11, (byte) 0x06, (byte) 0x03, (byte) 0x55,
        (byte) 0x04, (byte) 0x08, (byte) 0x0c, (byte) 0x0a, (byte) 0x43, (byte) 0x61, (byte) 0x6c,
        (byte) 0x69, (byte) 0x66, (byte) 0x6f, (byte) 0x72, (byte) 0x6e, (byte) 0x69, (byte) 0x61,
        (byte) 0x31, (byte) 0x14, (byte) 0x30, (byte) 0x12, (byte) 0x06, (byte) 0x03, (byte) 0x55,
        (byte) 0x04, (byte) 0x07, (byte) 0x0c, (byte) 0x0b, (byte) 0x53, (byte) 0x61, (byte) 0x6e,
        (byte) 0x66, (byte) 0x72, (byte) 0x61, (byte) 0x6e, (byte) 0x73, (byte) 0x69, (byte) 0x63,
        (byte) 0x6f, (byte) 0x31, (byte) 0x0f, (byte) 0x30, (byte) 0x0d, (byte) 0x06, (byte) 0x03,
        (byte) 0x55, (byte) 0x04, (byte) 0x0a, (byte) 0x0c, (byte) 0x06, (byte) 0x47, (byte) 0x6f,
        (byte) 0x6f, (byte) 0x67, (byte) 0x6c, (byte) 0x65, (byte) 0x31, (byte) 0x19, (byte) 0x30,
        (byte) 0x17, (byte) 0x06, (byte) 0x03, (byte) 0x55, (byte) 0x04, (byte) 0x0b, (byte) 0x0c,
        (byte) 0x10, (byte) 0x41, (byte) 0x6e, (byte) 0x64, (byte) 0x72, (byte) 0x6f, (byte) 0x69,
        (byte) 0x64, (byte) 0x20, (byte) 0x53, (byte) 0x65, (byte) 0x63, (byte) 0x75, (byte) 0x72,
        (byte) 0x69, (byte) 0x74, (byte) 0x79, (byte) 0x31, (byte) 0x1c, (byte) 0x30, (byte) 0x1a,
        (byte) 0x06, (byte) 0x03, (byte) 0x55, (byte) 0x04, (byte) 0x03, (byte) 0x0c, (byte) 0x13,
        (byte) 0x47, (byte) 0x6f, (byte) 0x6f, (byte) 0x67, (byte) 0x6c, (byte) 0x65, (byte) 0x20,
        (byte) 0x63, (byte) 0x61, (byte) 0x20, (byte) 0x73, (byte) 0x74, (byte) 0x72, (byte) 0x6f,
        (byte) 0x6e, (byte) 0x67, (byte) 0x62, (byte) 0x6f, (byte) 0x78, (byte) 0x31, (byte) 0x1f,
        (byte) 0x30, (byte) 0x1d, (byte) 0x06, (byte) 0x09, (byte) 0x2a, (byte) 0x86, (byte) 0x48,
        (byte) 0x86, (byte) 0xf7, (byte) 0x0d, (byte) 0x01, (byte) 0x09, (byte) 0x01, (byte) 0x16,
        (byte) 0x10, (byte) 0x73, (byte) 0x68, (byte) 0x61, (byte) 0x77, (byte) 0x6e, (byte) 0x40,
        (byte) 0x67, (byte) 0x6f, (byte) 0x6f, (byte) 0x67, (byte) 0x6c, (byte) 0x65, (byte) 0x2e,
        (byte) 0x63, (byte) 0x6f, (byte) 0x6d, (byte) 0x30, (byte) 0x1e, (byte) 0x17, (byte) 0x0d,
        (byte) 0x32, (byte) 0x31, (byte) 0x30, (byte) 0x31, (byte) 0x32, (byte) 0x38, (byte) 0x30,
        (byte) 0x36, (byte) 0x35, (byte) 0x37, (byte) 0x33, (byte) 0x38, (byte) 0x5a, (byte) 0x17,
        (byte) 0x0d, (byte) 0x34, (byte) 0x31, (byte) 0x30, (byte) 0x31, (byte) 0x32, (byte) 0x33,
        (byte) 0x30, (byte) 0x36, (byte) 0x35, (byte) 0x37, (byte) 0x33, (byte) 0x38, (byte) 0x5a,
        (byte) 0x30, (byte) 0x81, (byte) 0xa3, (byte) 0x31, (byte) 0x0b, (byte) 0x30, (byte) 0x09,
        (byte) 0x06, (byte) 0x03, (byte) 0x55, (byte) 0x04, (byte) 0x06, (byte) 0x13, (byte) 0x02,
        (byte) 0x55, (byte) 0x53, (byte) 0x31, (byte) 0x13, (byte) 0x30, (byte) 0x11, (byte) 0x06,
        (byte) 0x03, (byte) 0x55, (byte) 0x04, (byte) 0x08, (byte) 0x0c, (byte) 0x0a, (byte) 0x43,
        (byte) 0x61, (byte) 0x6c, (byte) 0x69, (byte) 0x66, (byte) 0x6f, (byte) 0x72, (byte) 0x6e,
        (byte) 0x69, (byte) 0x61, (byte) 0x31, (byte) 0x14, (byte) 0x30, (byte) 0x12, (byte) 0x06,
        (byte) 0x03, (byte) 0x55, (byte) 0x04, (byte) 0x07, (byte) 0x0c, (byte) 0x0b, (byte) 0x53,
        (byte) 0x61, (byte) 0x6e, (byte) 0x66, (byte) 0x72, (byte) 0x61, (byte) 0x6e, (byte) 0x73,
        (byte) 0x69, (byte) 0x63, (byte) 0x6f, (byte) 0x31, (byte) 0x0f, (byte) 0x30, (byte) 0x0d,
        (byte) 0x06, (byte) 0x03, (byte) 0x55, (byte) 0x04, (byte) 0x0a, (byte) 0x0c, (byte) 0x06,
        (byte) 0x47, (byte) 0x6f, (byte) 0x6f, (byte) 0x67, (byte) 0x6c, (byte) 0x65, (byte) 0x31,
        (byte) 0x19, (byte) 0x30, (byte) 0x17, (byte) 0x06, (byte) 0x03, (byte) 0x55, (byte) 0x04,
        (byte) 0x0b, (byte) 0x0c, (byte) 0x10, (byte) 0x41, (byte) 0x6e, (byte) 0x64, (byte) 0x72,
        (byte) 0x6f, (byte) 0x69, (byte) 0x64, (byte) 0x20, (byte) 0x53, (byte) 0x65, (byte) 0x63,
        (byte) 0x75, (byte) 0x72, (byte) 0x69, (byte) 0x74, (byte) 0x79, (byte) 0x31, (byte) 0x1c,
        (byte) 0x30, (byte) 0x1a, (byte) 0x06, (byte) 0x03, (byte) 0x55, (byte) 0x04, (byte) 0x03,
        (byte) 0x0c, (byte) 0x13, (byte) 0x47, (byte) 0x6f, (byte) 0x6f, (byte) 0x67, (byte) 0x6c,
        (byte) 0x65, (byte) 0x20, (byte) 0x63, (byte) 0x61, (byte) 0x20, (byte) 0x73, (byte) 0x74,
        (byte) 0x72, (byte) 0x6f, (byte) 0x6e, (byte) 0x67, (byte) 0x62, (byte) 0x6f, (byte) 0x78,
        (byte) 0x31, (byte) 0x1f, (byte) 0x30, (byte) 0x1d, (byte) 0x06, (byte) 0x09, (byte) 0x2a,
        (byte) 0x86, (byte) 0x48, (byte) 0x86, (byte) 0xf7, (byte) 0x0d, (byte) 0x01, (byte) 0x09,
        (byte) 0x01, (byte) 0x16, (byte) 0x10, (byte) 0x73, (byte) 0x68, (byte) 0x61, (byte) 0x77,
        (byte) 0x6e, (byte) 0x40, (byte) 0x67, (byte) 0x6f, (byte) 0x6f, (byte) 0x67, (byte) 0x6c,
        (byte) 0x65, (byte) 0x2e, (byte) 0x63, (byte) 0x6f, (byte) 0x6d, (byte) 0x30, (byte) 0x59,
        (byte) 0x30, (byte) 0x13, (byte) 0x06, (byte) 0x07, (byte) 0x2a, (byte) 0x86, (byte) 0x48,
        (byte) 0xce, (byte) 0x3d, (byte) 0x02, (byte) 0x01, (byte) 0x06, (byte) 0x08, (byte) 0x2a,
        (byte) 0x86, (byte) 0x48, (byte) 0xce, (byte) 0x3d, (byte) 0x03, (byte) 0x01, (byte) 0x07,
        (byte) 0x03, (byte) 0x42, (byte) 0x00, (byte) 0x04, (byte) 0x9c, (byte) 0xc8, (byte) 0x1a,
        (byte) 0xcf, (byte) 0xc8, (byte) 0x8a, (byte) 0xb9, (byte) 0x2f, (byte) 0x1f, (byte) 0x87,
        (byte) 0xb6, (byte) 0xb1, (byte) 0x34, (byte) 0x8e, (byte) 0x75, (byte) 0x38, (byte) 0x1d,
        (byte) 0x3a, (byte) 0xed, (byte) 0xcd, (byte) 0xf0, (byte) 0x8f, (byte) 0x91, (byte) 0x55,
        (byte) 0x0d, (byte) 0x1a, (byte) 0x6d, (byte) 0x6f, (byte) 0xf0, (byte) 0x70, (byte) 0x2d,
        (byte) 0x55, (byte) 0x4a, (byte) 0x30, (byte) 0xb9, (byte) 0xbe, (byte) 0xab, (byte) 0x30,
        (byte) 0xc7, (byte) 0xb3, (byte) 0xa2, (byte) 0x2d, (byte) 0xfc, (byte) 0xcc, (byte) 0x84,
        (byte) 0x0a, (byte) 0xc9, (byte) 0xbf, (byte) 0xb9, (byte) 0x31, (byte) 0x5a, (byte) 0xb7,
        (byte) 0x8c, (byte) 0xa0, (byte) 0x72, (byte) 0x21, (byte) 0xdd, (byte) 0x27, (byte) 0xac,
        (byte) 0xfe, (byte) 0xcd, (byte) 0x34, (byte) 0x11, (byte) 0x82, (byte) 0xa3, (byte) 0x63,
        (byte) 0x30, (byte) 0x61, (byte) 0x30, (byte) 0x1d, (byte) 0x06, (byte) 0x03, (byte) 0x55,
        (byte) 0x1d, (byte) 0x0e, (byte) 0x04, (byte) 0x16, (byte) 0x04, (byte) 0x14, (byte) 0x81,
        (byte) 0x6c, (byte) 0xe6, (byte) 0x5a, (byte) 0x30, (byte) 0xf8, (byte) 0xe2, (byte) 0xaf,
        (byte) 0x7f, (byte) 0xef, (byte) 0x04, (byte) 0x23, (byte) 0x50, (byte) 0xdc, (byte) 0x4e,
        (byte) 0xa4, (byte) 0x48, (byte) 0xe2, (byte) 0x05, (byte) 0x62, (byte) 0x30, (byte) 0x1f,
        (byte) 0x06, (byte) 0x03, (byte) 0x55, (byte) 0x1d, (byte) 0x23, (byte) 0x04, (byte) 0x18,
        (byte) 0x30, (byte) 0x16, (byte) 0x80, (byte) 0x14, (byte) 0x81, (byte) 0x6c, (byte) 0xe6,
        (byte) 0x5a, (byte) 0x30, (byte) 0xf8, (byte) 0xe2, (byte) 0xaf, (byte) 0x7f, (byte) 0xef,
        (byte) 0x04, (byte) 0x23, (byte) 0x50, (byte) 0xdc, (byte) 0x4e, (byte) 0xa4, (byte) 0x48,
        (byte) 0xe2, (byte) 0x05, (byte) 0x62, (byte) 0x30, (byte) 0x0f, (byte) 0x06, (byte) 0x03,
        (byte) 0x55, (byte) 0x1d, (byte) 0x13, (byte) 0x01, (byte) 0x01, (byte) 0xff, (byte) 0x04,
        (byte) 0x05, (byte) 0x30, (byte) 0x03, (byte) 0x01, (byte) 0x01, (byte) 0xff, (byte) 0x30,
        (byte) 0x0e, (byte) 0x06, (byte) 0x03, (byte) 0x55, (byte) 0x1d, (byte) 0x0f, (byte) 0x01,
        (byte) 0x01, (byte) 0xff, (byte) 0x04, (byte) 0x04, (byte) 0x03, (byte) 0x02, (byte) 0x01,
        (byte) 0x86, (byte) 0x30, (byte) 0x0a, (byte) 0x06, (byte) 0x08, (byte) 0x2a, (byte) 0x86,
        (byte) 0x48, (byte) 0xce, (byte) 0x3d, (byte) 0x04, (byte) 0x03, (byte) 0x02, (byte) 0x03,
        (byte) 0x48, (byte) 0x00, (byte) 0x30, (byte) 0x45, (byte) 0x02, (byte) 0x21, (byte) 0x00,
        (byte) 0xaf, (byte) 0x64, (byte) 0xe6, (byte) 0xa3, (byte) 0x6c, (byte) 0xae, (byte) 0xd3,
        (byte) 0x38, (byte) 0x02, (byte) 0xa1, (byte) 0x1e, (byte) 0x0e, (byte) 0x98, (byte) 0xa1,
        (byte) 0x91, (byte) 0xa8, (byte) 0x92, (byte) 0xe6, (byte) 0xf8, (byte) 0x79, (byte) 0x1a,
        (byte) 0x9f, (byte) 0x83, (byte) 0xd1, (byte) 0xb3, (byte) 0x23, (byte) 0x74, (byte) 0xd3,
        (byte) 0x3d, (byte) 0xb5, (byte) 0x4f, (byte) 0xc4, (byte) 0x02, (byte) 0x20, (byte) 0x74,
        (byte) 0xba, (byte) 0xeb, (byte) 0x9d, (byte) 0x57, (byte) 0x35, (byte) 0x09, (byte) 0x80,
        (byte) 0x20, (byte) 0x63, (byte) 0xb7, (byte) 0x0b, (byte) 0x15, (byte) 0xb6, (byte) 0xe5,
        (byte) 0xc1, (byte) 0x72, (byte) 0xa6, (byte) 0x8a, (byte) 0x4e, (byte) 0x9e, (byte) 0x57,
        (byte) 0x83, (byte) 0xd8, (byte) 0x63, (byte) 0xa7, (byte) 0x3c, (byte) 0x1a, (byte) 0x7d,
        (byte) 0x20, (byte) 0x85, (byte) 0xc6
    };

    private static final byte[] EC_ATTEST_CERT = {
        (byte) 0x30, (byte) 0x82, (byte) 0x02, (byte) 0x94, (byte) 0x30, (byte) 0x82, (byte) 0x02,
        (byte) 0x3b, (byte) 0xa0, (byte) 0x03, (byte) 0x02, (byte) 0x01, (byte) 0x02, (byte) 0x02,
        (byte) 0x02, (byte) 0x10, (byte) 0x00, (byte) 0x30, (byte) 0x0a, (byte) 0x06, (byte) 0x08,
        (byte) 0x2a, (byte) 0x86, (byte) 0x48, (byte) 0xce, (byte) 0x3d, (byte) 0x04, (byte) 0x03,
        (byte) 0x02, (byte) 0x30, (byte) 0x81, (byte) 0xa3, (byte) 0x31, (byte) 0x0b, (byte) 0x30,
        (byte) 0x09, (byte) 0x06, (byte) 0x03, (byte) 0x55, (byte) 0x04, (byte) 0x06, (byte) 0x13,
        (byte) 0x02, (byte) 0x55, (byte) 0x53, (byte) 0x31, (byte) 0x13, (byte) 0x30, (byte) 0x11,
        (byte) 0x06, (byte) 0x03, (byte) 0x55, (byte) 0x04, (byte) 0x08, (byte) 0x0c, (byte) 0x0a,
        (byte) 0x43, (byte) 0x61, (byte) 0x6c, (byte) 0x69, (byte) 0x66, (byte) 0x6f, (byte) 0x72,
        (byte) 0x6e, (byte) 0x69, (byte) 0x61, (byte) 0x31, (byte) 0x14, (byte) 0x30, (byte) 0x12,
        (byte) 0x06, (byte) 0x03, (byte) 0x55, (byte) 0x04, (byte) 0x07, (byte) 0x0c, (byte) 0x0b,
        (byte) 0x53, (byte) 0x61, (byte) 0x6e, (byte) 0x66, (byte) 0x72, (byte) 0x61, (byte) 0x6e,
        (byte) 0x73, (byte) 0x69, (byte) 0x63, (byte) 0x6f, (byte) 0x31, (byte) 0x0f, (byte) 0x30,
        (byte) 0x0d, (byte) 0x06, (byte) 0x03, (byte) 0x55, (byte) 0x04, (byte) 0x0a, (byte) 0x0c,
        (byte) 0x06, (byte) 0x47, (byte) 0x6f, (byte) 0x6f, (byte) 0x67, (byte) 0x6c, (byte) 0x65,
        (byte) 0x31, (byte) 0x19, (byte) 0x30, (byte) 0x17, (byte) 0x06, (byte) 0x03, (byte) 0x55,
        (byte) 0x04, (byte) 0x0b, (byte) 0x0c, (byte) 0x10, (byte) 0x41, (byte) 0x6e, (byte) 0x64,
        (byte) 0x72, (byte) 0x6f, (byte) 0x69, (byte) 0x64, (byte) 0x20, (byte) 0x53, (byte) 0x65,
        (byte) 0x63, (byte) 0x75, (byte) 0x72, (byte) 0x69, (byte) 0x74, (byte) 0x79, (byte) 0x31,
        (byte) 0x1c, (byte) 0x30, (byte) 0x1a, (byte) 0x06, (byte) 0x03, (byte) 0x55, (byte) 0x04,
        (byte) 0x03, (byte) 0x0c, (byte) 0x13, (byte) 0x47, (byte) 0x6f, (byte) 0x6f, (byte) 0x67,
        (byte) 0x6c, (byte) 0x65, (byte) 0x20, (byte) 0x63, (byte) 0x61, (byte) 0x20, (byte) 0x73,
        (byte) 0x74, (byte) 0x72, (byte) 0x6f, (byte) 0x6e, (byte) 0x67, (byte) 0x62, (byte) 0x6f,
        (byte) 0x78, (byte) 0x31, (byte) 0x1f, (byte) 0x30, (byte) 0x1d, (byte) 0x06, (byte) 0x09,
        (byte) 0x2a, (byte) 0x86, (byte) 0x48, (byte) 0x86, (byte) 0xf7, (byte) 0x0d, (byte) 0x01,
        (byte) 0x09, (byte) 0x01, (byte) 0x16, (byte) 0x10, (byte) 0x73, (byte) 0x68, (byte) 0x61,
        (byte) 0x77, (byte) 0x6e, (byte) 0x40, (byte) 0x67, (byte) 0x6f, (byte) 0x6f, (byte) 0x67,
        (byte) 0x6c, (byte) 0x65, (byte) 0x2e, (byte) 0x63, (byte) 0x6f, (byte) 0x6d, (byte) 0x30,
        (byte) 0x1e, (byte) 0x17, (byte) 0x0d, (byte) 0x32, (byte) 0x31, (byte) 0x30, (byte) 0x31,
        (byte) 0x32, (byte) 0x38, (byte) 0x30, (byte) 0x37, (byte) 0x31, (byte) 0x30, (byte) 0x30,
        (byte) 0x39, (byte) 0x5a, (byte) 0x17, (byte) 0x0d, (byte) 0x33, (byte) 0x31, (byte) 0x30,
        (byte) 0x31, (byte) 0x32, (byte) 0x36, (byte) 0x30, (byte) 0x37, (byte) 0x31, (byte) 0x30,
        (byte) 0x30, (byte) 0x39, (byte) 0x5a, (byte) 0x30, (byte) 0x81, (byte) 0x9a, (byte) 0x31,
        (byte) 0x0b, (byte) 0x30, (byte) 0x09, (byte) 0x06, (byte) 0x03, (byte) 0x55, (byte) 0x04,
        (byte) 0x06, (byte) 0x13, (byte) 0x02, (byte) 0x55, (byte) 0x53, (byte) 0x31, (byte) 0x13,
        (byte) 0x30, (byte) 0x11, (byte) 0x06, (byte) 0x03, (byte) 0x55, (byte) 0x04, (byte) 0x08,
        (byte) 0x0c, (byte) 0x0a, (byte) 0x43, (byte) 0x61, (byte) 0x6c, (byte) 0x69, (byte) 0x66,
        (byte) 0x6f, (byte) 0x72, (byte) 0x6e, (byte) 0x69, (byte) 0x61, (byte) 0x31, (byte) 0x0f,
        (byte) 0x30, (byte) 0x0d, (byte) 0x06, (byte) 0x03, (byte) 0x55, (byte) 0x04, (byte) 0x0a,
        (byte) 0x0c, (byte) 0x06, (byte) 0x47, (byte) 0x6f, (byte) 0x6f, (byte) 0x67, (byte) 0x6c,
        (byte) 0x65, (byte) 0x31, (byte) 0x19, (byte) 0x30, (byte) 0x17, (byte) 0x06, (byte) 0x03,
        (byte) 0x55, (byte) 0x04, (byte) 0x0b, (byte) 0x0c, (byte) 0x10, (byte) 0x41, (byte) 0x6e,
        (byte) 0x64, (byte) 0x72, (byte) 0x6f, (byte) 0x69, (byte) 0x64, (byte) 0x20, (byte) 0x53,
        (byte) 0x65, (byte) 0x63, (byte) 0x75, (byte) 0x72, (byte) 0x69, (byte) 0x74, (byte) 0x79,
        (byte) 0x31, (byte) 0x29, (byte) 0x30, (byte) 0x27, (byte) 0x06, (byte) 0x03, (byte) 0x55,
        (byte) 0x04, (byte) 0x03, (byte) 0x0c, (byte) 0x20, (byte) 0x47, (byte) 0x6f, (byte) 0x6f,
        (byte) 0x67, (byte) 0x6c, (byte) 0x65, (byte) 0x20, (byte) 0x49, (byte) 0x6e, (byte) 0x74,
        (byte) 0x65, (byte) 0x72, (byte) 0x6d, (byte) 0x65, (byte) 0x64, (byte) 0x69, (byte) 0x61,
        (byte) 0x74, (byte) 0x65, (byte) 0x20, (byte) 0x43, (byte) 0x41, (byte) 0x20, (byte) 0x73,
        (byte) 0x74, (byte) 0x72, (byte) 0x6f, (byte) 0x6e, (byte) 0x67, (byte) 0x62, (byte) 0x6f,
        (byte) 0x78, (byte) 0x31, (byte) 0x1f, (byte) 0x30, (byte) 0x1d, (byte) 0x06, (byte) 0x09,
        (byte) 0x2a, (byte) 0x86, (byte) 0x48, (byte) 0x86, (byte) 0xf7, (byte) 0x0d, (byte) 0x01,
        (byte) 0x09, (byte) 0x01, (byte) 0x16, (byte) 0x10, (byte) 0x73, (byte) 0x68, (byte) 0x61,
        (byte) 0x77, (byte) 0x6e, (byte) 0x40, (byte) 0x67, (byte) 0x6f, (byte) 0x6f, (byte) 0x67,
        (byte) 0x6c, (byte) 0x65, (byte) 0x2e, (byte) 0x63, (byte) 0x6f, (byte) 0x6d, (byte) 0x30,
        (byte) 0x59, (byte) 0x30, (byte) 0x13, (byte) 0x06, (byte) 0x07, (byte) 0x2a, (byte) 0x86,
        (byte) 0x48, (byte) 0xce, (byte) 0x3d, (byte) 0x02, (byte) 0x01, (byte) 0x06, (byte) 0x08,
        (byte) 0x2a, (byte) 0x86, (byte) 0x48, (byte) 0xce, (byte) 0x3d, (byte) 0x03, (byte) 0x01,
        (byte) 0x07, (byte) 0x03, (byte) 0x42, (byte) 0x00, (byte) 0x04, (byte) 0xfb, (byte) 0xc5,
        (byte) 0x8d, (byte) 0x57, (byte) 0x3f, (byte) 0x53, (byte) 0x3e, (byte) 0x6e, (byte) 0x62,
        (byte) 0x10, (byte) 0xd1, (byte) 0x66, (byte) 0x7a, (byte) 0x00, (byte) 0xf5, (byte) 0x8a,
        (byte) 0xd9, (byte) 0xa8, (byte) 0x61, (byte) 0x8f, (byte) 0x99, (byte) 0xcf, (byte) 0xae,
        (byte) 0x32, (byte) 0xf5, (byte) 0xb9, (byte) 0xab, (byte) 0xa4, (byte) 0x58, (byte) 0x1f,
        (byte) 0xa9, (byte) 0x47, (byte) 0x01, (byte) 0x39, (byte) 0x5d, (byte) 0xf5, (byte) 0x18,
        (byte) 0x82, (byte) 0x4e, (byte) 0x16, (byte) 0x44, (byte) 0x1a, (byte) 0xdf, (byte) 0xfc,
        (byte) 0xf4, (byte) 0xa0, (byte) 0xbd, (byte) 0x93, (byte) 0x42, (byte) 0x4a, (byte) 0x92,
        (byte) 0x41, (byte) 0x3b, (byte) 0x2b, (byte) 0x87, (byte) 0x04, (byte) 0xc0, (byte) 0x88,
        (byte) 0x37, (byte) 0xdb, (byte) 0x4c, (byte) 0x24, (byte) 0xe0, (byte) 0x18, (byte) 0xa3,
        (byte) 0x66, (byte) 0x30, (byte) 0x64, (byte) 0x30, (byte) 0x1d, (byte) 0x06, (byte) 0x03,
        (byte) 0x55, (byte) 0x1d, (byte) 0x0e, (byte) 0x04, (byte) 0x16, (byte) 0x04, (byte) 0x14,
        (byte) 0xf9, (byte) 0xda, (byte) 0x05, (byte) 0x74, (byte) 0xa2, (byte) 0x35, (byte) 0x5b,
        (byte) 0x00, (byte) 0xa2, (byte) 0x92, (byte) 0x08, (byte) 0x7e, (byte) 0x72, (byte) 0x87,
        (byte) 0xb4, (byte) 0x57, (byte) 0xf3, (byte) 0x01, (byte) 0x04, (byte) 0x46, (byte) 0x30,
        (byte) 0x1f, (byte) 0x06, (byte) 0x03, (byte) 0x55, (byte) 0x1d, (byte) 0x23, (byte) 0x04,
        (byte) 0x18, (byte) 0x30, (byte) 0x16, (byte) 0x80, (byte) 0x14, (byte) 0x81, (byte) 0x6c,
        (byte) 0xe6, (byte) 0x5a, (byte) 0x30, (byte) 0xf8, (byte) 0xe2, (byte) 0xaf, (byte) 0x7f,
        (byte) 0xef, (byte) 0x04, (byte) 0x23, (byte) 0x50, (byte) 0xdc, (byte) 0x4e, (byte) 0xa4,
        (byte) 0x48, (byte) 0xe2, (byte) 0x05, (byte) 0x62, (byte) 0x30, (byte) 0x12, (byte) 0x06,
        (byte) 0x03, (byte) 0x55, (byte) 0x1d, (byte) 0x13, (byte) 0x01, (byte) 0x01, (byte) 0xff,
        (byte) 0x04, (byte) 0x08, (byte) 0x30, (byte) 0x06, (byte) 0x01, (byte) 0x01, (byte) 0xff,
        (byte) 0x02, (byte) 0x01, (byte) 0x00, (byte) 0x30, (byte) 0x0e, (byte) 0x06, (byte) 0x03,
        (byte) 0x55, (byte) 0x1d, (byte) 0x0f, (byte) 0x01, (byte) 0x01, (byte) 0xff, (byte) 0x04,
        (byte) 0x04, (byte) 0x03, (byte) 0x02, (byte) 0x01, (byte) 0x86, (byte) 0x30, (byte) 0x0a,
        (byte) 0x06, (byte) 0x08, (byte) 0x2a, (byte) 0x86, (byte) 0x48, (byte) 0xce, (byte) 0x3d,
        (byte) 0x04, (byte) 0x03, (byte) 0x02, (byte) 0x03, (byte) 0x47, (byte) 0x00, (byte) 0x30,
        (byte) 0x44, (byte) 0x02, (byte) 0x20, (byte) 0x2e, (byte) 0xbb, (byte) 0x46, (byte) 0xd4,
        (byte) 0x40, (byte) 0xab, (byte) 0x55, (byte) 0xb3, (byte) 0xb6, (byte) 0xb6, (byte) 0x1b,
        (byte) 0x54, (byte) 0xe6, (byte) 0x3e, (byte) 0xed, (byte) 0x54, (byte) 0x30, (byte) 0xb7,
        (byte) 0xb7, (byte) 0x72, (byte) 0x10, (byte) 0x56, (byte) 0x34, (byte) 0x2d, (byte) 0x0b,
        (byte) 0xdb, (byte) 0x5c, (byte) 0x7f, (byte) 0xee, (byte) 0x51, (byte) 0x9a, (byte) 0x85,
        (byte) 0x02, (byte) 0x20, (byte) 0x17, (byte) 0x24, (byte) 0x2a, (byte) 0xdf, (byte) 0xf5,
        (byte) 0x33, (byte) 0xaf, (byte) 0x40, (byte) 0xa8, (byte) 0x6d, (byte) 0xd0, (byte) 0x58,
        (byte) 0x0c, (byte) 0x78, (byte) 0xfb, (byte) 0x86, (byte) 0xef, (byte) 0x07, (byte) 0xa6,
        (byte) 0x71, (byte) 0xcc, (byte) 0x55, (byte) 0xfc, (byte) 0x6a, (byte) 0x0b, (byte) 0x84,
        (byte) 0x28, (byte) 0x88, (byte) 0xa2, (byte) 0xca, (byte) 0x19, (byte) 0xe0
    };

    // OEM lock for RMA Purposes
    private static final byte[] OEM_LOCK_PROVISION_VERIFICATION_LABEL = { // "OEM Provisioning Lock"
        0x4f, 0x45, 0x4d, 0x20, 0x50, 0x72, 0x6f, 0x76, 0x69, 0x73, 0x69, 0x6f, 0x6e, 0x69, 0x6e,
        0x67, 0x20, 0x4c, 0x6f, 0x63, 0x6b
    };

    // ----------------------------------------------------------------------------------------------
    //  Provision functions
    // ----------------------------------------------------------------------------------------------

    /**
     * This function sends system properties (OSVersion, SystemPatch and VendorPatchLevel) to the
     * Applet.
     */
    public ResponseAPDU setAndroidOSSystemProperties(
            short osVersion, short osPatchLevel, short vendorPatchLevel) {
        short versionPtr = KMInteger.uint_16(osVersion);
        short patchPtr = KMInteger.uint_16(osPatchLevel);
        short vendorPatchPtr = KMInteger.uint_16(vendorPatchLevel);
        //  CBOR Command request for INS_INIT_STRONGBOX_CMD:
        //  Request = [
        //      uint  ; os_version
        //      uint  ; system_patch_level
        //      uint  ; vendor_patch_level
        //  ]
        short arrPtr = KMArray.instance((short) 3);
        KMArray vals = KMArray.cast(arrPtr);
        vals.add((short) 0, versionPtr);
        vals.add((short) 1, patchPtr);
        vals.add((short) 2, vendorPatchPtr);
        // Encode the request into APDU Format
        CommandAPDU apdu = KMTestUtils.encodeApdu(encoder, INS_INIT_STRONGBOX_CMD, p1, arrPtr);
        return simulator.transmitCommand(apdu);
    }

    /** This function provisions the UdsCertChain in the Applet. */
    public ResponseAPDU provisionUdsCertChain() {
        //  CBOR Command request for INS_PROVISION_RKP_UDS_CERT_CHAIN_CMD:
        //  Request = bstr .cbor UdsCerts
        //
        //  UdsCerts = {
        //      * SignerName => UdsCertChain
        //  }
        //
        //  UdsCertChain = [
        //      X509Certificate  ; Root certificate
        //      X509Certificate  ; UDSPublicKey signed by the root certificate
        //  ]
        //
        //  X509Certificate = bstr

        // Prepare the UdsCertChain Cbor array
        short innerArrPtr = KMArray.instance((short) 2);
        short byteBlobPtr1 =
                KMByteBlob.instance(
                        EC_ATTEST_ROOT_CERT, (short) 0, (short) EC_ATTEST_ROOT_CERT.length);
        short byteBlobPtr2 =
                KMByteBlob.instance(EC_ATTEST_CERT, (short) 0, (short) EC_ATTEST_CERT.length);
        KMArray.cast(innerArrPtr).add((short) 0, byteBlobPtr1);
        KMArray.cast(innerArrPtr).add((short) 1, byteBlobPtr2);
        // Prepare the UdsCerts Cbor map
        short map = KMMap.instance((short) 1);
        byte[] signerName = "TestSigner".getBytes();
        KMMap.cast(map)
                .add(
                        (short) 0,
                        KMTextString.instance(signerName, (short) 0, (short) signerName.length),
                        innerArrPtr);
        byte[] output = new byte[2048];
        short encodedLen = encoder.encode(map, output, (short) 0, (short) 2048);
        // Prepare the Request Cbor bytestring
        short encodedData = KMByteBlob.instance(output, (short) 0, encodedLen);
        // Encode the request into APDU Format
        CommandAPDU apdu =
                KMTestUtils.encodeApdu(
                        encoder, INS_PROVISION_RKP_UDS_CERT_CHAIN_CMD, p1, encodedData);
        return simulator.transmitCommand(apdu);
    }

    /** This function provisions the DeviceUnique Keypair. */
    public ResponseAPDU provisionDeviceUniqueKeyPair() {
        //  CBOR Command request for INS_PROVISION_RKP_DEVICE_UNIQUE_KEYPAIR_CMD:
        //  Request = [
        //     CoseKey
        //  ]
        //
        //  CoseKey = {
        //     1  :  2,    ; key type : EC2
        //     3  :  -7    ; AlgorithmES256
        //     -1 :  1     ; Curve: P256
        //     -2 :  bstr  ; X coordinate
        //     -3 :  bstr  ; Y coordinate
        //  }
        final short PRIVATE_KEY_LEN_OFF = 0;
        final short PUBLIC_KEY_LEN_OFF = 1;
        short[] lengths = new short[2];
        byte[] privateKey = new byte[128];
        byte[] pubKey = new byte[128];
        seProvider.createAsymmetricKey(
                KMType.EC,
                privateKey,
                (short) 0,
                (short) 128,
                pubKey,
                (short) 0,
                (short) 128,
                lengths);
        // Prepare CoseKey
        short coseKey =
                KMTestUtils.constructCoseKey(
                        KMInteger.uint_8(KMCose.COSE_KEY_TYPE_EC2),
                        KMType.INVALID_VALUE,
                        KMNInteger.uint_8(KMCose.COSE_ALG_ES256),
                        KMInteger.uint_8(KMCose.COSE_ECCURVE_256),
                        pubKey,
                        (short) 0,
                        lengths[PUBLIC_KEY_LEN_OFF],
                        privateKey,
                        (short) 0,
                        lengths[PRIVATE_KEY_LEN_OFF]);
        assertEquals(65, lengths[PUBLIC_KEY_LEN_OFF]);
        assertTrue("Private key length should not be > 32", (lengths[PRIVATE_KEY_LEN_OFF] <= 32));
        // Prepare the Request Cbor bytestring
        short arr = KMArray.instance((short) 1);
        KMArray.cast(arr).add((short) 0, coseKey);
        // Encode the request into APDU Format
        CommandAPDU apdu =
                KMTestUtils.encodeApdu(
                        encoder, INS_PROVISION_RKP_DEVICE_UNIQUE_KEYPAIR_CMD, p1, arr);
        return simulator.transmitCommand(apdu);
    }

    /**
     * This function provisions the OEM root public key. This key will be used to unlock the OEM
     * provisioning in the RMA facilities.
     */
    public ResponseAPDU provisionOEMRootPublicKey() {
        //  Request = [
        //     KeyParams,
        //     KeyFormat,
        //     PublicKey,
        //  ]
        //
        //  KeyParams = {
        //     268435466 : 1                ; Tag::EC_CURVE  : P_256
        //     536870917 : bstr .cbor [4]   ; Tag::DIGEST    : [SHA_2_256]
        //     268435458 : 3                ; Tag::ALGORITHM : EC
        //     536870913 : bstr .cbor [3]   ; Tag::PURPOSE   : [VERIFY]
        //  }
        //
        //  KeyFormat = uint  ; RAW key format
        //
        //  PublicKey = bstr  ; EC public key

        // Prepare the KeyParams
        short arrPtr = KMArray.instance((short) 4);
        short ecCurve = KMEnumTag.instance(KMType.ECCURVE, KMType.P_256);
        short byteBlob = KMByteBlob.instance((short) 1);
        KMByteBlob.cast(byteBlob).add((short) 0, KMType.SHA2_256);
        short digest = KMEnumArrayTag.instance(KMType.DIGEST, byteBlob);
        short byteBlob2 = KMByteBlob.instance((short) 1);
        KMByteBlob.cast(byteBlob2).add((short) 0, KMType.VERIFY);
        short purpose = KMEnumArrayTag.instance(KMType.PURPOSE, byteBlob2);
        KMArray.cast(arrPtr).add((short) 0, ecCurve);
        KMArray.cast(arrPtr).add((short) 1, digest);
        KMArray.cast(arrPtr).add((short) 2, KMEnumTag.instance(KMType.ALGORITHM, KMType.EC));
        KMArray.cast(arrPtr).add((short) 3, purpose);
        short keyParams = KMKeyParameters.instance(arrPtr);
        // Prepare the KeyFormat
        short keyFormatPtr = KMEnum.instance(KMType.KEY_FORMAT, KMType.RAW);
        // Prepare the EC public key
        short signKeyPtr = KMByteBlob.instance(EC_PUB_KEY, (short) 0, (short) EC_PUB_KEY.length);
        // Prepare the Request in Cbor
        short finalArrayPtr = KMArray.instance((short) 3);
        KMArray.cast(finalArrayPtr).add((short) 0, keyParams);
        KMArray.cast(finalArrayPtr).add((short) 1, keyFormatPtr);
        KMArray.cast(finalArrayPtr).add((short) 2, signKeyPtr);
        // Encode the request into APDU Format
        CommandAPDU apdu =
                KMTestUtils.encodeApdu(
                        encoder, INS_PROVISION_OEM_ROOT_PUBLIC_KEY_CMD, p1, finalArrayPtr);
        return simulator.transmitCommand(apdu);
    }

    /**
     * This function provisions the if secure boot is enforced. This is required for the DeviceInfo
     * structure during the RKP. ("fused" : 1 / 0)
     */
    public ResponseAPDU provisionSecureBootMode() {
        //  Request = [
        //     uint  ; 0 (secure boot not enforced)
        //  ]
        short arrPtr = KMArray.instance((short) 1);
        KMArray.cast(arrPtr).add((short) 0, KMInteger.uint_8((byte) 0));
        // Encode the request into APDU Format
        CommandAPDU apdu =
                KMTestUtils.encodeApdu(encoder, INS_PROVISION_SECURE_BOOT_MODE_CMD, p1, arrPtr);
        return simulator.transmitCommand(apdu);
    }

    /**
     * This function provisions the shared secret; this is required during computing a shared secret
     * between all the KeyMint instances in the device.
     */
    public ResponseAPDU provisionSharedSecret() {
        //  Request = [
        //      bstr  ; shared secret
        //  ]
        byte[] sharedKeySecret = {
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0
        };
        short arrPtr = KMArray.instance((short) 1);
        short byteBlob =
                KMByteBlob.instance(sharedKeySecret, (short) 0, (short) sharedKeySecret.length);
        KMArray.cast(arrPtr).add((short) 0, byteBlob);
        // Encode the request into APDU Format
        CommandAPDU apdu =
                KMTestUtils.encodeApdu(encoder, INS_PROVISION_PRESHARED_SECRET_CMD, p1, arrPtr);
        return simulator.transmitCommand(apdu);
    }

    /** This function provisions the attestation ids. */
    public ResponseAPDU provisionAttestIds() {
        //  Request = [
        //      AttestationIds
        //  ]
        //
        //  // Note: order is not important
        //  AttestationIds = {
        //      2415919814 : bstr  ; Tag::ATTESTATION_ID_BRAND : brand
        //      2415919815 : bstr  ; Tag::ATTESTATION_ID_DEVICE : device
        //      2415919816 : bstr  ; Tag::ATTESTATION_ID_PRODUCT : product
        //      2415919817 : bstr  ; Tag::ATTESTATION_ID_SERIAL : serial
        //      2415919818 : bstr  ; Tag::ATTESTATION_ID_IMEI : imei
        //      2415919819 : bstr  ; Tag::ATTESTATION_ID_MEID : meid
        //      2415919820 : bstr  ; Tag::ATTESTATION_ID_MANUFACTURER : manufacturer
        //      2415919821 : bstr  ; Tag::ATTESTATION_ID_MODEL : model
        //      2415919827 : bstr  ; Tag::ATTESTATION_ID_SECOND_IMEI : second_imei
        //  }
        // Prepare the AttestationIds
        short arrPtr = KMArray.instance((short) 9);
        KMArray.cast(arrPtr)
                .add(
                        (short) 0,
                        KMByteTag.instance(
                                KMType.ATTESTATION_ID_BRAND,
                                KMByteBlob.instance(BRAND, (short) 0, (short) BRAND.length)));
        KMArray.cast(arrPtr)
                .add(
                        (short) 1,
                        KMByteTag.instance(
                                KMType.ATTESTATION_ID_PRODUCT,
                                KMByteBlob.instance(PRODUCT, (short) 0, (short) PRODUCT.length)));
        KMArray.cast(arrPtr)
                .add(
                        (short) 2,
                        KMByteTag.instance(
                                KMType.ATTESTATION_ID_DEVICE,
                                KMByteBlob.instance(DEVICE, (short) 0, (short) DEVICE.length)));
        KMArray.cast(arrPtr)
                .add(
                        (short) 3,
                        KMByteTag.instance(
                                KMType.ATTESTATION_ID_MODEL,
                                KMByteBlob.instance(MODEL, (short) 0, (short) MODEL.length)));
        KMArray.cast(arrPtr)
                .add(
                        (short) 4,
                        KMByteTag.instance(
                                KMType.ATTESTATION_ID_IMEI,
                                KMByteBlob.instance(IMEI, (short) 0, (short) IMEI.length)));
        KMArray.cast(arrPtr)
                .add(
                        (short) 5,
                        KMByteTag.instance(
                                KMType.ATTESTATION_ID_SECOND_IMEI,
                                KMByteBlob.instance(
                                        SECOND_IMEI, (short) 0, (short) SECOND_IMEI.length)));
        KMArray.cast(arrPtr)
                .add(
                        (short) 6,
                        KMByteTag.instance(
                                KMType.ATTESTATION_ID_MEID,
                                KMByteBlob.instance(MEID, (short) 0, (short) MEID.length)));
        KMArray.cast(arrPtr)
                .add(
                        (short) 7,
                        KMByteTag.instance(
                                KMType.ATTESTATION_ID_MANUFACTURER,
                                KMByteBlob.instance(
                                        MANUFACTURER, (short) 0, (short) MANUFACTURER.length)));
        KMArray.cast(arrPtr)
                .add(
                        (short) 8,
                        KMByteTag.instance(
                                KMType.ATTESTATION_ID_SERIAL,
                                KMByteBlob.instance(SERIAL, (short) 0, (short) SERIAL.length)));
        // Prepare the request
        short keyParams = KMKeyParameters.instance(arrPtr);
        short outerArrPtr = KMArray.instance((short) 1);
        KMArray.cast(outerArrPtr).add((short) 0, keyParams);
        // Encode the request into APDU Format
        CommandAPDU apdu =
                KMTestUtils.encodeApdu(encoder, INS_PROVISION_ATTEST_IDS_CMD, p1, outerArrPtr);
        return simulator.transmitCommand(apdu);
    }

    /**
     * This function locks the OEM provisioning. Post this OEM provisioning is locked. To
     * re-provision OEM has to unlock the provisioning.
     */
    public ResponseAPDU provisionLocked() {
        // Sign the Lock message
        byte[] signature = new byte[120];
        ECPrivateKey key =
                (ECPrivateKey)
                        KeyBuilder.buildKey(
                                KeyBuilder.TYPE_EC_FP_PRIVATE, KeyBuilder.LENGTH_EC_FP_256, false);
        key.setS(EC_PRIV_KEY, (short) 0, (short) EC_PRIV_KEY.length);
        Signature ecSigner = Signature.getInstance(Signature.ALG_ECDSA_SHA_256, false);
        ecSigner.init(key, Signature.MODE_SIGN);
        short len =
                ecSigner.sign(
                        OEM_LOCK_PROVISION_VERIFICATION_LABEL,
                        (short) 0,
                        (short) OEM_LOCK_PROVISION_VERIFICATION_LABEL.length,
                        signature,
                        (short) 0);

        //  Request = [
        //      Signature
        //  ]
        //
        //  Signature = bstr ; ECSign(OEM_ROOT_KEY, "OEM Provisioning Lock")

        // Prepare the request
        short arr = KMArray.instance((short) 1);
        KMArray.cast(arr).add((short) 0, KMByteBlob.instance(signature, (short) 0, len));
        // Encode the request into APDU Format
        CommandAPDU apdu = KMTestUtils.encodeApdu(encoder, INS_OEM_LOCK_PROVISIONING_CMD, p1, arr);
        return simulator.transmitCommand(apdu);
    }

    /**
     * This function locks the SE provisioning. Post this command DeviceUniqueKeyPair and
     * UDSCertChain cannot be re-provisioned.
     */
    public ResponseAPDU provisionSeLocked() {
        // Encode the request into APDU Format
        CommandAPDU commandAPDU =
                new CommandAPDU(
                        0x80, INS_SE_FACTORY_PROVISIONING_LOCK_CMD, p1, KMTestUtils.APDU_P2);
        return simulator.transmitCommand(commandAPDU);
    }

    /**
     * This function computes the shared secret. In device the compute shared secret is triggered by
     * the keystore. This is required to make the KeyMint in the ready state.
     */
    public void computeSharedSecret() {
        short ret = getHmacSharingParams();
        assertEquals(KMError.OK, KMInteger.cast(KMArray.cast(ret).get((short) 0)).getShort());
        // KMHmacSharingParameters instance
        short hmacSharingParams = KMArray.cast(ret).get((short) 1);
        //  Request = [
        //      HmacSharingParameters
        //  ]
        //
        //  HmacSharingParameters = [
        //      bstr ; seed
        //      bstr ; nonce
        //  ]

        // Prepare the HmacSharingParameters
        short arr = KMArray.instance((short) 1);
        KMArray.cast(arr).add((short) 0, hmacSharingParams);
        // Prepare the request
        short arrPtr = KMArray.instance((short) 1);
        KMArray.cast(arrPtr).add((short) 0, arr);
        // Encode the request into APDU Format
        CommandAPDU apdu = KMTestUtils.encodeApdu(encoder, INS_COMPUTE_SHARED_HMAC_CMD, p1, arrPtr);
        ResponseAPDU response = simulator.transmitCommand(apdu);
        assertEquals(0x9000, response.getSW());
        // Parse the response
        byte[] resp = response.getBytes();
        arr = KMArray.instance((short) 2);
        KMArray.cast(arr).add((short) 0, KMInteger.exp());
        KMArray.cast(arr).add((short) 1, KMByteBlob.exp());
        short ptr = decoder.decode(arr, resp, (short) 0, (short) resp.length);
        assertEquals(KMError.OK, KMInteger.cast(KMArray.cast(ptr).get((short) 0)).getShort());
    }

    /** This function Provisions the KeyMint applet. */
    public void provisionKeyMintApplet() {
        assertEquals(KMError.OK, KMTestUtils.getErrorCode(decoder, provisionDeviceUniqueKeyPair()));
        assertEquals(KMError.OK, KMTestUtils.getErrorCode(decoder, provisionUdsCertChain()));
        assertEquals(KMError.OK, KMTestUtils.getErrorCode(decoder, provisionSeLocked()));
        assertEquals(KMError.OK, KMTestUtils.getErrorCode(decoder, provisionSharedSecret()));
        assertEquals(KMError.OK, KMTestUtils.getErrorCode(decoder, provisionSecureBootMode()));
        assertEquals(KMError.OK, KMTestUtils.getErrorCode(decoder, provisionAttestIds()));
        assertEquals(KMError.OK, KMTestUtils.getErrorCode(decoder, provisionOEMRootPublicKey()));
        assertEquals(KMError.OK, KMTestUtils.getErrorCode(decoder, provisionLocked()));
    }

    /**
     * Transitions the KeyMint applet to the {@code READY} state, enabling it to accept incoming
     * APDU commands. The applet remains in a restricted state until the following commands are
     * successfully processed:
     *
     * <ul>
     *   <li>{@code INS_SEND_ROT_DATA_CMD}
     *   <li>{@code INS_COMPUTE_SHARED_HMAC_CMD}
     *   <li>{@code INS_INIT_STRONGBOX_CMD} (OS version, system patch level, and vendor patch level)
     * </ul>
     */
    public void transitionKeyMintToReady() {
        assertEquals(
                KMError.OK,
                KMTestUtils.getErrorCode(
                        decoder,
                        setAndroidOSSystemProperties(
                                (short) OS_VERSION,
                                (short) OS_PATCH_LEVEL,
                                (short) VENDOR_PATCH_LEVEL)));
        computeSharedSecret();
        byte[] challenge = getRootOfTrustChallenge();
        sendRootOfTrust(challenge);
        sendEarlyBootEnded();
    }

    /**
     * This function sends INS_GET_HMAC_SHARING_PARAM_CMD command to the Applet to retrieve the hmac
     * sharing parameters. It returns the pointer to the parsed response. The pointer points to the
     * KMArray instance
     */
    public short getHmacSharingParams() {
        CommandAPDU commandAPDU =
                new CommandAPDU(0x80, INS_GET_HMAC_SHARING_PARAM_CMD, p1, KMTestUtils.APDU_P2);
        ResponseAPDU response = simulator.transmitCommand(commandAPDU);
        // parse the response from the applet
        short ret = KMArray.instance((short) 2);
        KMArray.cast(ret).add((short) 0, KMInteger.exp());
        short inst = KMHmacSharingParameters.exp();
        KMArray.cast(ret).add((short) 1, inst);
        byte[] respBuf = response.getBytes();
        short len = (short) respBuf.length;
        ret = decoder.decode(ret, respBuf, (short) 0, len);
        return ret;
    }

    /** This function sends the hard-coded ROT to the Applet. */
    public void sendRootOfTrust(byte[] challenge) {
        //  Request = [
        //      MacedRootOfTrust
        //  ]
        //
        //  MacedRootOfTrust = #6.17 [         ; COSE_Mac0 (tagged)
        //      protected: bstr .cbor {
        //          1 : 5,                     ; Algorithm : HMAC-256
        //      },
        //      unprotected : {},
        //      payload : bstr .cbor RootOfTrust,
        //      tag : bstr HMAC-256(K_mac, MAC_structure)
        //  ]
        //
        //  MAC_structure = [
        //      context : "MAC0",
        //      protected : bstr .cbor {
        //          1 : 5,                     ; Algorithm : HMAC-256
        //      },
        //      external_aad : bstr .size 16   ; Value of challenge argument
        //      payload : bstr .cbor RootOfTrust,
        //  ]
        //
        //  RootOfTrust = #6.40001 [           ; Tag 40001 indicates RoT v1.
        //      verifiedBootKey : bstr .size 32,
        //      deviceLocked : bool,
        //      verifiedBootState : &VerifiedBootState,
        //      verifiedBootHash : bstr .size 32,
        //      bootPatchLevel : int,          ; See Tag::BOOT_PATCHLEVEL
        //  ]
        //
        //  VerifiedBootState = (
        //      Verified : 0,
        //      SelfSigned : 1,
        //      Unverified : 2,
        //      Failed : 3
        //  )
        short[] scratchBuffer = new short[20];
        byte[] scratchPad = new byte[500];
        // Prepare the Payload for Cose_Mac0, which is the RootOfTrust.
        short payload = constructRotPayload();
        // Prepare the Protected Header for Cose_Mac0.
        short headerPtr =
                KMCose.constructHeaders(
                        scratchBuffer,
                        KMInteger.uint_8(KMCose.COSE_ALG_HMAC_256),
                        KMType.INVALID_VALUE,
                        KMType.INVALID_VALUE,
                        KMType.INVALID_VALUE);
        // Encode the protected header as byte blob.
        short len = encoder.encode(headerPtr, scratchPad, (short) 0, (short) 500);
        short protectedHeader = KMByteBlob.instance(scratchPad, (short) 0, len);
        // Unprotected Header
        short unprotectedHeader = KMArray.instance((short) 0);
        unprotectedHeader = KMCoseHeaders.instance(unprotectedHeader);
        // Prepare the Mac_Structure.
        short macStructure =
                KMCose.constructCoseMacStructure(
                        protectedHeader,
                        KMByteBlob.instance(challenge, (short) 0, (short) challenge.length),
                        payload);
        len = encoder.encode(macStructure, scratchPad, (short) 0, (short) 500);
        // Prepare the tag required for Cose_Mac0. HMAC-256(K_mac, MAC_structure)
        short signLen =
                seProvider.hmacSign(
                        KMKeymintDataStore.instance().getComputedHmacKey(),
                        scratchPad,
                        (short) 0,
                        len,
                        scratchPad,
                        len);
        short tag = KMByteBlob.instance(scratchPad, len, signLen);

        // Prepare the Cose_Mac0 structure
        short arr = KMArray.instance((short) 4);
        KMArray.cast(arr).add((short) 0, protectedHeader);
        KMArray.cast(arr).add((short) 1, unprotectedHeader);
        KMArray.cast(arr).add((short) 2, payload);
        KMArray.cast(arr).add((short) 3, tag);

        // Wrap Cose_Mac0 in a semantic tag to form MacedRootOfTrust
        short sTag =
                KMSemanticTag.instance(KMInteger.uint_16(KMSemanticTag.COSE_MAC_SEMANTIC_TAG), arr);

        // Prepare the request
        arr = KMArray.instance((short) 1);
        KMArray.cast(arr).add((short) 0, sTag);
        CommandAPDU apdu = KMTestUtils.encodeApdu(encoder, INS_SEND_ROT_DATA_CMD, p1, arr);
        ResponseAPDU response = simulator.transmitCommand(apdu);
        assertEquals(0x9000, response.getSW());
        byte[] resp = response.getBytes();
        arr = KMArray.instance((short) 1);
        KMArray.cast(arr).add((short) 0, KMInteger.exp());
        short ptr = decoder.decode(arr, resp, (short) 0, (short) resp.length);
        assertEquals(KMError.OK, KMInteger.cast(KMArray.cast(ptr).get((short) 0)).getShort());
    }

    /**
     * This function prepares the RootOfTrust. Converts it into a byte blob instance before
     * returning the instance.
     */
    public short constructRotPayload() {
        // RootOfTrust = #6.40001 [           ; Tag 40001 indicates RoT v1.
        //     verifiedBootKey : bstr .size 32,
        //     deviceLocked : bool,
        //     verifiedBootState : &VerifiedBootState,
        //     verifiedBootHash : bstr .size 32,
        //     bootPatchLevel : int,          ; See Tag::BOOT_PATCHLEVEL
        // ]
        //
        // VerifiedBootState = (
        //     Verified : 0,
        //     SelfSigned : 1,
        //     Unverified : 2,
        //     Failed : 3
        // )
        SecureRandom random = new SecureRandom();
        byte[] randomBytes = new byte[32];
        random.setSeed(0);
        random.nextBytes(randomBytes);
        short bootHashPtr = KMByteBlob.instance(randomBytes, (short) 0, (short) randomBytes.length);
        short bootKeyPtr = KMByteBlob.instance(randomBytes, (short) 0, (short) randomBytes.length);
        short deviceLockedPtr = KMSimpleValue.instance(KMSimpleValue.FALSE);
        short bootStatePtr = KMInteger.uint_8(KMType.VERIFIED_BOOT);
        short bootPatchPtr = KMInteger.uint_16((short) BOOT_PATCH_LEVEL);
        // Prepare the RootOfTrust
        short arr = KMArray.instance((short) 5);
        KMArray.cast(arr).add((short) 0, bootKeyPtr);
        KMArray.cast(arr).add((short) 1, deviceLockedPtr);
        KMArray.cast(arr).add((short) 2, bootStatePtr);
        KMArray.cast(arr).add((short) 3, bootHashPtr);
        KMArray.cast(arr).add((short) 4, bootPatchPtr);
        // Wrap RootOfTrust in semantic tag.
        short sTag = KMSemanticTag.instance(KMInteger.uint_16(KMSemanticTag.ROT_SEMANTIC_TAG), arr);
        byte[] scratchPad = new byte[256];
        // Encode the RootOfTrust
        short len = encoder.encode(sTag, scratchPad, (short) 0, (short) 256);
        return KMByteBlob.instance(scratchPad, (short) 0, len);
    }

    /** This function returns the root of the trust challenge. */
    public byte[] getRootOfTrustChallenge() {
        short arr = KMArray.instance((short) 0);
        CommandAPDU apdu = KMTestUtils.encodeApdu(encoder, INS_GET_ROT_CHALLENGE_CMD, p1, arr);
        ResponseAPDU response = simulator.transmitCommand(apdu);
        assertEquals(0x9000, response.getSW());
        // Parse the response to get the challenge.
        byte[] resp = response.getBytes();
        arr = KMArray.instance((short) 2);
        KMArray.cast(arr).add((short) 0, KMInteger.exp());
        KMArray.cast(arr).add((short) 1, KMByteBlob.exp());
        short ptr = decoder.decode(arr, resp, (short) 0, (short) resp.length);
        assertEquals(KMError.OK, KMInteger.cast(KMArray.cast(ptr).get((short) 0)).getShort());
        byte[] challenge = new byte[16];
        short challengePtr = KMArray.cast(ptr).get((short) 1);
        assertEquals(
                "Length of Challenge should be 16 bytes.",
                16,
                KMByteBlob.cast(challengePtr).length());
        Util.arrayCopyNonAtomic(
                KMByteBlob.cast(challengePtr).getBuffer(),
                KMByteBlob.cast(challengePtr).getStartOff(),
                challenge,
                (short) 0,
                KMByteBlob.cast(challengePtr).length());
        return challenge;
    }

    /** Sends the early boot ended command. */
    public void sendEarlyBootEnded() {
        short arr = KMArray.instance((short) 0);
        CommandAPDU apdu = KMTestUtils.encodeApdu(encoder, INS_EARLY_BOOT_ENDED_CMD, p1, arr);
        ResponseAPDU response = simulator.transmitCommand(apdu);
        assertEquals(0x9000, response.getSW());
        byte[] resp = response.getBytes();
        arr = KMArray.instance((short) 1);
        KMArray.cast(arr).add((short) 0, KMInteger.exp());
        short ptr = decoder.decode(arr, resp, (short) 0, (short) resp.length);
        assertEquals(KMError.OK, KMInteger.cast(KMArray.cast(ptr).get((short) 0)).getShort());
    }
}
