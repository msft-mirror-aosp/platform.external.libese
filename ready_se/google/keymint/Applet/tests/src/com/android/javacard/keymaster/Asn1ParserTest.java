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
package com.android.javacard.keymaster;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import com.android.javacard.seprovider.KMException;

import org.junit.After;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import java.security.SecureRandom;
import java.util.HexFormat;

@RunWith(JUnit4.class)
public final class Asn1ParserTest {
    private static KMRepository sRepository;
    private static KMAsn1Parser sAsn1Parser;
    private static SecureRandom sRandom;
    private static final String ATTESTATION_APPLICATION_ID = Integer.toHexString('a').repeat(1024);

    private final String EC_KEY_ATTRS_AUTH_ANY_ASN1_TPL =
            "30820445" // SEQUENCE length 1093 (KeyDescription) {
                    + "020101" // INTEGER length 1 value 0x01 (KeyFormat = PKCS8)
                    + "3082043E" // SEQUENCE length 1086 (AuthorizationList) {
                    + "A108" // [1] context-specific constructed tag=1 length 0x08 { (purpose)
                    + "3106" // SET length 0x06 {
                    + "020102" // INTEGER length 1 value 0x02 (Sign)
                    + "020103" // INTEGER length 1 value 0x03 (Verify)
                    // } end SET
                    // } end [1]
                    + "A203" // [2] context-specific constructed tag=2 length 0x03 { (algorithm)
                    + "020103" // INTEGER length 1 value 0x03 (EC)
                    // } end [2]
                    + "A505" // [5] context-specific constructed tag=2 length 0x05 { (digest)
                    + "3103" // SET length 3 {
                    + "020100" // INTEGER length 1 value 0x00 (none)
                    // } end SET
                    // } end [5]
                    + "A605" // [6] context-specific constructed tag=6 length 0x05 { (padding)
                    + "3103" // SET length 3 {
                    + "020101" // INTEGER length 1 value 0x01 (none)
                    // } end SET
                    // } end [6]
                    + "AA03" // [10] context-specific constructed tag=10 length 0x03 { (eccurve)
                    + "020101" // INTEGER length 1 value 0x01 (P256)
                    // } end [10]
                    + "BF837603" // [502] context-specific constructed tag=502 length 0x03 {
                    // (userSecureId)
                    + "020101" // INTEGER length 1 value 0x01 (password)
                    // } end [502]
                    + "BF837807" // [504] context-specific constructed tag=504 length 0x07 {
                    // (userAuthType)
                    + "020500FFFFFFFF" // INTEGER length 5 value 0x00FFFFFFFF (ANY)
                    // } end [504]
                    + "BF8545820404" // [709] context-specific constructed tag=709 length 0x0404 {
                    // (AttestationApplicationId)
                    + "04820400" //  OCTET_STRING length 1024
                    + ATTESTATION_APPLICATION_ID;

    // } end [709]
    // } end SEQUENCE (authorizationList)
    // } end SEQUENCE (keyDescription)

    private final String RSA_KEY_ATTRS_AUTH_BIOMETRIC_ASN1_TPL =
            "3039" // SEQUENCE length 57 (KeyDescription) {
                    + "020101" // INTEGER length 1 value 0x01 (KeyFormat = PKCS8)
                    + "3034" // SEQUENCE length 52 (AuthorizationList) {
                    + "A108" // [1] context-specific constructed tag=1 length 0x08 { (purpose)
                    + "3106" // SET length 0x06 {
                    + "020102" // INTEGER length 1 value 0x02 (Sign)
                    + "020103" // INTEGER length 1 value 0x03 (Verify)
                    // } end SET
                    // } end [1]
                    + "A203" // [2] context-specific constructed tag=2 length 3 { (algorithm)
                    + "020101" // INTEGER length 1 value 0x01 (RSA)
                    // } end [2]
                    + "A505" // [5] context-specific constructed tag=2 length 5 { (digest)
                    + "3103" // SET length 3 {
                    + "020100" // INTEGER length 1 value 0x00 (none)
                    // } end SET
                    // } end [5]
                    + "A605" // [6] context-specific constructed tag=6 length 5 { (padding)
                    + "3103" // SET length 3 {
                    + "020101" // INTEGER length 1 value 0x01 (none)
                    // } end SET
                    // } end [6]
                    + "BF814805" // [200] context-specific constructed tag=200 length 5 {
                    // (rsaPublicExponent)
                    + "0203010001" // INTEGER length 3 value 0x010001 (65537)
                    // } end [200]
                    + "BF837603" // [502] context-specific constructed tag=502 length 3 {
                    // (userSecureId)
                    + "020102" // INTEGER length 1 value 2 (fingerprint)
                    // } end [502]
                    + "BF837803" // [504] context-specific constructed tag=504 length 3 {
                    // (userAuthType)
                    + "020102"; // INTEGER length 1 value 0x02 (fingerprint)

    // } end [504]
    // } end SEQUENCE (authorizationList)
    // } end SEQUENCE (keyDescription)

    private final String AES_KEY_ATTRS_AUTH_PASSWORD_ASN1_TPL =
            "3036" // SEQUENCE length 54 (KeyDescription) {
                    + "020101" // INTEGER length 1 value 0x03 (KeyFormat = RAW)
                    + "3031" // SEQUENCE length 49 (AuthorizationList) {
                    + "A108" // [1] context-specific constructed tag=1 length 0x08 { (purpose)
                    + "3106" // SET length 0x06 {
                    + "020100" // INTEGER length 1 value 0x00 (Encrypt)
                    + "020101" // INTEGER length 1 value 0x01 (Decrypt)
                    // } end SET
                    // } end [1]
                    + "A203" // [2] context-specific constructed tag=2 length 3 { (algorithm)
                    + "020120" // INTEGER length 1 value 32 (AES)
                    // } end [2]
                    + "A304" // [3] context-specific constructed tag=3 length 4 { (keySize)
                    + "02020100" // INTEGER length 2 value 256 (AES-256)
                    // } end [3]
                    + "A505" // [5] context-specific constructed tag=2 length 5 { (digest)
                    + "3103" // SET length 3 {
                    + "020100" // INTEGER length 1 value 0x00 (none)
                    // } end SET
                    // } end [5]
                    + "A605" // [6] context-specific constructed tag=6 length 5 { (padding)
                    + "3103" // SET length 3 {
                    + "020101" // INTEGER length 1 value 0x01 (none)
                    // } end SET
                    // } end [6]
                    + "BF837603" // [502] context-specific constructed tag=502 length 3 {
                    // (userSecureId)
                    + "020101" // INTEGER length 1 value 1 (password)
                    // } end [502]
                    + "BF837803" // [504] context-specific constructed tag=504 length 3 {
                    // (userAuthType)
                    + "020101"; // INTEGER length 1 value 0x01 (password)

    // } end [504]
    // } end SEQUENCE (authorizationList)
    // } end SEQUENCE (keyDescription)

    // Tag 1020 is an unknown tag.
    private final String KEY_ATTRS_UNCLASSIFIED_TAGS_ASN1_TPL =
            "3012" // SEQUENCE length 12 (KeyDescription) {
                    + "020103" // INTEGER length 1 value 0x03 (KeyFormat = RAW)
                    + "3007" // SEQUENCE length 7 (AuthorizationList) {
                    + "BF877C03" // [1020] context-specific constructed tag=1020 length 3 { unknown
                    // tag
                    + "020101"; // INTEGER length 1 value 0x01

    // } end [1020]
    // } end SEQUENCE (authorizationList)
    // } end SEQUENCE (keyDescription)

    private final String AES_KEY_ATTRS_UNORDERED_TAGS_ASN1_TPL =
            "3021" // SEQUENCE length 33 (KeyDescription) {
                    + "020101" // INTEGER length 1 value 0x03 (KeyFormat = RAW)
                    + "301C" // SEQUENCE length 28 (AuthorizationList) {
                    + "A203" // [2] context-specific constructed tag=2 length 3 { (algorithm)
                    + "020120" // INTEGER length 1 value 32 (AES)
                    // } end [2]
                    + "A108" // [1] context-specific constructed tag=1 length 0x08 { (purpose)
                    + "3106" // SET length 0x06 {
                    + "020100" // INTEGER length 1 value 0x00 (Encrypt)
                    + "020101" // INTEGER length 1 value 0x01 (Decrypt)
                    // } end SET
                    // } end [1]
                    + "A304" // [3] context-specific constructed tag=3 length 4 { (keySize)
                    + "02020100" // INTEGER length 2 value 256 (AES-256)
                    // } end [3]
                    + "A605" // [6] context-specific constructed tag=6 length 5 { (padding)
                    + "3103" // SET length 3 {
                    + "020101"; // INTEGER length 1 value 0x01 (none)

    // } end [6]
    // } end SEQUENCE (authorizationList)
    // } end SEQUENCE (keyDescription)

    @BeforeClass
    public static void setup() {
        sRepository = new KMRepository(false /* isUpgrading */);
        KMType.initialize();
        sAsn1Parser = KMAsn1Parser.instance();
        sRandom = new SecureRandom();
    }

    @After
    public void reset() {
        // Release and clear the transient buffer memory
        sRepository.clean();
    }

    private short generateRandomSecureId() {
        byte[] randomBytes = new byte[8];
        sRandom.setSeed(0);
        sRandom.nextBytes(randomBytes);
        return KMInteger.instance(randomBytes, (short) 0, (short) randomBytes.length);
    }

    /**
     * This test validates the {@code parseAndUpdateAuthorizationList()} function by providing a
     * KeyDescription ASN.1 structure that includes EC Key attributes, USER_SECURE_ID, and
     * USER_AUTH_TYPE. It then verifies that the response from {@code
     * parseAndUpdateAuthorizationList()} accurately reflects the input parameters, specifically
     * checking for a matching USER_SECURE_ID (corresponding to the password SID) and correct
     * EcCurve and Algorithm values that align with the provided EC Key parameters.
     */
    @Test
    public void testVerifyPasswordSidInEcKeyAttributes() {
        short passwordSidPtr = generateRandomSecureId();
        short biometricSidPtr = KMInteger.uint_8((byte) 0);
        try {
            short keyParameters =
                    parseKeyDescription(
                            EC_KEY_ATTRS_AUTH_ANY_ASN1_TPL, passwordSidPtr, biometricSidPtr);
            // Verify if the parsed result contains proper userSecureId value.
            short tagPtr =
                    KMKeyParameters.findTag(
                            KMType.ULONG_ARRAY_TAG, KMType.USER_SECURE_ID, keyParameters);
            assertNotEquals(KMType.INVALID_VALUE, tagPtr);
            tagPtr = KMIntegerArrayTag.cast(tagPtr).get((short) 0);
            assertEquals(0, KMInteger.compare(tagPtr, passwordSidPtr));
            // Verify if the parsed result contains correct curve
            tagPtr = KMKeyParameters.findTag(KMType.ENUM_TAG, KMType.ECCURVE, keyParameters);
            assertNotEquals(KMType.INVALID_VALUE, tagPtr);
            tagPtr = KMEnumTag.cast(tagPtr).getValue();
            assertEquals(KMType.P_256, tagPtr);
            // Verify if the parsed result contains correct algorithm
            tagPtr = KMKeyParameters.findTag(KMType.ENUM_TAG, KMType.ALGORITHM, keyParameters);
            assertNotEquals(KMType.INVALID_VALUE, tagPtr);
            tagPtr = KMEnumTag.cast(tagPtr).getValue();
            assertEquals(KMType.EC, tagPtr);
        } catch (KMException e) {
            fail("Failed to parse and update authorizationList. Error: " + KMException.reason());
        }
    }

    /**
     * This test validates the {@code parseAndUpdateAuthorizationList()} function by providing a
     * KeyDescription ASN.1 structure that includes RSA Key attributes, USER_SECURE_ID, and
     * USER_AUTH_TYPE. It then verifies that the response from {@code
     * parseAndUpdateAuthorizationList()} accurately reflects the input parameters, specifically
     * checking for a matching USER_SECURE_ID (corresponding to the fingerprint SID) and correct RSA
     * public exponent and Algorithm values that align with the provided RSA Key parameters.
     */
    @Test
    public void testVerifyFingerprintSidInRsaKeyAttributes() {
        short fingerprintSidPtr = generateRandomSecureId();
        short passwordSidPtr = KMInteger.uint_8((byte) 0);
        try {
            short keyParameters =
                    parseKeyDescription(
                            RSA_KEY_ATTRS_AUTH_BIOMETRIC_ASN1_TPL,
                            passwordSidPtr,
                            fingerprintSidPtr);
            // Verify if the parsed result contains proper userSecureId value.
            short tagPtr =
                    KMKeyParameters.findTag(
                            KMType.ULONG_ARRAY_TAG, KMType.USER_SECURE_ID, keyParameters);
            assertNotEquals(KMType.INVALID_VALUE, tagPtr);
            tagPtr = KMIntegerArrayTag.cast(tagPtr).get((short) 0);
            assertEquals(0, KMInteger.compare(tagPtr, fingerprintSidPtr));
            // Verify if the parsed result contains correct rsa public exponent
            tagPtr =
                    KMKeyParameters.findTag(
                            KMType.ULONG_TAG, KMType.RSA_PUBLIC_EXPONENT, keyParameters);
            assertNotEquals(KMType.INVALID_VALUE, tagPtr);
            tagPtr = KMIntegerTag.cast(tagPtr).getValue();
            byte[] rsaPublicExponent = {0x00, 0x01, 0x00, 0x01};
            short rsaPublicExponentPtr =
                    KMInteger.instance(
                            rsaPublicExponent, (short) 0, (short) rsaPublicExponent.length);
            assertEquals(0, KMInteger.compare(tagPtr, rsaPublicExponentPtr));
            // Verify if the parsed result contains correct algorithm
            tagPtr = KMKeyParameters.findTag(KMType.ENUM_TAG, KMType.ALGORITHM, keyParameters);
            assertNotEquals(KMType.INVALID_VALUE, tagPtr);
            tagPtr = KMEnumTag.cast(tagPtr).getValue();
            assertEquals(KMType.RSA, tagPtr);
        } catch (KMException e) {
            fail("Failed to parse and update authorizationList. Error: " + KMException.reason());
        }
    }

    /**
     * Verifies that the applet rejects a {@code KeyDescription} ASN.1 structure containing unknown
     * or unsupported tags.
     *
     * <p>This test injects unexpected tags into the attestation extension data. The implementation
     * is expected to validate the schema strictly and return a {@code KMError.INVALID_ARGUMENT}
     * error.
     */
    @Test
    public void testKeyDescriptionWithUnknownTagFails() {
        short passwordSidPtr = generateRandomSecureId();
        short fingerprintSidPtr = KMInteger.uint_8((byte) 0);
        try {
            parseKeyDescription(
                    KEY_ATTRS_UNCLASSIFIED_TAGS_ASN1_TPL, passwordSidPtr, fingerprintSidPtr);
        } catch (KMException e) {
            // Pass
            assertEquals(KMError.INVALID_ARGUMENT, KMException.reason());
            return;
        }
        fail("This test should fail with INVALID_ARGUMENT error");
    }

    /**
     * Verifies that the applet enforces strict DER ordering for tags within the {@code
     * KeyDescription} ASN.1 structure.
     *
     * <p>Tags must be sorted in ascending order. This test constructs a {@code KeyDescription} with
     * tags out of sequence and asserts that the implementation returns {@code
     * KMError.INVALID_ARGUMENT}.
     */
    @Test
    public void testKeyDescriptionWithUnorderedTagsFails() {
        short passwordSidPtr = generateRandomSecureId();
        short fingerprintSidPtr = KMInteger.uint_8((byte) 0);
        try {
            parseKeyDescription(
                    AES_KEY_ATTRS_UNORDERED_TAGS_ASN1_TPL, passwordSidPtr, fingerprintSidPtr);
        } catch (KMException e) {
            // Pass
            assertEquals(KMError.INVALID_ARGUMENT, KMException.reason());
            return;
        }
        fail("This test should fail with INVALID_ARGUMENT error");
    }

    /**
     * This test validates the {@code parseAndUpdateAuthorizationList()} function by providing a
     * KeyDescription ASN.1 structure that includes AES Key attributes, USER_SECURE_ID, and
     * USER_AUTH_TYPE. It then verifies that the response from {@code
     * parseAndUpdateAuthorizationList()} accurately reflects the input parameters, specifically
     * checking for a matching USER_SECURE_ID (corresponding to the password SID) and correct Key
     * size and Algorithm values that align with the provided AES Key parameters.
     */
    @Test
    public void testVerifyPasswordSidInAesKeyAttributes() {
        short passwordSidPtr = generateRandomSecureId();
        short fingerprintSidPtr = KMInteger.uint_8((byte) 0);
        try {
            short keyParameters =
                    parseKeyDescription(
                            AES_KEY_ATTRS_AUTH_PASSWORD_ASN1_TPL,
                            passwordSidPtr,
                            fingerprintSidPtr);
            // Verify if the parsed result contains proper userSecureId value.
            short tagPtr =
                    KMKeyParameters.findTag(
                            KMType.ULONG_ARRAY_TAG, KMType.USER_SECURE_ID, keyParameters);
            assertNotEquals(KMType.INVALID_VALUE, tagPtr);
            tagPtr = KMIntegerArrayTag.cast(tagPtr).get((short) 0);
            assertEquals(0, KMInteger.compare(tagPtr, passwordSidPtr));
            // Verify if the parsed result contains correct key size.
            tagPtr = KMKeyParameters.findTag(KMType.UINT_TAG, KMType.KEYSIZE, keyParameters);
            assertNotEquals(KMType.INVALID_VALUE, tagPtr);
            tagPtr = KMIntegerTag.cast(tagPtr).getValue();
            short keySize = KMInteger.cast(tagPtr).getShort();
            assertEquals(256, keySize);
            // Verify if the parsed result contains correct algorithm
            tagPtr = KMKeyParameters.findTag(KMType.ENUM_TAG, KMType.ALGORITHM, keyParameters);
            assertNotEquals(KMType.INVALID_VALUE, tagPtr);
            tagPtr = KMEnumTag.cast(tagPtr).getValue();
            assertEquals(KMType.AES, tagPtr);
        } catch (KMException e) {
            fail("Failed to parse and update authorizationList. Error: " + KMException.reason());
        }
    }

    /**
     * This test validates the {@code parseAndUpdateAuthorizationList()} function. It provides an
     * empty KeyDescription ASN.1 structure and verifies that the function fails with an
     * UNKNOWN_ERROR exception.
     */
    @Test
    public void testEmptyKeyDescription() {
        final String emptyKeyDescription = "3000"; // SEQUENCE length 0 { }
        try {
            parseKeyDescription(emptyKeyDescription, (short) 0, (short) 0);
            fail("Parsing should fail with error code.");
        } catch (KMException e) {
            short actualError = KMException.reason();
            assertTrue(
                    "Error code should be either INVALID_DATA or UNKNOWN_ERROR",
                    KMError.INVALID_DATA == actualError || KMError.UNKNOWN_ERROR == actualError);
        }
    }

    /**
     * This test validates the {@code parseAndUpdateAuthorizationList()} function. It provides a
     * KeyDescription ASN.1 structure with invalid KeyFormat value and verifies that the function
     * fails with an INVALID_DATA exception.
     */
    @Test
    public void testInvalidKeyFormat() {
        // SEQUENCE length 6 {
        //   INTEGER length 2 value 65535
        //   SEQUENCE length 0 {
        //   } end SEQUENCE
        // } end SEQUENCE
        byte[] invalidKeyFormat = {0x30, 0x06, 0x02, 0x02, (byte) 0xFF, (byte) 0xFF, 0x30, 0x00};
        short blob =
                KMByteBlob.instance(invalidKeyFormat, (short) 0, (short) invalidKeyFormat.length);
        try {
            sAsn1Parser.keyFormatFromKeyDescription(blob);
            fail("Parsing should fail with error code.");
        } catch (KMException e) {
            assertEquals(KMError.INVALID_DATA, KMException.reason());
        }
    }

    /**
     * Verifies that {@code parseAndUpdateAuthorizationList} correctly parses the key format from a
     * KeyDescription ASN.1 structure that contains a valid KeyFormat value.
     */
    @Test
    public void testParseValidKeyFormat() {
        byte[] keyDescription = HexFormat.of().parseHex(EC_KEY_ATTRS_AUTH_ANY_ASN1_TPL);
        short blob = KMByteBlob.instance(keyDescription, (short) 0, (short) keyDescription.length);
        try {
            short keyFormat = sAsn1Parser.keyFormatFromKeyDescription(blob);
            assertEquals(KMType.PKCS8, keyFormat);
        } catch (KMException e) {
            fail(
                    "Failed to extract the KeyFormat from KeyDescription. Error: "
                            + KMException.reason());
        }
    }

    /**
     * This test validates the {@code parseAndUpdateAuthorizationList()} function. It provides a
     * invalid KeyDescription structure and verifies that the function fails with an INVALID_DATA
     * exception.
     */
    @Test
    public void testParseInvalidKeyDescription() {
        final String invalidKeyDescription = "496e76616c69642d4b65794465736372697074696f6e";
        try {
            parseKeyDescription(invalidKeyDescription, (short) 0, (short) 0);
            fail("Parsing should fail with error code.");
        } catch (KMException e) {
            assertEquals(KMError.INVALID_DATA, KMException.reason());
        }
    }

    private short parseKeyDescription(
            String asn1HexTemplate, short passwordSidPtr, short fingerprintSidPtr) {
        byte[] keyDescription = HexFormat.of().parseHex(asn1HexTemplate);
        short blob = KMByteBlob.instance(keyDescription, (short) 0, (short) keyDescription.length);
        byte[] scratchpad = sRepository.getHeap();
        short offset = sRepository.alloc((short) 1000);
        return sAsn1Parser.parseAndUpdateAuthorizationList(
                blob, scratchpad, offset, passwordSidPtr, fingerprintSidPtr);
    }
}
