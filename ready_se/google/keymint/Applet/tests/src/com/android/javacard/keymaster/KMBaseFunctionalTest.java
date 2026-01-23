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

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;

import com.android.javacard.seprovider.KMJCardSimulator;

import com.licel.jcardsim.smartcardio.CardSimulator;
import com.licel.jcardsim.utils.AIDUtil;

import javacard.framework.AID;
import javacard.framework.Util;

import org.junit.BeforeClass;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;

import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

/**
 * Base class which handles common functionalities like Key generation and Key operations. This
 * class also helps in initialization of the applet using {@code KMAppletInitializer}.
 */
public class KMBaseFunctionalTest {

    /** Constant field used as P1 parameter in the APDU for KeyMint4.0 */
    private static final byte APDU_KM4_P1 = 0x70;

    private static final String KEYMINT_APPLET_AID = "A00000006203020C010101";
    private static final byte KEYMINT_CMD_APDU_START = 0x20;
    private static final byte INS_GENERATE_KEY_CMD = KEYMINT_CMD_APDU_START + 1; // 0x21
    private static final byte INS_BEGIN_OPERATION_CMD = KEYMINT_CMD_APDU_START + 16; // 0x30
    private static final byte INS_UPDATE_OPERATION_CMD = KEYMINT_CMD_APDU_START + 17; // 0x31
    private static final byte INS_FINISH_OPERATION_CMD = KEYMINT_CMD_APDU_START + 18; // 0x32

    /**
     * The {@code CardSimulator} instance used to manage the applet lifecycle (installation and
     * deletion) and to transmit APDU commands to the applet within the JCardSim environment.
     */
    private static CardSimulator mSimulator;

    /** The {@code KMEncoder} instance used to Encode the data into CBOR format. */
    private static KMEncoder mEncoder;

    /** The {@code KMDecoder} instance used to parse the CBOR data. */
    private static KMDecoder mDecoder;

    /** P1 field in the APDU. */
    private static byte mP1;

    @BeforeClass
    public static void setup() {
        mSimulator = new CardSimulator();
        AID appletAID = AIDUtil.create(KEYMINT_APPLET_AID);
        mSimulator.installApplet(appletAID, KM4Applet.class);
        mSimulator.selectApplet(appletAID);
        mP1 = APDU_KM4_P1;

        mEncoder = new KMEncoder();
        mDecoder = new KMDecoder();
        KMAppletInitializer appletInitializer =
                new KMAppletInitializer(
                        mSimulator, new KMJCardSimulator(), mEncoder, mDecoder, mP1);
        appletInitializer.provisionKeyMintApplet();
        appletInitializer.transitionKeyMintToReady();
    }

    /**
     * Verifies the full incremental encryption and decryption lifecycle for symmetric ciphers.
     *
     * <p>The verification flow includes:
     *
     * <ol>
     *   <li>Generating a symmetric key based on the specified algorithm and size.
     *   <li>Performing incremental encryption via {@code update} calls, with the final data segment
     *       processed through {@code finish}.
     *   <li>Performing incremental decryption of the resulting ciphertext via {@code udpate} calls,
     *       with the final segment processed through {@code finish}.
     * </ol>
     *
     * <p>This function fails if the input message is not equal to the final decrypted output.
     *
     * @param alg The algorithm to use (AES/DES).
     * @param keySize The bit length of the key.
     * @param blockMode The block mode to be used for encrypt/decrypt operation.
     * @param padding The padding scheme to apply.
     * @param finalChunkViaFinish if {@code true}, the final data segment is processed during the
     *     {@code finish} call; otherwise it is processed via {@code update}.
     */
    public void verifyIncrementalSymmetricCipher(
            byte alg, short keySize, byte blockMode, byte padding, boolean finalChunkViaFinish) {
        short response = generateSymCipherKeyNoAttestKeySuccess(alg, keySize, null, null, false);
        // Extract the KeyBlob pointer from the KMArray and copy it to a byte array before executing
        // the begin APDU command. As explained in the {@code KMEncrytionOperationsTest} Javadoc,
        // the response
        // pointer is erased after the begin APDU command executes.
        byte[] keyBlob = KMTestUtils.getByteBlobBytes(KMArray.cast(response).get((short) 1));

        int messageLen = 240;
        byte[] message = "a".repeat(messageLen).getBytes(StandardCharsets.UTF_8);
        // Send the input message to the update operation in multiple parts, with chunk sizes
        // ranging from 1 to the total message length.
        for (short increment = 1; increment <= messageLen; ++increment) {
            short keyBlobPtr = KMByteBlob.instance(keyBlob, (short) 0, (short) keyBlob.length);
            short inParams =
                    buildSymmetricCipherOperationParams(blockMode, padding, null /* nonce */);
            BeginResult result = executeBeginSuccess(KMType.ENCRYPT, keyBlobPtr, inParams);

            ByteBuffer cipherTextBuf = ByteBuffer.allocate(messageLen + 16);
            short remainingBytes = (short) messageLen;
            short finalPos = 0;
            for (short i = 0; i < messageLen; i += increment) {
                if (finalChunkViaFinish && increment >= remainingBytes) {
                    finalPos = i;
                    break;
                } else {
                    OperationResult updateResult =
                            executeUpdateSuccess(
                                    result.operationHandle,
                                    message,
                                    i,
                                    (short) Math.min(increment, remainingBytes));
                    if (updateResult.output != null) {
                        cipherTextBuf.put(updateResult.output);
                    }
                }
                remainingBytes = (short) Math.max(0, (remainingBytes - increment));
            }
            OperationResult finishResult =
                    executeFinishSuccess(result.operationHandle, message, finalPos, remainingBytes);
            if (finishResult.output != null) {
                cipherTextBuf.put(finishResult.output);
            }
            // set the ByteBuffer limit to the current position and then position to 0.
            cipherTextBuf.flip();

            switch (blockMode) {
                case KMType.GCM:
                    assertEquals(messageLen + 16, cipherTextBuf.limit());
                    break;
                case KMType.CTR:
                case KMType.CBC:
                case KMType.ECB:
                    assertEquals(messageLen, cipherTextBuf.limit());
                    break;
            }

            switch (blockMode) {
                case KMType.CBC:
                case KMType.GCM:
                case KMType.CTR:
                    assertNotNull("No IV for block mode: " + blockMode, result.iv);
                    assertEquals(
                            (alg == KMType.AES) ? (blockMode == KMType.GCM ? 12 : 16) : 8,
                            result.iv.length);
                    break;

                case KMType.ECB:
                    assertNull("ECB mode should not generate IV", result.iv);
                    break;
            }

            inParams = buildSymmetricCipherOperationParams(blockMode, padding, result.iv);
            keyBlobPtr = KMByteBlob.instance(keyBlob, (short) 0, (short) keyBlob.length);
            result = executeBeginSuccess(KMType.DECRYPT, keyBlobPtr, inParams);
            assertEquals(KMError.OK, result.errorCode);

            int cipherTextLen = cipherTextBuf.limit();
            byte[] cipherBytes = new byte[cipherTextLen];
            cipherTextBuf.get(cipherBytes);
            ByteBuffer plainText = ByteBuffer.allocate(messageLen);
            remainingBytes = (short) cipherTextLen;
            finalPos = 0;
            for (short i = 0; i < cipherTextLen; i += increment) {
                if (finalChunkViaFinish && increment >= remainingBytes /* isFinalChunk */) {
                    finalPos = i;
                    break;
                } else {
                    OperationResult updateResult =
                            executeUpdateSuccess(
                                    result.operationHandle,
                                    cipherBytes,
                                    i,
                                    (short) Math.min(increment, remainingBytes));
                    if (updateResult.output != null) {
                        plainText.put(updateResult.output);
                    }
                }
                remainingBytes = (short) Math.max(0, (remainingBytes - increment));
            }
            finishResult =
                    executeFinishSuccess(
                            result.operationHandle, cipherBytes, finalPos, remainingBytes);
            if (finishResult.output != null) {
                plainText.put(finishResult.output);
            }
            // set the limit to the current position and set the position to 0
            plainText.flip();
            byte[] plainTextBytes = new byte[plainText.limit()];
            plainText.get(plainTextBytes);

            assertArrayEquals(
                    "Decryption didn't match for block mode: "
                            + blockMode
                            + " and increment: "
                            + increment,
                    message,
                    plainTextBytes);
        }
    }

    /**
     * This function builds the input key parameters required for Symmetric Cipher operations.
     *
     * @param blockMode The block mode to include in the key parameters.
     * @param padding The padding to include in the key parameters.
     * @param nonce The nonce bytes to include in the key parameters.
     * @return The {@code KMKeyParameters} instance.
     */
    public short buildSymmetricCipherOperationParams(byte blockMode, byte padding, byte[] nonce) {
        KMKeyParametersBuilder builder =
                new KMKeyParametersBuilder()
                        .blockMode(new byte[] {blockMode})
                        .padding(new byte[] {padding});
        if (nonce != null) {
            builder.nonce(nonce);
        }
        if (blockMode == KMType.GCM) {
            builder.macLength((short) 128);
        }
        return builder.build();
    }

    /**
     * This function prepares a generate key APDU command, send it to the applet, parses and
     * validates the output response. It creates a key with all possible values for block mode,
     * padding, purpose.
     *
     * @param alg The algorithm for which the key to be generated.
     * @param keySizeBits The key size in bits
     * @param appId The application id to be associated with the generated key.
     * @param appData The application data to be associated with the generated key.
     * @param unlockedDeviceRequired {@code true} if device unlock is required to use the key.
     * @return instance of {@code KMArray}
     */
    public short generateSymCipherKeyNoAttestKeySuccess(
            byte alg,
            short keySizeBits,
            byte[] appId,
            byte[] appData,
            boolean unlockedDeviceRequired) {
        KMKeyParametersBuilder builder =
                new KMKeyParametersBuilder()
                        .blockMode(new byte[] {KMType.ECB, KMType.CBC, KMType.CTR, KMType.GCM})
                        .padding(new byte[] {KMType.PKCS7, KMType.PADDING_NONE})
                        .keySize(keySizeBits)
                        .purpose(new byte[] {KMType.ENCRYPT, KMType.DECRYPT})
                        .noAuthRequired()
                        .callerNonce()
                        .algorithm(alg)
                        .setDefaultValidity();
        if (alg == KMType.AES) {
            builder.minMacLength((short) 128);
        }
        if (appId != null) {
            builder.applicationId(appId);
        }
        if (appData != null) {
            builder.applicationData(appData);
        }
        if (unlockedDeviceRequired) {
            builder.unlockedDeviceRequired();
        }
        short keyParams = builder.build();

        short emptyBlob = KMByteBlob.instance((short) 0);
        short emptyKeyParams = new KMKeyParametersBuilder().build();
        CommandAPDU apdu =
                encodeCommandAPDU(
                        new short[] {keyParams, emptyBlob, emptyKeyParams, emptyBlob},
                        INS_GENERATE_KEY_CMD);
        ResponseAPDU response = mSimulator.transmitCommand(apdu);
        assertEquals(0x9000, response.getSW());
        byte[] respBuf = response.getBytes();
        KMTestUtils.assertCborArrayLength("GenerateKey", respBuf, 4 /* expectedResponseArrayLen */);
        // Response = [
        //     uint,                ; ErrorCode
        //     bstr,                ; KeyBlob
        //     KeyCharacteristics,  ; output key characteristics
        //     Certificate,
        // ]
        //
        // Certificate = [
        //     1* bstr              ; Certificate
        // ]
        short byteBlobExp = KMByteBlob.exp();
        short certExp = KMArray.exp(byteBlobExp);
        short keyCharacteristicsExp = KMKeyCharacteristics.exp();
        short ret =
                decodeResponse(
                        new short[] {KMInteger.exp(), byteBlobExp, keyCharacteristicsExp, certExp},
                        respBuf);
        assertEquals(KMError.OK, KMInteger.cast(KMArray.cast(ret).get((short) 0)).getShort());
        return ret;
    }

    /**
     * Decodes a CBOR-encoded response and validates its structure against a predefined schema.
     *
     * <p>This method initializes a template array based on the expected {@code KMTypes} and
     * utilizes the decoder to populate it from the provided response buffer. The decoding process
     * will fail if the response elements do not match the specified types.
     *
     * @param expectedKMTypesInOrder An array of expected {@code KMTypes} defining the required
     *     sequence for the response.
     * @param response The raw CBOR-encoded response buffer from the applet.
     * @return A handle to a {@code KMArray} instance containing the decoded response data.
     */
    private short decodeResponse(short[] expectedKMTypesInOrder, byte[] response) {
        short inst = createKMArray(expectedKMTypesInOrder);
        return mDecoder.decode(inst, response, (short) 0, (short) response.length);
    }

    /**
     * Constructs a {@code CommandAPDU} by encoding the provided parameters into a CBOR array.
     *
     * <p>This method initializes a {@code KMArray} with the specified request parameters in the
     * given order, encodes the array into CBOR format, and encapsulates the resulting payload into
     * an APDU command using the specified instruction byte.
     *
     * @param requestParameters The ordered sequence of {@code KMType} handles to be included in the
     *     CBOR array.
     * @param cmd The instruction byte (INS) for the resulting APDU command.
     * @return An instance of {@code CommandAPDU} containing the encoded CBOR payload.
     */
    private CommandAPDU encodeCommandAPDU(short[] requestParameters, byte cmd) {
        short inst = createKMArray(requestParameters);
        return KMTestUtils.encodeApdu(mEncoder, cmd, mP1, inst);
    }

    /**
     * Creates a {@code KMArray} instance populated with the specified {@code KMType} handles.
     *
     * <p>This method initializes a new array of the appropriate size and appends the provided
     * values in the order they appear in the input array.
     *
     * @param vals An array containing handles to {@code KMType} instances (e.g., {@code KMInteger},
     *     {@code KMByteBlob}) to be added.
     * @return A handle to the newly created and populated {@code KMArray}.
     */
    private short createKMArray(short[] vals) {
        short inst = KMArray.instance((short) vals.length);
        KMArray arr = KMArray.cast(inst);
        short idx = 0;
        for (short val : vals) {
            arr.add(idx++, val);
        }
        return inst;
    }

    /**
     * Initiates a KeyMint {@code begin} operation and validates that the response is successful.
     *
     * <p>This method transmits the begin command and asserts that the returned error code is {@code
     * KMError.OK}. Upon success, it parses the CBOR response to extract the operation handle,
     * initialization vector (IV), and other relevant metadata.
     *
     * @param keyPurpose The purpose of the operation (e.g., {@code ENCRYPT}, {@code SIGN}).
     * @param keyBlob A handle to the {@code KMByteBlob} containing the wrapped key material.
     * @param keyParams A handle to the {@code KMKeyParameters} containing the operation parameters
     *     (e.g., padding, digest, block mode).
     * @return A {@code BeginResult} object encapsulating the operation handle and output
     *     parameters.
     * @throws AssertionFailedError if the applet returns a non-zero error code.
     */
    public BeginResult executeBeginSuccess(byte keyPurpose, short keyBlob, short keyParams) {
        // Prepare Begin request
        short hwToken = KMHardwareAuthToken.instance();
        short purpose = KMEnum.instance(KMType.PURPOSE, keyPurpose);
        CommandAPDU apdu =
                encodeCommandAPDU(
                        new short[] {purpose, keyBlob, keyParams, hwToken},
                        INS_BEGIN_OPERATION_CMD);
        ResponseAPDU response = mSimulator.transmitCommand(apdu);
        assertEquals(0x9000, response.getSW());
        byte[] respBuf = response.getBytes();
        KMTestUtils.assertCborArrayLength("Begin", respBuf, 5 /* expectedResponseArrayLen */);
        short outParams = KMKeyParameters.expAny();
        short intExp = KMInteger.exp();
        // Response = [
        //     uint,          ; ErrorCode
        //     KeyParameters, ; output key parameters containing nonce
        //     uint,          ; operation handle
        //     uint,          ; Buffering mode
        //     uint           ; MAC length
        // ]
        short ret =
                decodeResponse(new short[] {intExp, outParams, intExp, intExp, intExp}, respBuf);
        assertEquals(KMError.OK, KMInteger.cast(KMArray.cast(ret).get((short) 0)).getShort());
        // Extract the Operation handle pointer from the KMArray and copy it to a byte array before
        // executing the update operation.
        short opHandle = KMArray.cast(ret).get((short) 2);
        short opHandleLen = KMInteger.cast(opHandle).length();
        byte[] operationHandle = new byte[opHandleLen];
        KMInteger.cast(opHandle).getValue(operationHandle, (short) 0, opHandleLen);

        // Extract the nonce from begin response
        short params = KMArray.cast(ret).get((short) 1);
        byte[] iv = null;
        short noncePtr = KMKeyParameters.findTag(KMType.BYTES_TAG, KMType.NONCE, params);
        if (noncePtr != KMType.INVALID_VALUE) {
            noncePtr = KMByteTag.cast(noncePtr).getValue();
            short nonceLen = KMByteBlob.cast(noncePtr).length();
            iv = new byte[nonceLen];
            Util.arrayCopyNonAtomic(
                    KMByteBlob.cast(noncePtr).getBuffer(),
                    KMByteBlob.cast(noncePtr).getStartOff(),
                    iv,
                    (short) 0,
                    nonceLen);
        }
        return new BeginResult(iv, operationHandle, KMError.OK);
    }

    /**
     * Performs a KeyMint {@code update} operation and validates that the response is successful.
     *
     * <p>This method constructs the APDU request for the update operation using the provided handle
     * and message data. It asserts that the applet returns {@code KMError.OK}. The resulting output
     * (ciphertext, plaintext, or signature fragment) and the status code are captured within the
     * returned {@code OperationResult}.
     *
     * @param opHandleBytes The operation handle returned by a previous {@code begin} call.
     * @param message The input buffer containing data to be processed.
     * @param offset The starting position within the {@code message} buffer.
     * @param len The number of bytes from the {@code message} buffer to process.
     * @return An {@code OperationResult} containing the processed data and error code.
     * @throws AssertionFailedError if the applet returns a non-zero error code.
     */
    public OperationResult executeUpdateSuccess(
            byte[] opHandleBytes, byte[] message, short offset, short len) {
        short hwToken = KMHardwareAuthToken.instance();
        short verToken = KMVerificationToken.instance();
        short operationHandle = KMInteger.uint_64(opHandleBytes, (short) 0);
        short data = KMByteBlob.instance(message, offset, len);
        CommandAPDU apdu =
                encodeCommandAPDU(
                        new short[] {operationHandle, data, hwToken, verToken},
                        INS_UPDATE_OPERATION_CMD);

        ResponseAPDU response = mSimulator.transmitCommand(apdu);
        assertEquals(0x9000, response.getSW());
        byte[] respBuf = response.getBytes();
        KMTestUtils.assertCborArrayLength("Update", respBuf, 2 /* expectedResponseArrayLen */);
        // Response = [
        //     uint    ; ErrorCode
        //     bstr    ; processed output
        // ]
        short ret = decodeResponse(new short[] {KMInteger.exp(), KMByteBlob.exp()}, respBuf);
        assertEquals(KMError.OK, KMInteger.cast(KMArray.cast(ret).get((short) 0)).getShort());

        short dataPtr = KMArray.cast(ret).get((short) 1);
        byte[] output = null;
        if (!KMByteBlob.cast(dataPtr).isEmpty()) {
            len = KMByteBlob.cast(dataPtr).length();
            output =
                    ByteBuffer.allocate(len)
                            .put(
                                    KMByteBlob.cast(dataPtr).getBuffer(),
                                    KMByteBlob.cast(dataPtr).getStartOff(),
                                    len)
                            .array();
        }
        return new OperationResult(output, KMError.OK);
    }

    /**
     * Finalizes a KeyMint operation and returns the result.
     *
     * <p>This method constructs the {@code finish} APDU request using the provided operation handle
     * and the final segment of input data. The resulting final output—such as the remaining
     * ciphertext blocks, decrypted plaintext, or the generated signature—is captured within the
     * {@code OperationResult}.
     *
     * @param opHandleBytes The operation handle returned by a previous {@code begin} call.
     * @param message The final buffer of data to be processed.
     * @param offset The starting position within the {@code message} buffer.
     * @param len The number of bytes in the final segment.
     * @return An {@code OperationResult} containing the final processed output and status.
     * @throws AssertionFailedError if the applet returns a non-zero error code.
     */
    public OperationResult finish(byte[] opHandleBytes, byte[] message, short offset, short len) {
        short hwToken = KMHardwareAuthToken.instance();
        short verToken = KMVerificationToken.instance();
        short confToken = KMByteBlob.instance((short) 0);
        short operationHandle = KMInteger.uint_64(opHandleBytes, (short) 0);
        short data = KMByteBlob.instance(message, offset, len);
        short signatureTag = KMByteBlob.instance((short) 0);
        CommandAPDU apdu =
                encodeCommandAPDU(
                        new short[] {
                            operationHandle, data, signatureTag, hwToken, verToken, confToken
                        },
                        INS_FINISH_OPERATION_CMD);
        ResponseAPDU response = mSimulator.transmitCommand(apdu);
        assertEquals(0x9000, response.getSW());
        byte[] respBuf = response.getBytes();
        short respArrLen =
                KMTestUtils.readMajorTypeWithPayloadLength(
                        respBuf, (short) (KMTestUtils.CBOR_ARRAY_MAJOR_TYPE & 0x00FF));
        if (respArrLen == 1) { // Error
            // Response = [
            //     uint     ; ErrorCode
            // ]
            short ret =
                    decodeResponse(
                            new short[] {
                                KMInteger.exp(),
                            },
                            respBuf);
            short err = KMInteger.cast(KMArray.cast(ret).get((short) 0)).getShort();
            return new OperationResult(null, err);
        } else { // Success
            assertEquals(2, respArrLen);
            // Response = [
            //     uint    ; ErrorCode
            //     bstr    ; processed output
            // ]
            short ret = decodeResponse(new short[] {KMInteger.exp(), KMByteBlob.exp()}, respBuf);
            assertEquals(KMError.OK, KMInteger.cast(KMArray.cast(ret).get((short) 0)).getShort());

            short dataPtr = KMArray.cast(ret).get((short) 1);
            byte[] output = null;
            if (!KMByteBlob.cast(dataPtr).isEmpty()) {
                len = KMByteBlob.cast(dataPtr).length();
                output =
                        ByteBuffer.allocate(len)
                                .put(
                                        KMByteBlob.cast(dataPtr).getBuffer(),
                                        KMByteBlob.cast(dataPtr).getStartOff(),
                                        len)
                                .array();
            }
            return new OperationResult(output, KMError.OK);
        }
    }

    /**
     * Finalizes a KeyMint operation and validates that the response is successful.
     *
     * @param opHandleBytes The operation handle returned by a previous {@code begin} call.
     * @param message The final buffer of data to be processed.
     * @param offset The starting position within the {@code message} buffer.
     * @param len The number of bytes in the final segment.
     * @return An {@code OperationResult} containing the final processed output and status.
     * @throws AssertionFailedError if the applet returns a non-zero error code.
     */
    public OperationResult executeFinishSuccess(
            byte[] opHandleBytes, byte[] message, short offset, short len) {
        OperationResult result = finish(opHandleBytes, message, offset, len);
        assertEquals(KMError.OK, result.errorCode);
        return result;
    }

    /**
     * Represents the outcome of a successful KeyMint {@code begin} operation.
     *
     * <p>This container holds the operational metadata required for subsequent {@code update} and
     * {@code finish} calls, including the unique operation handle and any generated initialization
     * vector (IV).
     */
    public static class BeginResult {
        public final byte[] iv;
        public final byte[] operationHandle;
        public final short errorCode;

        public BeginResult(byte[] iv, byte[] operationHandle, short errorCode) {
            this.iv = iv;
            this.operationHandle = operationHandle;
            this.errorCode = errorCode;
        }

        @Override
        public String toString() {
            return "BeginResult{"
                    + "errorCode="
                    + errorCode
                    + ", hasIv="
                    + (iv != null)
                    + ", handleLen="
                    + (operationHandle != null ? operationHandle.length : 0)
                    + '}';
        }
    }

    /**
     * Represents the outcome of a KeyMint {@code update} or {@code finish} operation.
     *
     * <p>This container holds the data produced by the operation (such as ciphertext, plaintext, or
     * a signature) and the status code returned by the applet.
     */
    public static class OperationResult {
        public final byte[] output;
        public final short errorCode;

        public OperationResult(byte[] output, short errorCode) {
            this.output = output;
            this.errorCode = errorCode;
        }

        @Override
        public String toString() {
            int outputLen = (output != null) ? output.length : 0;
            return "OperationResult{"
                    + "errorCode="
                    + errorCode
                    + ", outputLength="
                    + outputLen
                    + '}';
        }
    }
}
