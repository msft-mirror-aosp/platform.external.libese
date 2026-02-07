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

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import java.nio.charset.StandardCharsets;

/**
 * Functional test suite for the KeyMint Applet based on the KeyMint Specification.
 *
 * <p>Each test case constructs command APDUs and utilizes the Card Simulator API to transmit them
 * to the KeyMint Applet for execution and verification.
 *
 * <p>The tests uses the encoder and decoder instances, which share the same memory buffer as the
 * applet. Since the applet's transient memory is cleared after each APDU execution, a copy of the
 * decoder output should be taken, if needed, before executing any new APDU command.
 */
@RunWith(JUnit4.class)
public class KMEncryptionOperationsTest extends KMBaseFunctionalTest {

    /** Verifies AES in ECB mode using incremental data updates. */
    @Test
    public void testEncryptionAesEcbIncremental() {
        verifyCipherIncrementalFinality(KMType.AES, (short) 256, KMType.ECB, KMType.PADDING_NONE);
    }

    /** Verifies AES in CBC mode using incremental data updates. */
    @Test
    public void testEncryptionAesCbcIncremental() {
        verifyCipherIncrementalFinality(KMType.AES, (short) 256, KMType.CBC, KMType.PADDING_NONE);
    }

    /** Verifies AES in CTR mode using incremental data updates. */
    @Test
    public void testEncryptionAesCtrIncremental() {
        verifyCipherIncrementalFinality(KMType.AES, (short) 256, KMType.CTR, KMType.PADDING_NONE);
    }

    /** Verifies DES in ECB mode using incremental data updates. */
    @Test
    public void testEncryptionDesEcbIncremental() {
        verifyCipherIncrementalFinality(KMType.DES, (short) 168, KMType.ECB, KMType.PADDING_NONE);
    }

    /** Verifies DES in CBC mode using incremental data updates. */
    @Test
    public void testEncryptionDesCbcIncremental() {
        verifyCipherIncrementalFinality(KMType.DES, (short) 168, KMType.CBC, KMType.PADDING_NONE);
    }

    /**
     * Verifies that AES/DES encryption without padding rejects input data that is not a multiple of
     * the block size.
     *
     * <p>For block ciphers like AES/DES, when padding is disabled ({@code KMType.PADDING_NONE}),
     * the total input length must be a multiple of the block size. This test asserts that the
     * implementation returns {@code KMError.INVALID_INPUT_LENGTH} when provided with non-aligned
     * data.
     */
    @Test
    public void testSymCipherNoPaddingFailsWithNonBlockAlignedInput() {
        for (byte alg : new byte[] {KMType.AES, KMType.DES}) {
            short keySize = (short) (alg == KMType.AES ? 256 : 168);
            short ret = generateSymCipherKeyNoAttestKeySuccess(alg, keySize, null, null, false);
            // Extract the KeyBlob pointer from the KMArray and copy it to a byte array before
            // executing
            // the begin APDU command. As explained in the {@code KMEncrytionOperationsTest}
            // Javadoc, the response
            // pointer is erased after the begin APDU command executes.
            byte[] keyBlob = KMTestUtils.getByteBlobBytes(KMArray.cast(ret).get((short) 1));

            for (byte blockMode : new byte[] {KMType.ECB, KMType.CBC}) {

                byte[] message = "a".repeat(20).getBytes(StandardCharsets.UTF_8);

                short keyBlobPtr = KMByteBlob.instance(keyBlob, (short) 0, (short) keyBlob.length);
                short inParams =
                        buildSymmetricCipherOperationParams(
                                blockMode, KMType.PADDING_NONE, null /* nonce */);
                BeginResult result = executeBeginSuccess(KMType.ENCRYPT, keyBlobPtr, inParams);

                OperationResult finishResult =
                        finish(result.operationHandle, message, (short) 0, (short) message.length);

                assertEquals(KMError.INVALID_INPUT_LENGTH, finishResult.errorCode);
            }
        }
    }

    /**
     * Orchestrates incremental cipher verification by testing both data-carrying and empty {@code
     * finish} operations.
     *
     * <p>This helper executes the round-trip encryption/decryption process twice:
     *
     * <ol>
     *   <li>Providing the final data segment during the {@code finish} call.
     *   <li>Providing all data via {@code update} calls, followed by an empty {@code finish}.
     * </ol>
     *
     * @param alg The algorithm identifier (e.g., AES or DES).
     * @param keySize The bit length of the key.
     * @param blockMode The block cipher mode (e.g., ECB or CBC).
     * @param padding The padding scheme to apply.
     */
    private void verifyCipherIncrementalFinality(
            byte alg, short keySize, byte blockMode, byte padding) {
        for (boolean finalChunkViaFinish : new boolean[] {true, false}) {
            verifyIncrementalSymmetricCipher(alg, keySize, blockMode, padding, finalChunkViaFinish);
        }
    }
}
