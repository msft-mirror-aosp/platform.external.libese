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
import static org.junit.Assert.assertNotNull;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.Util;

import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

/** Utility class */
public class KMTestUtils {
    public static final byte APDU_P2 = 0x00;
    public static final short ADDITIONAL_MASK = 0x1F;
    private static final short UINT8_LENGTH = 0x18;
    private static final short UINT16_LENGTH = 0x19;
    public static final short MAJOR_TYPE_MASK = 0xE0;
    public static final byte CBOR_ARRAY_MAJOR_TYPE = (byte) 0x80;

    /**
     * Constructs a {@code CommandAPDU} by serializing a {@code KMType} object into CBOR and
     * embedding it as the APDU payload.
     *
     * <p>This method uses the provided encoder to convert the KeyMint internal representation
     * ({@code cmd}) into a CBOR-encoded byte array. This serialized data is then placed in the data
     * field of a new APDU with the specified instruction and P1 parameters.
     *
     * @param encoder The encoder instance used to serialize the {@code KMType} cmd object.
     * @param ins The APDU instruction byte (INS).
     * @param p1 The first parameter byte (P1) of the APDU header.
     * @param cmd A handle to the {@code KMType} instance to be serialized and transmitted.
     * @return A {@code CommandAPDU} instance ready for transmission to the applet.
     */
    public static CommandAPDU encodeApdu(KMEncoder encoder, byte ins, byte p1, short cmd) {
        byte[] buf = new byte[2500];
        buf[0] = (byte) 0x80;
        buf[1] = ins;
        buf[2] = p1;
        buf[3] = APDU_P2;
        buf[4] = 0;
        short len = encoder.encode(cmd, buf, (short) 7, (short) 2500);
        Util.setShort(buf, (short) 5, len);
        byte[] apdu = new byte[7 + len];
        Util.arrayCopyNonAtomic(buf, (short) 0, apdu, (short) 0, (short) (7 + len));
        return new CommandAPDU(apdu);
    }

    /**
     * Constructs a {@code COSE_Key} structure from the provided cryptographic parameters.
     *
     * <p>This method assembles a CBOR map representing a COSE_Key, including the key type,
     * algorithm, curve, and the public/private key components.
     *
     * @param keyType The COSE key type (e.g., {@code KTY_EC2} or {@code KTY_OKP}).
     * @param keyId The key identifier (kid), or {@code KMType.INVALID_VALUE} if not used.
     * @param keyAlg The algorithm identifier (e.g., {@code ALG_ES256} or {@code ALG_EdDSA}).
     * @param curve The cryptographic curve (e.g., {@code P_256} or {@code ED25519}).
     * @param pubKey Buffer containing the public key material.
     * @param pubKeyOff Starting offset of the public key in the buffer.
     * @param pubKeyLen Length of the public key material.
     * @param priv Buffer containing the private key material (optional, may be null).
     * @param privKeyOff Starting offset of the private key in the buffer.
     * @param privKeyLen Length of the private key material.
     * @return A handle to the {@code KMCoseKey}.
     */
    public static short constructCoseKey(
            short keyType,
            short keyId,
            short keyAlg,
            short curve,
            byte[] pubKey,
            short pubKeyOff,
            short pubKeyLen,
            byte[] priv,
            short privKeyOff,
            short privKeyLen) {
        if (pubKey[pubKeyOff] == 0x04) { // uncompressed format
            pubKeyOff += 1;
            pubKeyLen -= 1;
        }
        pubKeyLen = (short) (pubKeyLen / 2);
        short xPtr = KMByteBlob.instance(pubKey, pubKeyOff, pubKeyLen);
        short yPtr = KMByteBlob.instance(pubKey, (short) (pubKeyOff + pubKeyLen), pubKeyLen);
        short privPtr = KMByteBlob.instance(priv, privKeyOff, privKeyLen);
        short[] scratchpad = new short[20];
        short coseKey =
                KMCose.constructCoseKey(
                        scratchpad, keyType, keyId, keyAlg, curve, xPtr, yPtr, privPtr);
        KMCoseKey.cast(coseKey).canonicalize();
        return coseKey;
    }

    /**
     * Decodes the {@code ResponseAPDU} to extract the KeyMint error code.
     *
     * <p>This method assumes the response is a CBOR-encoded array where the first element is an
     * integer representing the status. It utilizes the provided {@code KMDecoder} to parse the
     * response buffer and retrieve the error code.
     *
     * @param decoder The decoder instance used to parse the CBOR response.
     * @param response The {@code ResponseAPDU} received from the applet.
     * @return The error code extracted from the first element of the CBOR array.
     */
    public static short getErrorCode(KMDecoder decoder, ResponseAPDU response) {
        byte[] respBuf = response.getBytes();
        assertNotNull(respBuf);
        assertEquals(0x9000, response.getSW());
        short arr = KMArray.instance((short) 1);
        KMArray.cast(arr).add((short) 0, KMInteger.exp());
        arr = decoder.decode(arr, respBuf, (short) 0, (short) respBuf.length);
        return KMInteger.cast(KMArray.cast(arr).get((short) 0)).getShort();
    }

    /**
     * Validates the CBOR major type of a response and extracts its associated payload length.
     *
     * <p>This method inspects the initial byte(s) of the response to ensure they match the expected
     * {@code majorType}. If the type is correct, it parses and returns the length of the following
     * payload (e.g., the number of bytes in a byte string or the number of elements in an array).
     *
     * @param resp The raw CBOR-encoded byte array to inspect.
     * @param majorType The expected CBOR major type (e.g., {@code MAJOR_TYPE_ARRAY}).
     * @return The decoded payload length associated with the major type.
     */
    public static short readMajorTypeWithPayloadLength(byte[] resp, short majorType) {
        short cur = (short) 0;
        short payloadLength;
        byte val = resp[cur++];
        if ((short) (val & MAJOR_TYPE_MASK) != majorType) {
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }
        short lenType = (short) (val & ADDITIONAL_MASK);
        if (lenType > UINT16_LENGTH) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        if (lenType < UINT8_LENGTH) {
            payloadLength = lenType;
        } else if (lenType == UINT8_LENGTH) {
            payloadLength = (short) (resp[cur] & 0xFF);
        } else {
            payloadLength = Util.getShort(resp, cur);
        }
        return payloadLength;
    }

    /**
     * Asserts that the CBOR response contains an array of the expected length.
     *
     * <p>This method parses the major type and payload length from the start of the response buffer
     * and compares the resulting element count against the expected value.
     *
     * @param req A description of the request for use in failure messages.
     * @param response The raw CBOR-encoded response buffer.
     * @param expectedResponseArrayLen The expected number of elements in the CBOR array.
     */
    public static void assertCborArrayLength(
            String req, byte[] response, int expectedResponseArrayLen) {
        assertNotNull(response);
        // Extracts the count of elements in the CBOR Array (Major Type 4)
        short actualResponseArrayLen =
                KMTestUtils.readMajorTypeWithPayloadLength(
                        response, (short) (KMTestUtils.CBOR_ARRAY_MAJOR_TYPE & 0x00FF));

        assertEquals(
                String.format(
                        "%s: Expected CBOR Array length %d, but found %d.",
                        req, expectedResponseArrayLen, actualResponseArrayLen),
                expectedResponseArrayLen,
                actualResponseArrayLen);
    }

    /**
     * Extracts the raw byte data from a {@code KMByteBlob} into a new Java byte array.
     *
     * <p>This method retrieves the underlying bytes from the provided Keymaster heap handle and
     * copies them into a standard byte array. This is primarily used for exporting key blobs,
     * signatures, or other binary data for verification.
     *
     * @param blob A handle to the {@code KMByteBlob} instance.
     * @return A new byte array containing the contents of the blob.
     */
    public static byte[] getByteBlobBytes(short blob) {
        short length = KMByteBlob.cast(blob).length();
        byte[] blobBytes = new byte[length];
        Util.arrayCopyNonAtomic(
                KMByteBlob.cast(blob).getBuffer(),
                KMByteBlob.cast(blob).getStartOff(),
                blobBytes,
                (short) 0,
                length);
        return blobBytes;
    }
}
