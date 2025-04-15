package com.android.javacard.keymaster;

import com.android.javacard.seprovider.KMException;
import javacard.framework.JCSystem;
import javacard.framework.Util;

/**
 * This is a utility class that helps in parsing the PKCS8 encoded RSA and EC keys, certificate
 * subject, subjectPublicKey info and ECDSA signatures.
 */
public class KMAsn1Parser {

  // Below are the ASN.1 tag types
  public static final byte ASN1_OCTET_STRING = 0x04;
  public static final byte ASN1_SEQUENCE = 0x30;
  public static final byte ASN1_SET = 0x31;
  public static final byte ASN1_INTEGER = 0x02;
  public static final byte ASN1_NULL = 0x05;
  public static final byte OBJECT_IDENTIFIER = 0x06;
  public static final byte ASN1_A0_TAG = (byte) 0xA0;
  public static final byte ASN1_A1_TAG = (byte) 0xA1;
  public static final byte ASN1_BIT_STRING = 0x03;

  public static final byte ASN1_UTF8_STRING = 0x0C;
  public static final byte ASN1_TELETEX_STRING = 0x14;
  public static final byte ASN1_PRINTABLE_STRING = 0x13;
  public static final byte ASN1_UNIVERSAL_STRING = 0x1C;
  public static final byte ASN1_BMP_STRING = 0x1E;
  public static final byte IA5_STRING = 0x16;
  // OID of the EC P256 curve 1.2.840.10045.3.1.7
  public static final byte[] EC_CURVE = {
    0x06, 0x08, 0x2a, (byte) 0x86, 0x48, (byte) 0xce, 0x3d, 0x03, 0x01, 0x07
  };
  // Constant for rsaEncryption pkcs#1 (1.2.840.113549.1.1.1) and NULL
  public static final byte[] RSA_ALGORITHM = {
    0x06,
    0x09,
    0x2A,
    (byte) 0x86,
    0x48,
    (byte) 0x86,
    (byte) 0xF7,
    0x0D,
    0x01,
    0x01,
    0x01,
    0x05,
    0x00
  };
  // Constant for ecPublicKey (1.2.840.10045.2.1) and prime256v1 (1.2.840.10045.3.1.7)
  public static final byte[] EC_ALGORITHM = {
    0x06,
    0x07,
    0x2a,
    (byte) 0x86,
    0x48,
    (byte) 0xce,
    0x3d,
    0x02,
    0x01,
    0x06,
    0x08,
    0x2a,
    (byte) 0x86,
    0x48,
    (byte) 0xce,
    0x3d,
    0x03,
    0x01,
    0x07
  };
  // The maximum length of email id attribute.
  public static final short MAX_EMAIL_ADD_LEN = 255;
  // Datatable offsets.
  private static final byte DATA_START_OFFSET = 0;
  private static final byte DATA_LENGTH_OFFSET = 1;
  private static final byte DATA_CURSOR_OFFSET = 2;
  // This array contains the last byte of OID for each oid type.
  // The first 4 bytes are common as shown above in COMMON_OID
  private static final byte[] attributeOIds = {
    0x03, /* commonName COMMON_OID.3 */ 0x04, /* surName COMMON_OID.4*/
    0x05, /* serialNumber COMMON_OID.5 */ 0x06, /* countryName COMMON_OID.6 */
    0x07, /* locality COMMON_OID.7 */ 0x08, /* stateOrProviince COMMON_OID.8 */
    0x0A, /* organizationName COMMON_OID.10 */ 0x0B, /* organizationalUnitName COMMON_OID.11 */
    0x0C, /* title COMMON_OID.10 */ 0x29, /* name COMMON_OID.41 */
    0x2A, /* givenName COMMON_OID.42 */ 0x2B, /* initials COMMON_OID.43 */
    0x2C, /* generationQualifier COMMON_OID.44 */ 0x2E, /* dnQualifer COMMON_OID.46 */
    0x41, /* pseudonym COMMON_OID.65 */
  };
  // https://datatracker.ietf.org/doc/html/rfc5280, RFC 5280, Page 124
  // TODO Specification does not mention about the DN_QUALIFIER_OID max length.
  // So the max limit is set at 64.
  // For name the RFC 5280 supports up to 32768, as Javacard doesn't support
  // that much length, the max limit for name is set to 128.
  private static final byte[] attributeValueMaxLen = {
    0x40, /* 1-64 commonName */
    0x28, /* 1-40 surname */
    0x40, /* 1-64 serial */
    0x02, /* 1-2 country */
    (byte) 0x80, /* 1-128 locality */
    (byte) 0x80, /* 1-128 state */
    0x40, /* 1-64 organization */
    0x40, /* 1-64 organization unit*/
    0x40, /* 1-64 title */
    0x29, /* 1-128 name */
    0x10, /* 1-16 givenName */
    0x05, /* 1-5 initials */
    0x03, /* 1-3 gen qualifier */
    0x40, /* 1-64 dn-qualifier */
    (byte) 0x80 /* 1-128 pseudonym */
  };

  // Below are the allowed softwareEnforced Authorization tags inside the attestation certificate's
  // extension.
  public static final short[] swTagIds = {
    KMType.BYTES_TAG, KMType.MODULE_HASH,
    KMType.BYTES_TAG, KMType.ATTESTATION_APPLICATION_ID,
    KMType.DATE_TAG, KMType.CREATION_DATETIME,
    KMType.BOOL_TAG, KMType.ALLOW_WHILE_ON_BODY,
    KMType.UINT_TAG, KMType.USAGE_COUNT_LIMIT,
    KMType.DATE_TAG, KMType.USAGE_EXPIRE_DATETIME,
    KMType.DATE_TAG, KMType.ORIGINATION_EXPIRE_DATETIME,
    KMType.DATE_TAG, KMType.ACTIVE_DATETIME,
  };

  // Below are the valid Authorization tags but not supported in Strongbox.
  private static final short[] validAuthListTags = {
    KMType.BOOL_TAG, KMType.DEVICE_UNIQUE_ATTESTATION,
    KMType.BOOL_TAG, KMType.TRUSTED_USER_PRESENCE_REQUIRED,
  };

  // Below are the allowed hardwareEnforced Authorization tags inside the attestation certificate's
  // extension.
  public static final short[] hwTagIds = {
    KMType.BYTES_TAG, KMType.ATTESTATION_ID_SECOND_IMEI,
    KMType.UINT_TAG, KMType.BOOT_PATCH_LEVEL,
    KMType.UINT_TAG, KMType.VENDOR_PATCH_LEVEL,
    KMType.BYTES_TAG, KMType.ATTESTATION_ID_MODEL,
    KMType.BYTES_TAG, KMType.ATTESTATION_ID_MANUFACTURER,
    KMType.BYTES_TAG, KMType.ATTESTATION_ID_MEID,
    KMType.BYTES_TAG, KMType.ATTESTATION_ID_IMEI,
    KMType.BYTES_TAG, KMType.ATTESTATION_ID_SERIAL,
    KMType.BYTES_TAG, KMType.ATTESTATION_ID_PRODUCT,
    KMType.BYTES_TAG, KMType.ATTESTATION_ID_DEVICE,
    KMType.BYTES_TAG, KMType.ATTESTATION_ID_BRAND,
    KMType.UINT_TAG, KMType.OS_PATCH_LEVEL,
    KMType.UINT_TAG, KMType.OS_VERSION,
    KMType.BYTES_TAG, KMType.ROOT_OF_TRUST,
    KMType.ENUM_TAG, KMType.ORIGIN,
    KMType.BOOL_TAG, KMType.UNLOCKED_DEVICE_REQUIRED,
    KMType.BOOL_TAG, KMType.TRUSTED_CONFIRMATION_REQUIRED,
    KMType.UINT_TAG, KMType.AUTH_TIMEOUT,
    KMType.ENUM_TAG, KMType.USER_AUTH_TYPE,
    KMType.BOOL_TAG, KMType.NO_AUTH_REQUIRED,
    KMType.BOOL_TAG, KMType.EARLY_BOOT_ONLY,
    KMType.BOOL_TAG, KMType.ROLLBACK_RESISTANCE,
    KMType.ENUM_ARRAY_TAG, KMType.RSA_OAEP_MGF_DIGEST,
    KMType.ULONG_TAG, KMType.RSA_PUBLIC_EXPONENT,
    KMType.ENUM_TAG, KMType.ECCURVE,
    KMType.UINT_TAG, KMType.MIN_MAC_LENGTH,
    KMType.BOOL_TAG, KMType.CALLER_NONCE,
    KMType.ENUM_ARRAY_TAG, KMType.PADDING,
    KMType.ENUM_ARRAY_TAG, KMType.DIGEST,
    KMType.ENUM_ARRAY_TAG, KMType.BLOCK_MODE,
    KMType.UINT_TAG, KMType.KEYSIZE,
    KMType.ENUM_TAG, KMType.ALGORITHM,
    KMType.ENUM_ARRAY_TAG, KMType.PURPOSE
  };

  private static KMAsn1Parser inst;
  // https://datatracker.ietf.org/doc/html/rfc5280, RFC 5280, Page 21
  // 2.5.4
  public byte[] COMMON_OID = new byte[] {0x06, 0x03, 0x55, 0x04};
  public byte[] EMAIL_ADDRESS_OID =
      new byte[] {
        0x06, 0x09, 0x2A, (byte) 0x86, 0x48, (byte) 0x86, (byte) 0xF7, 0x0D, 0x01, 0x09, 0x01
      };
  // The maximum possible SET length for all combinations of ENUM_REPs is 21 bytes.
  // This is derived as follows:
  // Each entry in the SET is an ASN1_INTEGER.
  // An ASN1_INTEGER with a single-byte value requires 3 bytes:
  //   - 1 byte for the tag (e.g., UNIVERSAL 2 for INTEGER)
  //   - 1 byte for the length (indicating a 1-byte value)
  //   - 1 byte for the integer value itself (Digest/Purpose/Padding/BlockMode)
  // The maximum repetition count of 7 is possible for both Digest and Purpose ENUM_REPs.
  // With a maximum of 7 repetitions, the total maximum length is 7 entries * 3 bytes/entry = 21
  // bytes.
  private static final short MAX_ENUM_REP_SET_LENGTH = 21;
  private byte[] data;
  private short[] dataInfo;

  private KMAsn1Parser() {
    dataInfo = JCSystem.makeTransientShortArray((short) 3, JCSystem.CLEAR_ON_RESET);
    dataInfo[DATA_START_OFFSET] = 0;
    dataInfo[DATA_LENGTH_OFFSET] = 0;
    dataInfo[DATA_CURSOR_OFFSET] = 0;
  }

  public static KMAsn1Parser instance() {
    if (inst == null) {
      inst = new KMAsn1Parser();
    }
    return inst;
  }

  public short decodeRsa(short blob) {
    init(blob);
    decodeCommon((short) 0, RSA_ALGORITHM);
    return decodeRsaPrivateKey((short) 0);
  }

  public short decodeEc(short blob) {
    init(blob);
    decodeCommon((short) 0, EC_ALGORITHM);
    return decodeEcPrivateKey((short) 1);
  }

  /**
   * Parses and validates an ASN.1 unsigned integer, adjusting its length and copying it to an
   * output buffer.
   *
   * <p>This function reads an integer from the internal data buffer, skipping any leading zero
   * bytes. It then adjusts the integer's effective length to a standard size (1, 2, 4, or 8 bytes),
   * and pads it with leading zeros to fit the final length. The result is right-justified within
   * the output buffer.
   *
   * @param integerSizeInBytes The total number of bytes representing the integer, as specified by
   *     its ASN.1 length field. Must be between 1 and 9 bytes.
   * @param expectedSizeInBytes The expected length of the integer in bytes (e.g., 4 for an integer,
   *     8 for a long). This is used to validate the {@code integerSizeInBytes}.
   * @param scratchPad A byte array serving as the output buffer where the processed integer will be
   *     copied.
   * @param offset The starting offset in the {@code scratchPad} buffer where the integer bytes
   *     should be copied.
   * @return The adjusted length of the copied integer in bytes (1, 2, 4, or 8).
   * @throws KMException.throwIt(KMError.INVALID_DATA) if the input integer is signed or its length
   *     is out of the supported range.
   * @throws KMException.throwIt(KMError.ILLEGAL_USE) if a buffer access or copying operation fails.
   */
  private short asn1Integer(
      short integerSizeInBytes, short expectedSizeInBytes, byte[] scratchPad, short offset) {
    // Validate the integer length.
    if (integerSizeInBytes <= 0 || integerSizeInBytes > (short) (expectedSizeInBytes + 1)) {
      KMException.throwIt(KMError.INVALID_DATA);
    }
    short dataOffset = dataInfo[DATA_CURSOR_OFFSET];
    // Check for the signed bit (most significant bit).
    // An unsigned integer in ASN.1 should have the MSB of its first byte as 0.
    if ((data[dataOffset] & 0x80) != 0) {
      KMException.throwIt(KMError.INVALID_DATA);
    }

    // Find the first non-zero byte to handle leading zeros.
    short firstNonZeroByte = 0;
    while (firstNonZeroByte < integerSizeInBytes
        && data[(short) (dataOffset + firstNonZeroByte)] == 0) {
      firstNonZeroByte++;
    }

    // Calculate the actual length of the non-zero integer.
    short actualIntLen = (short) (integerSizeInBytes - firstNonZeroByte);

    // Handle the special case where the integer's value is 0.
    // If the entire buffer is zeros, the actual length is 1 byte.
    if (actualIntLen == 0) {
      actualIntLen = 1;
      firstNonZeroByte = (short) (integerSizeInBytes - 1);
    }

    // Adjust the length to 1, 2, 4, or 8 bytes.
    short adjustedLen = actualIntLen;
    if (actualIntLen > 4) {
      adjustedLen = 8;
    } else if (actualIntLen > 2) {
      adjustedLen = 4;
    }

    if (adjustedLen > expectedSizeInBytes) {
      KMException.throwIt(KMError.INVALID_DATA);
    }

    // Copy the integer bytes to the output buffer, right-justified with padding.
    // First, fill the entire destination with zeros for padding.
    Util.arrayFillNonAtomic(scratchPad, offset, adjustedLen, (byte) 0);

    // Then, copy the actual data starting from the first non-zero byte.
    // The destination offset is calculated to align the data to the right.
    Util.arrayCopyNonAtomic(
        data,
        (short) (dataOffset + firstNonZeroByte),
        scratchPad,
        (short) (offset + adjustedLen - actualIntLen),
        actualIntLen);

    // Increment the data cursor by the original integer length.
    incrementCursor(integerSizeInBytes);

    return adjustedLen;
  }

  /**
   * Constructs a tag instance based on its type and updates `USER_SECURE_ID`.
   *
   * <p>This helper function, used by {@code parseAndUpdateAuthorizationList()}, creates an instance
   * of a specific tag type, such as {@link KMIntegerTag}, {@link KMIntegerArrayTag}, {@link
   * KMEnumTag}, {@link KMEnumArrayTag}, or {@link KMByteTag}.
   *
   * <p>During construction, if the tag is `USER_SECURE_ID`, its value is updated. This modification
   * logic is fully described in the documentation for `parseAndUpdateAuthorizationList()`.
   * Specifically, the value is replaced with `passwordSid` or `biometricSid` depending on the tag's
   * original value.
   *
   * @param tagType The type of the tag being constructed.
   * @param tag The tag being processed.
   * @param scratchpad A temporary buffer for internal data processing.
   * @param offset The starting offset within the `scratchpad` to use.
   * @param passwordSid The SID used to replace `USER_SECURE_ID` for password authenticators.
   * @param biometricSid The SID used to replace `USER_SECURE_ID` for biometric authenticators.
   * @return The extracted parameter value as appropriate {@link KMTag} instance.
   */
  public short extractParameterValue(
      short tagType,
      short tag,
      byte[] scratchpad,
      short offset,
      short passwordSid,
      short biometricSid) {
    short length;
    short tagPtr = KMType.INVALID_VALUE;
    switch (tagType) {
      case KMType.BOOL_TAG:
        if (0x00 != header(ASN1_NULL)) {
          KMException.throwIt(KMError.INVALID_DATA);
        }
        tagPtr = KMBoolTag.instance(tag);
        break;
      case KMType.ENUM_ARRAY_TAG:
        {
          length = header(ASN1_SET);
          if (length > MAX_ENUM_REP_SET_LENGTH) {
            KMException.throwIt(KMError.INVALID_DATA);
          }
          short curOffset = dataInfo[DATA_CURSOR_OFFSET];
          short scratchpadPos = offset;
          // Parses the ASN.1 SET OF type.
          //
          // This DER parser currently does not strictly enforce the full ASN.1 DER rules
          // for SET OF structures, specifically:
          // 1. It does not verify that elements are encoded in strictly ascending order based
          // on their DER encoding.
          // 2. It does not prohibit duplicate values within the set.
          //
          // The C++ default implementation which uses boringssl for parsing the ASN.1 DER encoded
          // KeyDescription structures relaxes these constraints for SET OF ASN.1 types.
          // Furthermore, a maximum length check is in place, which prevents buffer overflows even
          // if duplicate entries are present. The DER parsed output is used internally by
          // KeyMint itself, and it won't cause a problem upon consuming.
          while (dataInfo[DATA_CURSOR_OFFSET] < ((short) (curOffset + length))) {
            short intLen = header(ASN1_INTEGER);
            asn1Integer(intLen, (short) 1 /* expectedSizeInBytes */, scratchpad, scratchpadPos);
            scratchpadPos++;
          }
          short blob = KMByteBlob.instance(scratchpad, offset, (short) (scratchpadPos - offset));
          tagPtr = KMEnumArrayTag.instance(tag, blob);
        }
        break;
      case KMType.ENUM_TAG:
        {
          length = header(ASN1_INTEGER);
          short len = asn1Integer(length, KMInteger.UINT_32, scratchpad, offset);
          tagPtr = KMEnumTag.instance(tag, scratchpad, offset, len);
        }
        break;
      case KMType.UINT_TAG:
      // Fall through
      case KMType.DATE_TAG:
      // Fall through
      case KMType.ULONG_TAG:
        {
          length = header(ASN1_INTEGER);
          short expectedSize = (tagType == KMType.UINT_TAG) ? KMInteger.UINT_32 : KMInteger.UINT_64;
          short len = asn1Integer(length, expectedSize, scratchpad, offset);
          short ptr = 0;
          // Handles USER_SECURE_ID as a special case. Typically, USER_SECURE_ID is a repetitive tag
          // containing an 8-byte random value generated by Gatekeeper or Biometric services on the
          // Android side. However, during the importWrappedKey process, USER_SECURE_ID in the
          // authorization list functions as an ASN.1 integer. Its value corresponds to one of the
          // three user authentication types: USER_AUTH_TYPE (PASSWORD, BIOMETRIC, or ANY). If
          // USER_SECURE_ID contains any other value, an exception is thrown.

          // How to process USER_SECURE_ID:
          // 1. If USER_SECURE_ID is PASSWORD, use the password SID.
          // 2. If USER_SECURE_ID is BIOMETRIC, use the biometric SID.
          // 3. If USER_SECURE_ID is ANY, use the password SID. This is because biometric
          // authentication tokens contain both password and fingerprint SIDs, but password
          // authentication tokens only contain the password SID.
          if (tag == KMType.USER_SECURE_ID) {
            if (len == 4) {
              short highShort = Util.getShort(scratchpad, offset);
              short lowShort = Util.getShort(scratchpad, (short) (offset + 2));
              if (highShort == (short) 0xFFFF && lowShort == (short) 0xFFFF) {
                ptr = passwordSid;
              } else {
                KMException.throwIt(KMError.INVALID_DATA);
              }
            } else if (len == 1) {
              byte userAuthType = scratchpad[offset];
              if (userAuthType == KMType.PASSWORD) {
                ptr = passwordSid;
              } else if (userAuthType == KMType.FINGERPRINT) {
                ptr = biometricSid;
              } else {
                KMException.throwIt(KMError.INVALID_DATA);
              }
            } else {
              KMException.throwIt(KMError.INVALID_DATA);
            }
            short arrPtr = KMArray.instance((short) 1);
            KMArray.cast(arrPtr).add((short) 0, ptr);
            tagPtr = KMIntegerArrayTag.instance(KMType.ULONG_ARRAY_TAG, tag, arrPtr);
          } else {
            ptr = KMInteger.instance(scratchpad, offset, len);
            tagPtr = KMIntegerTag.instance(tagType, tag, ptr);
          }
        }
        break;
      case KMType.BYTES_TAG:
        {
          length = header(ASN1_OCTET_STRING);
          // Maximum size of Attestation application id is 1024
          if (length > 1024) {
            KMException.throwIt(KMError.INVALID_DATA);
          }
          short ptr = KMByteBlob.instance(data, dataInfo[DATA_CURSOR_OFFSET], length);
          incrementCursor(length);
          tagPtr = KMByteTag.instance(tag, ptr);
        }
        break;
      default:
        // Adhere to KeyMint specification:  Any Tag type other than mentioned in the
        // KeyCreationResult#AuthorizationList would result in error.
        // TagTypes: BIGNUM, UINT_REP and ULONG_REP are not available in AuthorizationList
        KMException.throwIt(KMError.INVALID_DATA);
    }
    return tagPtr;
  }

  /**
   * Parses a DER-encoded **KeyDescription** to extract the **KeyFormat** value.
   *
   * <p>This function reads the provided ASN.1-encoded `KeyDescription` blob and returns the
   * associated `KeyFormat` value. This value indicates the encoding format of the secret key to be
   * imported.
   *
   * @param blob A `ByteBlob` containing the DER-encoded `KeyDescription` structure.
   * @return The `KeyFormat` value, which can be `KeyFormat::PKCS8`, `KeyFormat::X509`, or
   *     `KeyFormat::RAW`.
   */
  public short keyFormatFromKeyDescription(short blob) {
    init(blob);
    short len = header(ASN1_SEQUENCE);
    if (len < 0) {
      KMException.throwIt(KMError.INVALID_DATA);
    }
    len = header(ASN1_INTEGER);
    if (len != 1) {
      KMException.throwIt(KMError.INVALID_DATA);
    }
    short keyFormat = getByte();
    if (keyFormat != KMType.RAW && keyFormat != KMType.X509 && keyFormat != KMType.PKCS8) {
      KMException.throwIt(KMError.INVALID_DATA);
    }
    return keyFormat;
  }

  /**
   * Parses a DER-encoded **KeyDescription** to extract and process the **AuthorizationList**.
   *
   * <p>This function first parses the ASN.1-encoded {@code blob} to convert the contained {@code
   * AuthorizationList} into a {@link KMKeyParameters} object. It then modifies the {@code
   * AuthorizationList} based on the value of its {@code USER_SECURE_ID} tag.
   *
   * <p>Specifically, if the {@code USER_SECURE_ID} tag's value is {@code
   * HardwareAuthenticatorType::PASSWORD} or {@code HardwareAuthenticatorType::ANY}, the tag is
   * replaced with {@code passwordSid}. If the tag's value is {@code
   * HardwareAuthenticatorType::FINGERPRINT}, it's replaced with {@code biometricSid}.
   *
   * <pre>
   * KeyDescription ::= SEQUENCE(
   *     keyFormat INTEGER,         # Values from KeyFormat enum.
   *     keyParams AuthorizationList,
   * )
   * </pre>
   *
   * {@code AuthorizationList} is an ASN.1 SEQUENCE. It contains the explicit context tags as
   * defined in the {@code KeyCreationResult#Authorization} in the KeyMint specification.
   *
   * @param blob A {@code ByteBlob} containing the DER-encoded {@code KeyDescription}.
   * @param scratchpad A buffer for internal data processing.
   * @param scratchOff The offset within the {@code scratchpad} to begin processing.
   * @param passwordSid The {@code KMInteger} representing the password SID.
   * @param biometricSid The {@code KMInteger} representing the biometric SID.
   * @return A {@code KeyParameter} instance populated from the AuthorizationList.
   */
  public short parseAndUpdateAuthorizationList(
      short blob, byte[] scratchpad, short scratchOff, short passwordSid, short biometricSid) {
    short tag;
    short len;
    short arrLen = 0;
    short ptr;
    short prevTag = KMType.INVALID_TAG;
    short baseOff = scratchOff;
    // skip key format
    keyFormatFromKeyDescription(blob);
    // parse authorization list
    short encodedAuthListLen = header(ASN1_SEQUENCE);
    encodedAuthListLen += dataInfo[DATA_CURSOR_OFFSET];
    // Loop through all elements in the AuthorizationList sequence.
    // The sequence contains multiple elements identified by context-specific tags. Each
    // context-specific tag is in the Tag-Length-Value format, as per ASN.1 standards. We process
    // all the tags until we reach the end of the sequence.
    while (dataInfo[DATA_CURSOR_OFFSET] < encodedAuthListLen) {
      // Read the TLV (Tag-Length-Value) structure in each iteration.
      tag = getExplicitContextTag();
      if (prevTag != KMType.INVALID_TAG && tag <= prevTag) {
        // Tags should be in the ascending order.
        KMException.throwIt(KMError.INVALID_ARGUMENT);
      }
      prevTag = tag;
      len = getLength();
      if (len < 0) {
        // Length greater than short cannot be supported.
        KMException.throwIt(KMError.UNKNOWN_ERROR);
      }
      // In accordance with the default Rust/C++ implementation, an INVALID_ARGUMENT error is
      // returned
      // when a tag is read that is not present in the AuthorizationList.
      short tagType = getTagTypeFromTag(tag);
      if (tagType == KMType.INVALID_VALUE) {
        KMException.throwIt(KMError.INVALID_ARGUMENT);
      }
      ptr = extractParameterValue(tagType, tag, scratchpad, scratchOff, passwordSid, biometricSid);
      if (ptr == KMType.INVALID_VALUE) {
        KMException.throwIt(KMError.UNKNOWN_ERROR);
      }
      scratchOff = Util.setShort(scratchpad, scratchOff, ptr);
      arrLen++;
    }
    short arrPtr = KMArray.instance(arrLen);
    for (short i = 0; i < arrLen; ++i) {
      KMArray.cast(arrPtr).add(i, Util.getShort(scratchpad, baseOff));
      baseOff += 2;
    }
    return KMKeyParameters.instance(arrPtr);
  }

  /*
     Name ::= CHOICE { -- only one possibility for now --
         rdnSequence  RDNSequence }
     RDNSequence ::= SEQUENCE OF RelativeDistinguishedName
     RelativeDistinguishedName ::=
         SET SIZE (1..MAX) OF AttributeTypeAndValue
     AttributeTypeAndValue ::= SEQUENCE {
       type     AttributeType,
       value    AttributeValue }
     AttributeType ::= OBJECT IDENTIFIER
     AttributeValue ::= ANY -- DEFINED BY AttributeType
  */
  public void validateDerSubject(short blob) {
    init(blob);
    header(ASN1_SEQUENCE);
    while (dataInfo[DATA_CURSOR_OFFSET]
        < ((short) (dataInfo[DATA_START_OFFSET] + dataInfo[DATA_LENGTH_OFFSET]))) {
      header(ASN1_SET);
      header(ASN1_SEQUENCE);
      // Parse and validate OBJECT-IDENTIFIER and Value fields
      // Cursor is incremented in validateAttributeTypeAndValue.
      validateAttributeTypeAndValue();
    }
  }

  public short decodeEcSubjectPublicKeyInfo(short blob) {
    init(blob);
    header(ASN1_SEQUENCE);
    short len = header(ASN1_SEQUENCE);
    short ecPublicInfo = KMByteBlob.instance(len);
    getBytes(ecPublicInfo);
    if (Util.arrayCompare(
            KMByteBlob.cast(ecPublicInfo).getBuffer(),
            KMByteBlob.cast(ecPublicInfo).getStartOff(),
            EC_ALGORITHM,
            (short) 0,
            KMByteBlob.cast(ecPublicInfo).length())
        != 0) {
      KMException.throwIt(KMError.UNKNOWN_ERROR);
    }
    len = header(ASN1_BIT_STRING);
    if (len < 1) {
      KMException.throwIt(KMError.UNKNOWN_ERROR);
    }
    // TODO need to handle if unused bits are not zero
    byte unusedBits = getByte();
    if (unusedBits != 0) {
      KMException.throwIt(KMError.UNIMPLEMENTED);
    }
    short pubKey = KMByteBlob.instance((short) (len - 1));
    getBytes(pubKey);
    return pubKey;
  }

  // Seq[Int,Int,Int,Int,<ignore rest>]
  public short decodeRsaPrivateKey(short version) {
    short resp = KMArray.instance((short) 3);
    header(ASN1_OCTET_STRING);
    header(ASN1_SEQUENCE);
    short len = header(ASN1_INTEGER);
    if (len != 1) {
      KMException.throwIt(KMError.UNKNOWN_ERROR);
    }
    short ver = getByte();
    if (ver != version) {
      KMException.throwIt(KMError.UNKNOWN_ERROR);
    }
    len = header(ASN1_INTEGER);
    short modulus = KMByteBlob.instance(len);
    getBytes(modulus);
    updateRsaKeyBuffer(modulus);
    len = header(ASN1_INTEGER);
    short pubKey = KMByteBlob.instance(len);
    getBytes(pubKey);
    len = header(ASN1_INTEGER);
    short privKey = KMByteBlob.instance(len);
    getBytes(privKey);
    updateRsaKeyBuffer(privKey);
    KMArray.cast(resp).add((short) 0, modulus);
    KMArray.cast(resp).add((short) 1, pubKey);
    KMArray.cast(resp).add((short) 2, privKey);
    return resp;
  }

  private void updateRsaKeyBuffer(short blob) {
    byte[] buffer = KMByteBlob.cast(blob).getBuffer();
    short startOff = KMByteBlob.cast(blob).getStartOff();
    short len = KMByteBlob.cast(blob).length();
    if (0 == buffer[startOff] && len > 256) {
      KMByteBlob.cast(blob).setStartOff(++startOff);
      KMByteBlob.cast(blob).reduceLength(--len);
    }
  }

  private short readEcdsa256SigIntegerHeader() {
    short len = header(ASN1_INTEGER);
    if (len == 33) {
      if (0 != getByte()) {
        KMException.throwIt(KMError.INVALID_DATA);
      }
      len--;
    } else if (len > 33) {
      KMException.throwIt(KMError.INVALID_DATA);
    }
    return len;
  }

  // Seq [Int, Int]
  public short decodeEcdsa256Signature(short blob, byte[] scratchPad, short scratchPadOff) {
    init(blob);
    short len = header(ASN1_SEQUENCE);
    len = readEcdsa256SigIntegerHeader();
    // concatenate r and s in the buffer (r||s)
    Util.arrayFillNonAtomic(scratchPad, scratchPadOff, (short) 64, (byte) 0);
    // read r
    getBytes(scratchPad, (short) (scratchPadOff + 32 - len), len);
    len = readEcdsa256SigIntegerHeader();
    // read s
    getBytes(scratchPad, (short) (scratchPadOff + 64 - len), len);
    return (short) 64;
  }

  // Seq [Int, Blob]
  public void decodeCommon(short version, byte[] alg) {
    short len = header(ASN1_SEQUENCE);
    len = header(ASN1_INTEGER);
    if (len != 1) {
      KMException.throwIt(KMError.UNKNOWN_ERROR);
    }
    short ver = getByte();
    if (ver != version) {
      KMException.throwIt(KMError.UNKNOWN_ERROR);
    }
    len = header(ASN1_SEQUENCE);
    short blob = KMByteBlob.instance(len);
    getBytes(blob);
    if (Util.arrayCompare(
            KMByteBlob.cast(blob).getBuffer(),
            KMByteBlob.cast(blob).getStartOff(),
            alg,
            (short) 0,
            KMByteBlob.cast(blob).length())
        != 0) {
      KMException.throwIt(KMError.UNKNOWN_ERROR);
    }
  }

  // Seq[Int,blob,blob]
  public short decodeEcPrivateKey(short version) {
    short resp = KMArray.instance((short) 2);
    header(ASN1_OCTET_STRING);
    header(ASN1_SEQUENCE);
    short len = header(ASN1_INTEGER);
    if (len != 1) {
      KMException.throwIt(KMError.UNKNOWN_ERROR);
    }
    short ver = getByte();
    if (ver != version) {
      KMException.throwIt(KMError.UNKNOWN_ERROR);
    }
    len = header(ASN1_OCTET_STRING);
    short privKey = KMByteBlob.instance(len);
    getBytes(privKey);
    validateTag0IfPresent();
    header(ASN1_A1_TAG);
    len = header(ASN1_BIT_STRING);
    if (len < 1) {
      KMException.throwIt(KMError.UNKNOWN_ERROR);
    }
    // TODO need to handle if unused bits are not zero
    byte unusedBits = getByte();
    if (unusedBits != 0) {
      KMException.throwIt(KMError.UNIMPLEMENTED);
    }
    short pubKey = KMByteBlob.instance((short) (len - 1));
    getBytes(pubKey);
    KMArray.cast(resp).add((short) 0, pubKey);
    KMArray.cast(resp).add((short) 1, privKey);
    return resp;
  }

  private void validateTag0IfPresent() {
    if (data[dataInfo[DATA_CURSOR_OFFSET]] != ASN1_A0_TAG) {
      return;
    }
    short len = header(ASN1_A0_TAG);
    if (len != EC_CURVE.length) {
      KMException.throwIt(KMError.UNKNOWN_ERROR);
    }
    if (Util.arrayCompare(data, dataInfo[DATA_CURSOR_OFFSET], EC_CURVE, (short) 0, len) != 0) {
      KMException.throwIt(KMError.UNKNOWN_ERROR);
    }
    incrementCursor(len);
  }

  private void validateAttributeTypeAndValue() {
    // First byte should be OBJECT_IDENTIFIER, otherwise it is not well-formed DER Subject.
    if (data[dataInfo[DATA_CURSOR_OFFSET]] != OBJECT_IDENTIFIER) {
      KMException.throwIt(KMError.UNKNOWN_ERROR);
    }
    // Check if the OID matches the email address
    if ((Util.arrayCompare(
            data,
            dataInfo[DATA_CURSOR_OFFSET],
            EMAIL_ADDRESS_OID,
            (short) 0,
            (short) EMAIL_ADDRESS_OID.length)
        == 0)) {
      incrementCursor((short) EMAIL_ADDRESS_OID.length);
      // Validate the length of the attribute value.
      if (getByte() != IA5_STRING) {
        KMException.throwIt(KMError.UNKNOWN_ERROR);
      }
      short emailLength = getLength();
      if (emailLength <= 0 && emailLength > MAX_EMAIL_ADD_LEN) {
        KMException.throwIt(KMError.UNKNOWN_ERROR);
      }
      incrementCursor(emailLength);
      return;
    }
    // Check other OIDs.
    for (short i = 0; i < (short) attributeOIds.length; i++) {
      if ((Util.arrayCompare(
                  data,
                  dataInfo[DATA_CURSOR_OFFSET],
                  COMMON_OID,
                  (short) 0,
                  (short) COMMON_OID.length)
              == 0)
          && (attributeOIds[i]
              == data[(short) (dataInfo[DATA_CURSOR_OFFSET] + COMMON_OID.length)])) {
        incrementCursor((short) (COMMON_OID.length + 1));
        // Validate the length of the attribute value.
        short tag = getByte();
        if (tag != ASN1_UTF8_STRING
            && tag != ASN1_TELETEX_STRING
            && tag != ASN1_PRINTABLE_STRING
            && tag != ASN1_UNIVERSAL_STRING
            && tag != ASN1_BMP_STRING) {
          KMException.throwIt(KMError.UNKNOWN_ERROR);
        }
        short attrValueLength = getLength();
        if (attrValueLength <= 0 && attrValueLength > attributeValueMaxLen[i]) {
          KMException.throwIt(KMError.UNKNOWN_ERROR);
        }
        incrementCursor(attrValueLength);
        return;
      }
    }
    // If no match is found above then move the cursor to next element.
    getByte(); // Move Cursor by one byte (OID)
    incrementCursor(getLength()); // Move cursor to AtrributeTag
    getByte(); // Move cursor to AttributeValue
    incrementCursor(getLength()); // Move cursor to next SET element
  }

  private short header(short tag) {
    short t = getByte();
    if (t != tag) {
      KMException.throwIt(KMError.INVALID_DATA);
    }
    short len = getLength();
    if (len < 0) {
      KMException.throwIt(KMError.INVALID_DATA);
    }
    return len;
  }

  private byte getByte() {
    byte d = data[dataInfo[DATA_CURSOR_OFFSET]];
    incrementCursor((short) 1);
    return d;
  }

  private short getExplicitContextTag() {
    byte firstByte = getByte();
    // bit 8(1), bit 7(0) represents context specific and bit 6(1) represents it is EXPLICIT
    // bit 5 to bit 1 represents the actual tag.
    if (0xA0 != (0xE0 & firstByte)) { // isContextSpecificExplicitTag
      KMException.throwIt(KMError.INVALID_DATA);
    }
    short tag = (short) (firstByte & 0x001F);
    if (tag == 0x001f) {
      /* high tag number */
      // As per ITU-T X.690 specification, section 8.1.2.4
      // For tags with a number greater than or equal to 31, the identifier shall comprise a leading
      // octet followed by
      // one or more subsequent octets.
      // The leading octet shall be encoded as follows:
      // a) bits 8 and 7 shall be encoded to represent the class of the tag
      // b) bit 6 shall be a zero or a one according to the rules (Explicit(1) / Implicit(0))
      // c) bits 5 to 1 shall be encoded as 11111.
      //
      // The subsequent octets shall encode the number of the tag as follows:
      // a) bit 8 of each octet shall be set to one unless it is the last octet of the identifier
      // octets;
      // b) bits 7 to 1 of the first subsequent octet, followed by bits 7 to 1 of the second
      // subsequent octet, followed in
      //    turn by bits 7 to 1 of each further octet, up to and including the last subsequent octet
      // in the identifier
      //    octets shall be the encoding of an unsigned binary integer equal to the tag number, with
      // bit 7 of the first
      //    subsequent octet as the most significant bit;
      // c) bits 7 to 1 of the first subsequent octet shall not all be zero.
      //
      // Example of encoding a tag with number 503: (Base-128(503) = 0x03, 0x77)
      //   | first octet |      | second octet |    | last octet |
      //   1 0 1 1 1 1 1 1      1 0 0 0 0 0 1 1     0 1 1 1 0 1 1 1
      //                        |
      //                   continuation bit
      //
      // Example of decoding the tag 503:
      // 1. Check if the first octet contains 0x1F from b5..b1
      // 2. secondOctet(b7..b1) * 128^1 + lastOctet(b7..b1) * 128^0
      short curOff = dataInfo[DATA_CURSOR_OFFSET];
      short exponent = 0;
      // Check if the tag number exceeds the maximum short value support by the JavaCard.
      while (0x80 == (data[curOff] & 0x80)) {
        /* hasContinuationByte */
        if (exponent > 2) {
          // tag should be less than SHORT_MAX 32767
          KMException.throwIt(KMError.UNKNOWN_ERROR);
        }
        exponent++;
        curOff++;
      }
      // Extract tag
      tag = 0;
      short product;
      while (exponent >= 0) {
        product = 1;
        for (short k = 0; k < exponent; ++k) {
          product *= 128;
        }
        tag += (short) ((getByte() & 0x7F) * product);
        exponent--;
      }
    }
    return tag;
  }

  private short findTagTypeInArray(short[] tags, short tag) {
    short length = (short) tags.length;
    for (short i = 0; i < length; i += 2) {
      if (tag == tags[(short) (i + 1)]) {
        return tags[i];
      }
    }
    return KMType.INVALID_VALUE;
  }

  private short getTagTypeFromTag(short tag) {
    // An exception to USER_SECURE_ID tag which is encoded as INTEGER in authorization list
    // as opposed to SET.
    if (tag == KMType.USER_SECURE_ID) {
      return KMType.UINT_TAG;
    }
    short tagType = findTagTypeInArray(hwTagIds, tag);
    if (tagType != KMType.INVALID_VALUE) {
      return tagType;
    }
    tagType = findTagTypeInArray(swTagIds, tag);
    if (tagType != KMType.INVALID_VALUE) {
      return tagType;
    }
    tagType = findTagTypeInArray(validAuthListTags, tag);
    if (tagType != KMType.INVALID_VALUE) {
      return tagType;
    }
    return KMType.INVALID_VALUE;
  }

  private short getShort() {
    short d = Util.getShort(data, dataInfo[DATA_CURSOR_OFFSET]);
    incrementCursor((short) 2);
    return d;
  }

  private void getBytes(short blob) {
    short len = KMByteBlob.cast(blob).length();
    Util.arrayCopyNonAtomic(
        data,
        dataInfo[DATA_CURSOR_OFFSET],
        KMByteBlob.cast(blob).getBuffer(),
        KMByteBlob.cast(blob).getStartOff(),
        len);
    incrementCursor(len);
  }

  private void getBytes(byte[] buffer, short offset, short len) {
    Util.arrayCopyNonAtomic(data, dataInfo[DATA_CURSOR_OFFSET], buffer, offset, len);
    incrementCursor(len);
  }

  private short getLength() {
    byte len = getByte();
    if (len >= 0) {
      return len;
    }
    len = (byte) (len & 0x7F);
    if (len == 1) {
      return (short) (getByte() & 0xFF);
    } else if (len == 2) {
      return getShort();
    } else {
      KMException.throwIt(KMError.UNKNOWN_ERROR);
    }
    return KMType.INVALID_VALUE; // should not come here
  }

  public void init(short blob) {
    data = KMByteBlob.cast(blob).getBuffer();
    dataInfo[DATA_START_OFFSET] = KMByteBlob.cast(blob).getStartOff();
    dataInfo[DATA_LENGTH_OFFSET] = KMByteBlob.cast(blob).length();
    dataInfo[DATA_CURSOR_OFFSET] = dataInfo[DATA_START_OFFSET];
  }

  public void incrementCursor(short n) {
    dataInfo[DATA_CURSOR_OFFSET] += n;
    if (dataInfo[DATA_CURSOR_OFFSET]
        > ((short) (dataInfo[DATA_START_OFFSET] + dataInfo[DATA_LENGTH_OFFSET]))) {
      KMException.throwIt(KMError.UNKNOWN_ERROR);
    }
  }
}
