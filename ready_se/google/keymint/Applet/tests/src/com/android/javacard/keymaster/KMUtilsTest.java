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
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.fail;

import com.android.javacard.seprovider.KMException;

import javacard.framework.Util;

import org.junit.After;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import java.nio.ByteBuffer;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Date;
import java.util.TimeZone;

/** This class tests the methods in {@link KMUtils}. */
@RunWith(JUnit4.class)
public final class KMUtilsTest {
    private static KMRepository sRepository;

    @BeforeClass
    public static void setup() {
        sRepository = new KMRepository(false /* isUpgrading */);
        KMType.initialize();
    }

    @After
    public void reset() {
        // Release and clear the transient buffer memory
        sRepository.clean();
    }

    /**
     * Verifies {@code KMUtils.countTemporalCount} against the KeyMint specification.
     *
     * <p>Iterates from Dec 31, 1999, to Dec 31, 9999, in 100-year increments. Compares the API
     * output (stored in scratchpad) against the expected Temporal Count calculated as: {@code T =
     * DateTime / 30_DAYS_IN_MILLIS}.
     */
    @Test
    public void testTemporalCountFrom1999To9999() {
        byte[] scratchpad = new byte[48];
        final long THIRTY_DAY_MILLIS = 2592000000L;
        final long HUNDRED_YEAR_MILLIS = 3155673600000L;
        final long START_DATE = 946627200000L; // 31st Dec 1999 08:00:00 UTC
        final long END_DATE = 253402243200000L; // 31st Dec 9999 08:00:00 UTC

        for (long dateTime = START_DATE; dateTime <= END_DATE; dateTime += HUNDRED_YEAR_MILLIS) {
            byte[] dateBytes = ByteBuffer.allocate(Long.BYTES).putLong(dateTime).array();

            KMUtils.countTemporalCount(
                    dateBytes, (short) 0, (short) dateBytes.length, scratchpad, (short) 0);

            long actualQuotient = ByteBuffer.wrap(scratchpad, (short) 0, (short) 8).getLong();
            long expectedQuotient = dateTime / THIRTY_DAY_MILLIS;

            assertEquals("Failed for date: " + dateTime, expectedQuotient, actualQuotient);
        }
    }

    /**
     * Verifies that the {@link KMUtils#divide} method throws a {@code KMException} with the {@code
     * INVALID_ARGUMENT} error code when the divisor is zero.
     *
     * <p>This test ensures that division by zero is handled as an invalid argument.
     */
    @Test
    public void testDivideByZeroThrowsInvalidArgumentException() {
        byte[] scratchpad = new byte[48];
        // set the dividend to 1
        scratchpad[(short) 7] = 1;

        assertThrows(
                KMException.class,
                () ->
                        KMUtils.divide(
                                scratchpad,
                                (short) 0 /* dividendOff */,
                                (short) 8 /* divisorOff */,
                                (short) 16 /* remainderOff */,
                                (short) 24 /* quotientOff */,
                                (short) 32 /* scratchOff */));
        assertEquals(
                "KMException should have INVALID_ARGUMENT error code",
                KMError.INVALID_ARGUMENT,
                KMException.reason());
    }

    /**
     * Verifies the {@link KMUtils#divide} implementation by choosing cases
     *
     * <p>1.where the divisor is greater than the dividend, which should result in a quotient of
     * zero and a remainder equal to the dividend.
     *
     * <p>2.where the divisor is less than the dividend
     */
    @Test
    public void testDivideVariousCombinationsOfDividendDivisor() {
        long dividend = 1L;
        long divisor = 0x7fffffffffffffffL;

        while (dividend > 0 && divisor > 0) {
            verifyDivision(dividend, divisor);
            // Shift values for next iteration
            dividend *= 2;
            divisor /= 2;
        }
    }

    /**
     * Validates the {@link KMUtils#divide} implementation by sending the same divisor and dividend
     * to see if the quotient becomes 1 and remainder becomes 0.
     */
    @Test
    public void testDivideSameDividendDivisor() {
        long dividend = 0x7fffffffffffffffL;

        while (dividend > 0) {
            verifyDivision(dividend, dividend /* divisor is same as dividend */);
            // Shift values for next iteration
            dividend /= 2;
        }
    }

    /**
     * Validates {@link KMUtils#convertToDate} by iterating from 1970 to 9999 in 365 days increments.
     *
     * <p>This test verifies compliance with RFC 5280 date formatting requirements:
     *
     * <ul>
     *   <li><b>UTCTime (YYMMDDHHMMSSZ):</b> Used for dates prior to 2050.
     *   <li><b>GeneralizedTime (YYYYMMDDHHMMSSZ):</b> Used for dates from 2050 onwards.
     * </ul>
     *
     * <p>The test ensures that the millisecond input, when converted to a byte-string by the
     * utility, can be parsed back to the exact same millisecond value (truncated to the second).
     * * @see <a href="https://datatracker.ietf.org/doc/html/rfc5280#section-4.1.2.5">RFC 5280
     * Section 4.1.2.5</a>
     */
    @Test
    public void testConvertToDateCompliesWithRFC5280AcrossFullDateRange() {
        final byte[] scratchpad = new byte[256];
        final ByteBuffer timeBuf = ByteBuffer.allocate(Long.BYTES);

        SimpleDateFormat utcFormatter = new SimpleDateFormat("yyMMddHHmmss'Z'");
        utcFormatter.set2DigitYearStart(new Date(0));
        utcFormatter.setTimeZone(TimeZone.getTimeZone("UTC")); // Ensure UTC context

        SimpleDateFormat genFormatter = new SimpleDateFormat("yyyyMMddHHmmss'Z'");
        genFormatter.setTimeZone(TimeZone.getTimeZone("UTC"));

        Calendar calendar = Calendar.getInstance(TimeZone.getTimeZone("UTC"));

        try {
            long rfcThreshold = genFormatter.parse("20500101000000Z").getTime();
            long startTime = genFormatter.parse("19700101235959Z").getTime();
            long endTime = genFormatter.parse("99991231235959Z").getTime();
            long yearInMillis = java.util.concurrent.TimeUnit.DAYS.toMillis(365);

            // Range: '1970-01-01T23:59:59Z' to '9999-12-31T23:59:59Z', step: 1 year milliseconds
            for (long millis = startTime; millis <= endTime; millis += yearInMillis) {
                timeBuf.clear();
                timeBuf.putLong(millis);

                short time = KMInteger.instance((short) 8);
                Util.arrayCopyNonAtomic(
                        timeBuf.array(),
                        (short) 0,
                        KMInteger.cast(time).getBuffer(),
                        KMInteger.cast(time).getStartOff(),
                        (short) 8);

                // Execute the conversion to data logic
                short timeFormat = KMUtils.convertToDate(time, scratchpad);

                // Select formatter based on RFC 5280 rules
                SimpleDateFormat activeFormatter =
                        (millis < rfcThreshold) ? utcFormatter : genFormatter;

                // Extract string representation
                String dateStr =
                        new String(
                                KMByteBlob.cast(timeFormat).getBuffer(),
                                KMByteBlob.cast(timeFormat).getStartOff(),
                                KMByteBlob.cast(timeFormat).length());

                // Verify the round-trip conversion
                Date parsedDate = activeFormatter.parse(dateStr);
                calendar.setTime(parsedDate);

                assertEquals(
                        "Mismatch for date string: " + dateStr, millis, calendar.getTimeInMillis());

                // Clean the repository
                KMRepository.instance().clean();
            }
        } catch (ParseException e) {
            fail("Parse Exception");
        }
    }

    /**
     * Helper method to perform the division via {@link KMUtils#divide} and assert the results.
     *
     * @param dividend The value to be divided.
     * @param divisor The value to divide by.
     */
    private void verifyDivision(long dividend, long divisor) {
        final byte[] scratchpad = new byte[48];
        final short dividendOff = 0;
        final short divisorOff = 8;
        final short remainderOff = 16;
        final short quotientOff = 24;
        final short scratchOff = 32;
        Util.arrayFillNonAtomic(scratchpad, (short) 0, (short) 48, (byte) 0);
        ByteBuffer dividendBuf = ByteBuffer.allocate(Long.BYTES);
        ByteBuffer divisorBuf = ByteBuffer.allocate(Long.BYTES);

        // Prepare input data
        dividendBuf.putLong(dividend);
        divisorBuf.putLong(divisor);

        Util.arrayCopyNonAtomic(dividendBuf.array(), (short) 0, scratchpad, dividendOff, (short) 8);
        Util.arrayCopyNonAtomic(divisorBuf.array(), (short) 0, scratchpad, divisorOff, (short) 8);

        // Execute division logic
        KMUtils.divide(scratchpad, dividendOff, divisorOff, remainderOff, quotientOff, scratchOff);

        // Extract results
        long actualQuotient = ByteBuffer.wrap(scratchpad, quotientOff, 8).getLong();
        long actualRemainder = ByteBuffer.wrap(scratchpad, remainderOff, 8).getLong();

        // Standard Java results
        long expectedQuotient = dividend / divisor;
        long expectedRemainder = dividend % divisor;

        // Assertions
        assertEquals(
                "Quotient mismatch for " + dividend + " / " + divisor,
                expectedQuotient,
                actualQuotient);
        assertEquals(
                "Remainder mismatch for " + dividend + " % " + divisor,
                expectedRemainder,
                actualRemainder);
    }
}
