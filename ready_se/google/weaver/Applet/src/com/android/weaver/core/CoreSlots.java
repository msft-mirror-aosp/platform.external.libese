/*
 * Copyright (C) 2017 The Android Open Source Project
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

package com.android.weaver.core;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;

import org.globalplatform.upgrade.Element;
import org.globalplatform.upgrade.UpgradeManager;

import com.android.weaver.Consts;
import com.android.weaver.Slots;

import com.nxp.id.jcopx.util.DSTimer;

class CoreSlots implements Slots {
    static final byte NUM_SLOTS = 64;
    static final byte PKG_VERSION_PRIMITIVE_SIZE = 2;

    private Slot[] mSlots;

    /**
     * Initializes the CoreSlots instance. This constructor is invoked once during the applet's
     * lifecycle, either upon initial installation or during an upgrade.
     *
     * <p><b>1. During Installation:</b> When the applet is installed for the first time, this
     * constructor is called. The {@code isUpgrading} parameter will be {@code false}. Call flow:
     * {@code CardManager -> install() -> WeaverCore() -> CoreSlots()}
     *
     * <p><b>2. During Applet Upgrade:</b> When the applet is upgraded, the old applet is deleted,
     * and the new applet is installed. During this installation process, the constructor is called
     * again, with {@code isUpgrading} set to {@code true}. This allows for specific initialization
     * logic during an upgrade. Call flow: {@code UpgradeManager -> install() -> WeaverCore() ->
     * CoreSlots()}
     *
     * <p>Once the applet completes the installation/upgrade phase, the restore phase starts,
     * managed by the {@code UpgradeManager}. The {@code onRestore} function is then called with the
     * following possible call flows:
     *
     * <ul>
     *   <li><b>Restoring Existing Data:</b> If there is data from a previous applet version to
     *       restore, the call flow is: {@code UpgradeManager -> WeaverCore#onRestore() ->
     *       CoreSlots#onRestore() -> Slot#readFrom()}. This process reads and populates the {@code
     *       Slot} objects with the preserved data.
     *   <li><b>Data exists but the upgrade functionality isn't implemented:</b> This scenario is
     *       problematic because the old applet did not implement the necessary upgrade
     *       functionality. As a result, the new applet cannot restore the existing data. In this
     *       situation, {@code createSlots()} is called with {@code isUpgrading} set to {@code
     *       false}, which initializes new, default {@code Slot} objects, effectively causing the
     *       user to lose their data. This should not happen in the field.
     * </ul>
     *
     * </ul>
     *
     * @param isUpgrading A boolean indicating if the applet is currently being upgraded.
     */
    CoreSlots(boolean isUpgrading) {
        // Allocate all memory up front
        mSlots = new Slot[NUM_SLOTS];
        createSlots(isUpgrading);

        // Make the same size as the value so the whole buffer can be copied in read() so there is
        // no time difference between success and failure.
        Slot.sRemainingBackoff = JCSystem.makeTransientByteArray(
                Consts.SLOT_VALUE_BYTES, JCSystem.CLEAR_ON_RESET);
    }

    /**
     * Initializes individual {@link Slot} objects within the {@code mSlots} array. Slots are only
     * created during initial installation, not during an upgrade, to preserve existing slot data
     * across upgrades.
     *
     * @param isUpgrading A boolean indicating if the applet is currently being upgraded.
     */
    private void createSlots(boolean isUpgrading) {
        if (!isUpgrading) {
            for (short i = 0; i < NUM_SLOTS; ++i) {
                mSlots[i] = new Slot();
            }
        }
    }

    @Override
    public short getNumSlots() {
        return NUM_SLOTS;
    }

    @Override
    public void write(short rawSlotId, byte[] key, short keyOffset,
            byte[] value, short valueOffset) {
        final short slotId = validateSlotId(rawSlotId);
        mSlots[slotId].write(key, keyOffset, value, valueOffset);
    }

    @Override
    public byte read(short rawSlotId, byte[] key, short keyOffset,
            byte[] outValue, short outOffset) {
        final short slotId = validateSlotId(rawSlotId);
        return mSlots[slotId].read(key, keyOffset, outValue, outOffset);
    }

    @Override
    public void eraseValue(short rawSlotId) {
        final short slotId = validateSlotId(rawSlotId);
        mSlots[slotId].eraseValue();
    }

    @Override
    public void eraseAll() {
        for (short i = 0; i < NUM_SLOTS; ++i) {
            mSlots[i].erase();
        }
    }

    /**
     * Check the slot ID is within range.
     */
    private short validateSlotId(short slotId) {
        // slotId is unsigned so if the signed version is negative then it is far too big
        if (slotId < 0 || slotId >= NUM_SLOTS) {
            ISOException.throwIt(Consts.SW_INVALID_SLOT_ID);
        }
        return slotId;
    }

    private static class Slot {
        /**
         * The number of bytes required to save the primitive data.
         * - mFailureCount - 2 bytes
         * - Timer instance creation status - 1 byte
         */
        static final byte SLOT_PRIMITIVE_BYTES = 3;
        /**
         * The number of object references to save.
         * - key   - 1
         * - value - 1
         */
        static final byte SLOT_OBJECTS_SIZE = 2;

        // The below two arrays map the value of the failure counter to the timeout (in seconds)
        // that the applet enforces after that number of failures.  The timeouts are 32-bit values;
        // however, to be compatible with Javacard implementations that do not support 'int', we
        // split them into their low and high 16-bit halves.

        private static final short[] TIMEOUT_SECONDS_LOW = {
            /* 0  */ (short) (0 & 0xffff),
            /* 1  */ (short) (0 & 0xffff),
            /* 2  */ (short) (0 & 0xffff),
            /* 3  */ (short) (0 & 0xffff),
            /* 4  */ (short) (0 & 0xffff),
            /* 5  */ (short) (60 & 0xffff), // 1 minute
            /* 6  */ (short) (300 & 0xffff), // 5 minutes
            /* 7  */ (short) (900 & 0xffff), // 15 minutes
            /* 8  */ (short) (1800 & 0xffff), // 30 minutes
            /* 9  */ (short) (5400 & 0xffff), // 90 minutes
            /* 10 */ (short) (14580 & 0xffff), // 3^(10-5) minutes = 4.05 hours
            /* 11 */ (short) (43740 & 0xffff), // 3^(11-5) minutes = 12.15 hours
            /* 12 */ (short) (131220 & 0xffff), // 3^(12-5) minutes = 36.45 hours
            /* 13 */ (short) (393660 & 0xffff), // 3^(13-5) minutes = 4.56 days
            /* 14 */ (short) (1180980 & 0xffff), // 3^(14-5) minutes = 13.67 days
            /* 15 */ (short) (3542940 & 0xffff), // 3^(15-5) minutes = 41.01 days
            /* 16 */ (short) (10628820 & 0xffff), // 3^(16-5) minutes = 123.02 days
            /* 17 */ (short) (31886460 & 0xffff), // 3^(17-5) minutes = 1.01 years
            /* 18 */ (short) (95659380 & 0xffff), // 3^(18-5) minutes = 3.03 years
            /* 19 */ (short) (286978140 & 0xffff), // 3^(19-5) minutes = 9.09 years
        };

        private static final short[] TIMEOUT_SECONDS_HIGH = {
            /* 0  */ (short) (0 >> 16),
            /* 1  */ (short) (0 >> 16),
            /* 2  */ (short) (0 >> 16),
            /* 3  */ (short) (0 >> 16),
            /* 4  */ (short) (0 >> 16),
            /* 5  */ (short) (60 >> 16), // 1 minute
            /* 6  */ (short) (300 >> 16), // 5 minutes
            /* 7  */ (short) (900 >> 16), // 15 minutes
            /* 8  */ (short) (1800 >> 16), // 30 minutes
            /* 9  */ (short) (5400 >> 16), // 90 minutes
            /* 10 */ (short) (14580 >> 16), // 3^(10-5) minutes = 4.05 hours
            /* 11 */ (short) (43740 >> 16), // 3^(11-5) minutes = 12.15 hours
            /* 12 */ (short) (131220 >> 16), // 3^(12-5) minutes = 36.45 hours
            /* 13 */ (short) (393660 >> 16), // 3^(13-5) minutes = 4.56 days
            /* 14 */ (short) (1180980 >> 16), // 3^(14-5) minutes = 13.67 days
            /* 15 */ (short) (3542940 >> 16), // 3^(15-5) minutes = 41.01 days
            /* 16 */ (short) (10628820 >> 16), // 3^(16-5) minutes = 123.02 days
            /* 17 */ (short) (31886460 >> 16), // 3^(17-5) minutes = 1.01 years
            /* 18 */ (short) (95659380 >> 16), // 3^(18-5) minutes = 3.03 years
            /* 19 */ (short) (286978140 >> 16), // 3^(19-5) minutes = 9.09 years
        };

        private static byte[] sRemainingBackoff;

        private byte[] mKey;
        private byte[] mValue;
        private short mFailureCount;
        private DSTimer mBackoffTimer;

        Slot() {
            mKey = new byte[Consts.SLOT_KEY_BYTES];
            mValue = new byte[Consts.SLOT_VALUE_BYTES];
        }

        private Slot(byte[] key, byte[] value) {
            mKey = key;
            mValue = value;
        }

        private static Slot makeSlot(
                byte[] key, byte[] value, short failureCount, boolean createTimerInstance) {
            Slot slot = new Slot(key, value);
            slot.mFailureCount = failureCount;
            slot.mBackoffTimer = createTimerInstance ? DSTimer.getInstance() : null;
            return slot;
        }

        /**
         * Transactionally reset the slot with a new key and value.
         *
         * @param keyBuffer   the buffer containing the key data
         * @param keyOffset   the offset of the key in its buffer
         * @param valueBuffer the buffer containing the value data
         * @param valueOffset the offset of the value in its buffer
         */
        public void write(
                byte[] keyBuffer, short keyOffset, byte[] valueBuffer, short valueOffset) {
            JCSystem.beginTransaction();
            Util.arrayCopy(keyBuffer, keyOffset, mKey, (short) 0, Consts.SLOT_KEY_BYTES);
            Util.arrayCopy(valueBuffer, valueOffset, mValue, (short) 0, Consts.SLOT_VALUE_BYTES);
            mFailureCount = 0;
            mBackoffTimer = DSTimer.getInstance();
            JCSystem.commitTransaction();
        }

        /**
         * Clear the slot's value.
         */
        public void eraseValue() {
            // This is intended to be destructive so a partial update is not a problem
            Util.arrayFillNonAtomic(mValue, (short) 0, Consts.SLOT_VALUE_BYTES, (byte) 0);
        }

        /**
         * Transactionally clear the slot.
         */
        public void erase() {
            JCSystem.beginTransaction();
            arrayFill(mKey, (short) 0, Consts.SLOT_KEY_BYTES, (byte) 0);
            arrayFill(mValue, (short) 0, Consts.SLOT_VALUE_BYTES, (byte) 0);
            mFailureCount = 0;
            mBackoffTimer.stopTimer();
            JCSystem.commitTransaction();
        }

        private boolean hasRemainingBackOff() {
            return ((0 != Util.getShort(sRemainingBackoff, (short) 0)) ||
                (0 != Util.getShort(sRemainingBackoff, (short) 2)));
        }

        /**
         * Copy the slot's value to the buffer if the provided key matches the slot's key.
         *
         * @param keyBuffer the buffer containing the key
         * @param keyOffset the offset of the key in its buffer
         * @param outBuffer the buffer to copy the value or backoff time into
         * @param outOffset the offset into the output buffer
         * @return status code
         */
        public byte read(byte[] keyBuffer, short keyOffset, byte[] outBuffer, short outOffset) {

            // Check for no more attempts allowed.
            if (mFailureCount >= TIMEOUT_SECONDS_LOW.length || mFailureCount < 0) {
                Util.setShort(outBuffer, outOffset, (short) 0x7fff);
                Util.setShort(outBuffer, (short) (outOffset + 2), (short) 0xffff);
                return Consts.READ_BACK_OFF;
            }

            // Check timeout has expired or hasn't been started
            mBackoffTimer.getRemainingTime(sRemainingBackoff, (short) 0);
            if (hasRemainingBackOff()) {
                Util.arrayCopyNonAtomic(
                        sRemainingBackoff, (short) 0, outBuffer, outOffset, (byte) 4);
                return Consts.READ_BACK_OFF;
            }

            // Assume this read will fail
            if (mFailureCount != 0x7fff) {
                mFailureCount += 1;
            }

            // Compute the next retry timeout, and start/stop the timer accordingly.
            if (computeRetryTimeout(sRemainingBackoff, (short) 0, mFailureCount)) {
                // Nonzero timeout: start the timer.
                mBackoffTimer.startTimer(
                        sRemainingBackoff, (short) 0, DSTimer.DST_POWEROFFMODE_FALLBACK);
            } else {
                // Zero timeout: stop the timer.
                mBackoffTimer.stopTimer();
            }

            // Check whether the key matches, in constant time.
            final byte result;
            final byte[] data;
            if (Util.arrayCompare(keyBuffer, keyOffset, mKey, (short) 0, Consts.SLOT_KEY_BYTES)
                    == 0) {
                // Correct key.  Reset the failure counter, stop the timer, and copy out the value.
                mFailureCount = 0;
                mBackoffTimer.stopTimer();
                data = mValue;
                result = Consts.READ_SUCCESS;
            } else {
                // Wrong key.  Copy out the next timeout.
                data = sRemainingBackoff;
                result = Consts.READ_WRONG_KEY;
            }
            Util.arrayCopyNonAtomic(data, (short) 0, outBuffer, outOffset, Consts.SLOT_VALUE_BYTES);
            return result;
        }

        /**
         * 3.0.3 does not offer Util.arrayFill
         */
        private static void arrayFill(byte[] bArray, short bOff, short bLen, byte bValue) {
            for (short i = 0; i < bLen; ++i) {
                bArray[(short) (bOff + i)] = bValue;
            }
        }

        /**
         * Computes the timeout in seconds as a function of the failure counter.
         *
         * <p>The 32-bit timeout in seconds is written to bArray starting at bOff.
         *
         * @return Whether the timeout is nonzero
         */
        private static boolean computeRetryTimeout(byte[] bArray, short bOff, short failureCount) {
            // Get the high and low words of the timeout.
            if (failureCount >= TIMEOUT_SECONDS_LOW.length || failureCount < 0) {
                failureCount = (short) (TIMEOUT_SECONDS_LOW.length - 1);
            }
            short highWord = TIMEOUT_SECONDS_HIGH[failureCount];
            short lowWord = TIMEOUT_SECONDS_LOW[failureCount];

            // Write the timeout to the array.
            Util.setShort(bArray, bOff, highWord);
            Util.setShort(bArray, (short) (bOff + 2), lowWord);

            return highWord != 0 || lowWord != 0;
        }

        public static void writeTo(Element element, Slot slot) {
            element.write(slot.mBackoffTimer != null);
            element.write(slot.mFailureCount);
            element.write(slot.mKey);
            element.write(slot.mValue);
        }

        public static Slot readFrom(Element element) {
            // Read in the same order as they were saved.
            boolean createTimerInstance = element.readBoolean();
            short failureCount = element.readShort();
            byte[] key = (byte[]) element.readObject();
            byte[] value = (byte[]) element.readObject();
            return Slot.makeSlot(key, value, failureCount, createTimerInstance);
        }
    }

    static Element onSave(CoreSlots csObj) {
        // WEAVER_PACKAGE_VERSION- 2 bytes
        short primitiveCount = PKG_VERSION_PRIMITIVE_SIZE;
        primitiveCount += (Slot.SLOT_PRIMITIVE_BYTES * NUM_SLOTS);
        short objectCount = (short) (Slot.SLOT_OBJECTS_SIZE * NUM_SLOTS);
        // Create element.
        Element element =
                UpgradeManager.createElement(Element.TYPE_SIMPLE, primitiveCount, objectCount);
        element.write(WeaverCore.WEAVER_PACKAGE_VERSION);
        for (short i = 0; i < NUM_SLOTS; i++) {
            Slot.writeTo(element, csObj.mSlots[i]);
        }
        return element;
    }

    static void onRestore(Element element, CoreSlots csObj) {
        if (element == null) {
            // No element to restore; initialize with default new objects.
            csObj.createSlots(false /* isUpgrading */);
        } else {
            element.initRead();
            short oldVersion = element.readShort();
            if (WeaverCore.WEAVER_PACKAGE_VERSION < oldVersion) {
                ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
            }
            for (short i = 0; i < NUM_SLOTS; ++i) {
                csObj.mSlots[i] = Slot.readFrom(element);
            }
        }
    }
}
