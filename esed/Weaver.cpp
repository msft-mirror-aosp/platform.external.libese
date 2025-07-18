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

#include "Weaver.h"

#include <android-base/logging.h>

#include <ese/app/weaver.h>
#include "ScopedEseConnection.h"

namespace android {
namespace esed {

using ::aidl::android::hardware::weaver::WeaverConfig;
using ::aidl::android::hardware::weaver::WeaverReadResponse;
using ::aidl::android::hardware::weaver::WeaverReadStatus;

constexpr uint32_t kMillisPerSecond = 1000;

ScopedAStatus Weaver::getConfig(WeaverConfig* _aidl_return) {
    LOG(VERBOSE) << "Running Weaver::getNumSlots";
    // Open SE session for applet
    ScopedEseConnection ese{mEse};
    ese.init();
    EseWeaverSession ws;
    ese_weaver_session_init(&ws);
    EseAppResult res = ese_weaver_session_open(mEse.ese_interface(), &ws);
    if (EseAppResultValue(res) == ESE_APP_RESULT_ERROR_OS) {
        switch (EseAppResultAppValue(res)) {
        case 0x6999: // SW_APPLET_SELECT_FAILED
        case 0x6A82: // SW_FILE_NOT_FOUND
            // No applet means no Weaver storage. Report no slots to prompt
            // fallback to software mode.
            *_aidl_return = WeaverConfig{0, 0, 0};
            return ScopedAStatus::ok();
        }
    } else if (res != ESE_APP_RESULT_OK) {
        // Transient error
        return ScopedAStatus::fromStatus(STATUS_FAILED_TRANSACTION);
    }

    // Call the applet
    uint32_t numSlots;
    if (ese_weaver_get_num_slots(&ws, &numSlots) != ESE_APP_RESULT_OK) {
        return ScopedAStatus::fromStatus(STATUS_FAILED_TRANSACTION);
    }

    // Try and close the session
    if (ese_weaver_session_close(&ws) != ESE_APP_RESULT_OK) {
        LOG(WARNING) << "Failed to close Weaver session";
    }

    *_aidl_return = {(int32_t)numSlots, kEseWeaverKeySize, kEseWeaverValueSize};
    return ScopedAStatus::ok();
}

ScopedAStatus Weaver::write(int32_t slotId, const std::vector<uint8_t>& key,
                            const std::vector<uint8_t>& value) {
    LOG(INFO) << "Running Weaver::write on slot " << slotId;
    ScopedEseConnection ese{mEse};
    ese.init();
    // Validate the key and value sizes
    if (key.size() != kEseWeaverKeySize) {
        LOG(ERROR) << "Key size must be " << kEseWeaverKeySize << ", not" << key.size() << " bytes";
        return ScopedAStatus::fromStatus(STATUS_FAILED_TRANSACTION);
    }
    if (value.size() != kEseWeaverValueSize) {
        LOG(ERROR) << "Value size must be " << kEseWeaverValueSize << ", not" << value.size()
                   << " bytes";
        return ScopedAStatus::fromStatus(STATUS_FAILED_TRANSACTION);
    }

    // Open SE session for applet
    EseWeaverSession ws;
    ese_weaver_session_init(&ws);
    if (ese_weaver_session_open(mEse.ese_interface(), &ws) != ESE_APP_RESULT_OK) {
        return ScopedAStatus::fromStatus(STATUS_FAILED_TRANSACTION);
    }

    // Call the applet
    if (ese_weaver_write(&ws, slotId, key.data(), value.data()) != ESE_APP_RESULT_OK) {
        return ScopedAStatus::fromStatus(STATUS_FAILED_TRANSACTION);
    }

    // Try and close the session
    if (ese_weaver_session_close(&ws) != ESE_APP_RESULT_OK) {
        LOG(WARNING) << "Failed to close Weaver session";
    }

    return ScopedAStatus::ok();
}

ScopedAStatus Weaver::read(int32_t slotId, const std::vector<uint8_t>& key,
                           WeaverReadResponse* _aidl_return) {
    LOG(VERBOSE) << "Running Weaver::read on slot " << slotId;

    // Validate the key size
    if (key.size() != kEseWeaverKeySize) {
        LOG(ERROR) << "Key size must be " << kEseWeaverKeySize << ", not" << key.size() << " bytes";
        return ScopedAStatus::fromStatus(STATUS_FAILED_TRANSACTION);
    }

    // Open SE session for applet
    ScopedEseConnection ese{mEse};
    ese.init();
    EseWeaverSession ws;
    ese_weaver_session_init(&ws);
    if (ese_weaver_session_open(mEse.ese_interface(), &ws) != ESE_APP_RESULT_OK) {
        return ScopedAStatus::fromStatus(STATUS_FAILED_TRANSACTION);
    }

    // Call the applet
    uint8_t value[kEseWeaverValueSize] = {};
    uint32_t timeout_seconds;
    const int res = ese_weaver_read(&ws, slotId, key.data(), value, &timeout_seconds);
    switch (res) {
        case ESE_APP_RESULT_OK:
            _aidl_return->status = WeaverReadStatus::OK;
            _aidl_return->value = std::vector<uint8_t>(value, value + sizeof(value));
            _aidl_return->timeout = 0;
            break;
        case ESE_WEAVER_READ_WRONG_KEY:
            _aidl_return->status = WeaverReadStatus::INCORRECT_KEY;
            _aidl_return->timeout = timeout_seconds * kMillisPerSecond;
            break;
        case ESE_WEAVER_READ_TIMEOUT:
            _aidl_return->status = WeaverReadStatus::THROTTLE;
            _aidl_return->timeout = timeout_seconds * kMillisPerSecond;
            break;
        default:
            _aidl_return->status = WeaverReadStatus::FAILED;
            _aidl_return->timeout = 0;
            break;
    }

    // Try and close the session
    if (ese_weaver_session_close(&ws) != ESE_APP_RESULT_OK) {
        LOG(WARNING) << "Failed to close Weaver session";
    }
    memset_explicit(value, 0, sizeof(value));
    return ScopedAStatus::ok();
}

}  // namespace esed
}  // namespace android
