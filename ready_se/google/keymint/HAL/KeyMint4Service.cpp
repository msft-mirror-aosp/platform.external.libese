/*
 * Copyright 2020, The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#define LOG_TAG "javacard.strongbox-service"
#include <android-base/logging.h>
#include <android-base/properties.h>
#include <android/binder_manager.h>
#include <android/binder_process.h>
#include <keymaster/km_version.h>

#include "JavacardKeyMint4Device.h"
#include "JavacardRemotelyProvisionedComponentDevice.h"
#include "JavacardSecureElement.h"
#include "JavacardSharedSecret.h"
#include "OmapiTransport.h"
#include "SocketTransport.h"
#include "keymint_utils.h"
#include <aidl/android/hardware/security/keymint/SecurityLevel.h>

using aidl::android::hardware::security::keymint::JavacardKeyMint4Device;
using aidl::android::hardware::security::keymint::JavacardRemotelyProvisionedComponentDevice;
using aidl::android::hardware::security::keymint::SecurityLevel;
using aidl::android::hardware::security::sharedsecret::JavacardSharedSecret;
using keymaster::KmVersion;
using keymint::javacard::getOsPatchlevel;
using keymint::javacard::getOsVersion;
using keymint::javacard::getVendorPatchlevel;
using keymint::javacard::ITransport;
using keymint::javacard::JavacardSecureElement;
using keymint::javacard::OmapiTransport;
using keymint::javacard::SocketTransport;

#define PROP_BUILD_QEMU "ro.kernel.qemu"
#define PROP_BUILD_FINGERPRINT "ro.build.fingerprint"
// Cuttlefish build fingerprint substring.
#define CUTTLEFISH_FINGERPRINT_SS "aosp_cf_"

constexpr int kKeymintVersion = 400;
// Ensures HAL and applet version consistency. This is used as P1 byte in the APDU header. This
// value is used by the applet to confirm that the KeyMint HAL is running a compatible version of
// Keymint. If the versions do not match, the command is not executed.
constexpr int kP1 = 0x70;

template <typename T, class... Args> std::shared_ptr<T> addService(Args&&... args) {
    std::shared_ptr<T> ser = ndk::SharedRefBase::make<T>(std::forward<Args>(args)...);
    auto instanceName = std::string(T::descriptor) + "/strongbox";
    LOG(INFO) << "adding javacard strongbox service instance: " << instanceName;
    binder_status_t status =
        AServiceManager_addService(ser->asBinder().get(), instanceName.c_str());
    CHECK(status == STATUS_OK);
    return ser;
}

std::shared_ptr<ITransport> getTransportInstance() {
    return std::make_shared<OmapiTransport>();
}

int main() {
    ABinderProcess_setThreadPoolMaxThreadCount(0);
    // Javacard Secure Element
    std::shared_ptr<JavacardSecureElement> card =
        std::make_shared<JavacardSecureElement>(kP1, getTransportInstance());
    std::shared_ptr<::keymint::javacard::JavacardKeyMintDevice> device =
        std::make_shared<::keymint::javacard::JavacardKeyMintDevice>(card, kKeymintVersion);
    // Add Keymint Service
    addService<JavacardKeyMint4Device>(card, device);
    // Add Shared Secret Service
    addService<JavacardSharedSecret>(card);
    // Add Remotely Provisioned Component Service
    addService<JavacardRemotelyProvisionedComponentDevice>(card);

    ABinderProcess_joinThreadPool();
    return EXIT_FAILURE;  // should not reach
}
